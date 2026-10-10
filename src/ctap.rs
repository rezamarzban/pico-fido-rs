//! Minimal CTAP2 authenticator (getInfo / makeCredential / getAssertion / reset).
//!
//! Private keys are generated and kept inside an ATECC608 (one key per slot, 8 slots) and never
//! leave it; the RP2040 only sends the 32-byte digest to be signed. A flash table (keys.rs) maps
//! credential IDs / relying parties to slots and stores user info for discoverable credentials.
//! No PIN, sign counter is always 0, attestation is "none".
use alloc::string::String;
use alloc::vec::Vec;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use crate::atecc::{self, Atecc, Bus};
use crate::cbor::{R, W};
use crate::keys::{trunc, Cred, Store, ID_LEN, MAX_CREDS};

pub const AAGUID: [u8; 16] = [0; 16];
pub const MAX_MSG: usize = 1200;

pub mod err {
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const INVALID_LENGTH: u8 = 0x03;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const KEY_STORE_FULL: u8 = 0x28;
    pub const KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const NO_CREDENTIALS: u8 = 0x2E;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const OTHER: u8 = 0x7F;
}

/// Result of one `handle` call.
pub enum Resp {
    /// Full CTAP response: status byte 0x00 followed by CBOR (if any).
    Ok(Vec<u8>),
    /// CTAP error status byte.
    Err(u8),
    /// Request is valid but needs a button press: wait for it, then call `handle` again with `up = true`.
    NeedUp,
}

enum Stop {
    Err(u8),
    NeedUp,
}
impl From<u8> for Stop {
    fn from(c: u8) -> Self {
        Stop::Err(c)
    }
}
type Res = Result<Vec<u8>, Stop>;

fn hw<T>(r: Result<T, atecc::Error>) -> Result<T, Stop> {
    r.map_err(|e| {
        defmt::error!("ATECC error: {}", e);
        Stop::Err(err::OTHER)
    })
}

pub struct Ctap {
    at: Atecc<Bus>,
    store: Store,
    /// ATECC answered and both its config and data zones are locked (see README: provisioning).
    ready: bool,
}

impl Ctap {
    pub fn new(at: Atecc<Bus>, store: Store, ready: bool) -> Self {
        Ctap { at, store, ready }
    }

    /// `req` = CTAP command byte + CBOR. `up` = user pressed the button for this request.
    /// Call first with `up = false`; on `NeedUp` call again with `true`.
    pub async fn handle(&mut self, req: &[u8], up: bool) -> Resp {
        let Some((&cmd, body)) = req.split_first() else {
            return Resp::Err(err::INVALID_LENGTH);
        };
        let r = match cmd {
            0x01 => self.make_credential(body, up).await,
            0x02 => self.get_assertion(body, up).await,
            0x04 => Ok(get_info()),
            0x07 => self.reset(up).await,
            0x0B => {
                if up {
                    Ok(Vec::new())
                } else {
                    Err(Stop::NeedUp)
                }
            }
            0x08 => Err(Stop::Err(err::NOT_ALLOWED)),
            _ => Err(Stop::Err(err::INVALID_COMMAND)),
        };
        match r {
            Ok(body) => {
                let mut out = Vec::with_capacity(body.len() + 1);
                out.push(0);
                out.extend_from_slice(&body);
                Resp::Ok(out)
            }
            Err(Stop::Err(c)) => Resp::Err(c),
            Err(Stop::NeedUp) => Resp::NeedUp,
        }
    }

    /// Table index (= ATECC slot) of the credential with this ID for this RP.
    fn find(&self, id: &[u8], rp: &[u8; 32]) -> Option<usize> {
        if id.len() != ID_LEN {
            return None;
        }
        self.store
            .slots
            .iter()
            .position(|c| c.as_ref().map_or(false, |c| c.id[..] == *id && c.rp == *rp))
    }

    async fn make_credential(&mut self, body: &[u8], up: bool) -> Res {
        let mut r = R::new(body);
        let (mut hash, mut rp_id) = (None, None);
        let (mut alg_ok, mut rk, mut uv, mut pin) = (false, false, false, false);
        let mut exclude: Vec<&[u8]> = Vec::new();
        let (mut user_id, mut user_name, mut user_disp): (Option<&[u8]>, &str, &str) = (None, "", "");

        for _ in 0..r.map()? {
            match r.uint()? {
                1 => hash = Some(r.bytes()?),
                3 => {
                    for _ in 0..r.map()? {
                        match r.text()? {
                            "id" => user_id = Some(r.bytes()?),
                            "name" => user_name = r.text()?,
                            "displayName" => user_disp = r.text()?,
                            _ => r.skip()?,
                        }
                    }
                }
                2 => {
                    for _ in 0..r.map()? {
                        if r.text()? == "id" {
                            rp_id = Some(r.text()?);
                        } else {
                            r.skip()?;
                        }
                    }
                }
                4 => {
                    for _ in 0..r.array()? {
                        let (mut alg, mut ty) = (None, None);
                        for _ in 0..r.map()? {
                            match r.text()? {
                                "alg" => alg = Some(r.int()?),
                                "type" => ty = Some(r.text()?),
                                _ => r.skip()?,
                            }
                        }
                        alg_ok |= alg == Some(-7) && ty == Some("public-key");
                    }
                }
                5 => {
                    for _ in 0..r.array()? {
                        for _ in 0..r.map()? {
                            if r.text()? == "id" {
                                exclude.push(r.bytes()?);
                            } else {
                                r.skip()?;
                            }
                        }
                    }
                }
                7 => {
                    for _ in 0..r.map()? {
                        match r.text()? {
                            "rk" => rk = r.bool()?,
                            "uv" => uv = r.bool()?,
                            _ => r.skip()?,
                        }
                    }
                }
                8 => {
                    pin = true;
                    r.skip()?
                }
                _ => r.skip()?,
            }
        }
        let hash = hash.ok_or(err::MISSING_PARAMETER)?;
        let rp_id = rp_id.ok_or(err::MISSING_PARAMETER)?;
        if hash.len() != 32 {
            return Err(err::INVALID_PARAMETER.into());
        }
        if pin {
            return Err(err::PIN_NOT_SET.into());
        }
        if uv {
            return Err(err::UNSUPPORTED_OPTION.into());
        }
        if !alg_ok {
            return Err(err::UNSUPPORTED_ALGORITHM.into());
        }
        if rk && user_id.is_none() {
            return Err(err::MISSING_PARAMETER.into());
        }
        if user_id.map_or(false, |u| u.len() > 64) {
            return Err(err::INVALID_PARAMETER.into());
        }
        if !self.ready {
            defmt::error!("ATECC not provisioned/locked - see README");
            return Err(err::OTHER.into());
        }
        let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let excluded = exclude.iter().any(|id| self.find(id, &rp).is_some());
        if !up {
            return Err(Stop::NeedUp);
        }
        if excluded {
            return Err(err::CREDENTIAL_EXCLUDED.into());
        }

        // Pick a slot: overwrite the same (rp, user) discoverable credential, else any free slot.
        let reuse = match (rk, user_id) {
            (true, Some(u)) => self.store.slots.iter().position(|c| {
                c.as_ref().map_or(false, |c| c.rk && c.rp == rp && c.uid.as_slice() == u)
            }),
            _ => None,
        };
        let slot = reuse
            .or_else(|| self.store.free_slot())
            .ok_or(err::KEY_STORE_FULL)?;
        let pk = hw(self.at.gen_key(slot as u8).await)?;

        let mut id = [0u8; ID_LEN];
        let mut rnd = [0u8; 32];
        hw(self.at.random(&mut rnd).await)?;
        id[0] = 1; // version
        id[1] = slot as u8;
        id[2..].copy_from_slice(&rnd[..ID_LEN - 2]);

        self.store.slots[slot] = Some(Cred {
            rk,
            id,
            rp,
            uid: if rk { user_id.unwrap_or(&[]).to_vec() } else { Vec::new() },
            name: if rk { trunc(user_name, 32) } else { String::new() },
            display: if rk { trunc(user_disp, 32) } else { String::new() },
        });
        if !self.store.save() {
            self.store.slots[slot] = None;
            return Err(err::OTHER.into());
        }

        let mut ad = Vec::with_capacity(256);
        ad.extend_from_slice(&rp);
        ad.push(0x41); // UP | AT
        ad.extend_from_slice(&[0, 0, 0, 0]); // sign count
        ad.extend_from_slice(&AAGUID);
        ad.extend_from_slice(&(id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&id);
        let mut c = W::new(); // COSE_Key, ES256
        c.map(5);
        c.uint(1);
        c.uint(2);
        c.uint(3);
        c.int(-7);
        c.int(-1);
        c.uint(1);
        c.int(-2);
        c.bytes(&pk[..32]);
        c.int(-3);
        c.bytes(&pk[32..]);
        ad.extend_from_slice(&c.0);

        let mut w = W::new();
        w.map(3);
        w.uint(1);
        w.text("none");
        w.uint(2);
        w.bytes(&ad);
        w.uint(3);
        w.map(0);
        Ok(w.0)
    }

    async fn get_assertion(&mut self, body: &[u8], touched: bool) -> Res {
        let mut r = R::new(body);
        let (mut rp_id, mut hash) = (None, None);
        let (mut want_up, mut uv, mut pin) = (true, false, false);
        let mut allow: Vec<&[u8]> = Vec::new();

        for _ in 0..r.map()? {
            match r.uint()? {
                1 => rp_id = Some(r.text()?),
                2 => hash = Some(r.bytes()?),
                3 => {
                    for _ in 0..r.array()? {
                        for _ in 0..r.map()? {
                            if r.text()? == "id" {
                                allow.push(r.bytes()?);
                            } else {
                                r.skip()?;
                            }
                        }
                    }
                }
                5 => {
                    for _ in 0..r.map()? {
                        match r.text()? {
                            "up" => want_up = r.bool()?,
                            "uv" => uv = r.bool()?,
                            _ => r.skip()?,
                        }
                    }
                }
                6 => {
                    pin = true;
                    r.skip()?
                }
                _ => r.skip()?,
            }
        }
        let rp_id = rp_id.ok_or(err::MISSING_PARAMETER)?;
        let hash = hash.ok_or(err::MISSING_PARAMETER)?;
        if hash.len() != 32 {
            return Err(err::INVALID_PARAMETER.into());
        }
        if pin {
            return Err(err::PIN_NOT_SET.into());
        }
        if uv {
            return Err(err::UNSUPPORTED_OPTION.into());
        }
        if !self.ready {
            return Err(err::OTHER.into());
        }
        let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let found = if allow.is_empty() {
            // discoverable credential login: newest matching resident credential
            self.store
                .slots
                .iter()
                .enumerate()
                .filter(|(_, c)| c.as_ref().map_or(false, |c| c.rk && c.rp == rp))
                .map(|(i, _)| i)
                .last()
        } else {
            allow.iter().find_map(|id| self.find(id, &rp))
        };
        let idx = found.ok_or(err::NO_CREDENTIALS)?;
        if want_up && !touched {
            return Err(Stop::NeedUp);
        }
        let (cid, user) = {
            let c = self.store.slots[idx].as_ref().ok_or(err::NO_CREDENTIALS)?;
            let user = if allow.is_empty() { Some((c.uid.clone(), c.name.clone(), c.display.clone())) } else { None };
            (c.id, user)
        };

        let mut ad = Vec::with_capacity(37);
        ad.extend_from_slice(&rp);
        ad.push(if want_up { 0x01 } else { 0x00 });
        ad.extend_from_slice(&[0, 0, 0, 0]);
        let mut h = Sha256::new();
        h.update(&ad);
        h.update(hash);
        let digest: [u8; 32] = h.finalize().into();
        let raw = hw(self.at.sign_digest(idx as u8, &digest).await)?;
        let sig = Signature::from_slice(&raw).map_err(|_| Stop::Err(err::OTHER))?;

        let mut w = W::new();
        w.map(if user.is_some() { 4 } else { 3 });
        w.uint(1);
        w.map(2);
        w.text("id");
        w.bytes(&cid);
        w.text("type");
        w.text("public-key");
        w.uint(2);
        w.bytes(&ad);
        w.uint(3);
        w.bytes(sig.to_der().as_bytes());
        if let Some((uid, name, disp)) = user {
            w.uint(4);
            w.map(1 + (!name.is_empty()) as u64 + (!disp.is_empty()) as u64);
            w.text("id");
            w.bytes(&uid);
            if !name.is_empty() {
                w.text("name");
                w.text(&name);
            }
            if !disp.is_empty() {
                w.text("displayName");
                w.text(&disp);
            }
        }
        Ok(w.0)
    }

    async fn reset(&mut self, up: bool) -> Res {
        if !up {
            return Err(Stop::NeedUp);
        }
        for s in 0..MAX_CREDS {
            if self.store.slots[s].is_some() {
                // Overwrite the old key inside the chip so it can never sign again.
                let _ = self.at.gen_key(s as u8).await;
                self.store.slots[s] = None;
            }
        }
        if !self.store.save() {
            return Err(err::OTHER.into());
        }
        Ok(Vec::new())
    }
}

fn get_info() -> Vec<u8> {
    let mut w = W::new();
    w.map(5);
    w.uint(1);
    w.arr(1);
    w.text("FIDO_2_0");
    w.uint(3);
    w.bytes(&AAGUID);
    w.uint(4);
    w.map(3);
    w.text("rk");
    w.bool(true);
    w.text("up");
    w.bool(true);
    w.text("plat");
    w.bool(false);
    w.uint(5);
    w.uint(MAX_MSG as u64);
    w.uint(8);
    w.uint(64);
    w.0
}
