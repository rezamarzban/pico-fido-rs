//! Minimal stateless CTAP2 authenticator (getInfo / makeCredential / getAssertion).
//!
//! Credentials are *not stored*: the credential ID is `nonce(32) || HMAC(master, rp, nonce)(32)`
//! and the ES256 private key is re-derived from `HMAC(master, rp, nonce)` on every use.
//! The only persistent secret is the 32-byte `master` key (see keys.rs).
//! No resident keys, no PIN, sign counter is always 0, attestation is "none".
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::cbor::{R, W};

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

pub struct Ctap {
    master: [u8; 32],
    /// Set when `master` changed (reset) and must be written to flash.
    pub dirty: bool,
}

impl Ctap {
    pub fn new(master: [u8; 32]) -> Self {
        Ctap { master, dirty: false }
    }
    pub fn master(&self) -> &[u8; 32] {
        &self.master
    }

    /// `req` = CTAP command byte + CBOR. `up` = user pressed the button for this request.
    /// Pure and re-entrant: call first with `up = false`; on `NeedUp` call again with `true`.
    pub fn handle(&mut self, req: &[u8], up: bool, rng: &mut dyn FnMut(&mut [u8])) -> Resp {
        let Some((&cmd, body)) = req.split_first() else {
            return Resp::Err(err::INVALID_LENGTH);
        };
        let r = match cmd {
            0x01 => self.make_credential(body, up, rng),
            0x02 => self.get_assertion(body, up),
            0x04 => Ok(get_info()),
            0x07 => self.reset(up, rng),
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

    fn mac(&self, tag: u8, rp: &[u8; 32], nonce: &[u8]) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.master).unwrap();
        m.update(&[tag]);
        m.update(rp);
        m.update(nonce);
        m
    }

    fn derive(&self, rp: &[u8; 32], nonce: &[u8]) -> Option<SigningKey> {
        let k = self.mac(b'k', rp, nonce).finalize().into_bytes();
        SigningKey::from_bytes(&k).ok()
    }

    /// Returns the signing key if `id` is a credential created by this device for this RP.
    fn check_cred(&self, rp: &[u8; 32], id: &[u8]) -> Option<SigningKey> {
        if id.len() != 64 {
            return None;
        }
        self.mac(b'i', rp, &id[..32]).verify_slice(&id[32..]).ok()?;
        self.derive(rp, &id[..32])
    }

    fn make_credential(&mut self, body: &[u8], up: bool, rng: &mut dyn FnMut(&mut [u8])) -> Res {
        let mut r = R::new(body);
        let (mut hash, mut rp_id) = (None, None);
        let (mut alg_ok, mut rk, mut uv, mut pin) = (false, false, false, false);
        let mut exclude: Vec<&[u8]> = Vec::new();

        for _ in 0..r.map()? {
            match r.uint()? {
                1 => hash = Some(r.bytes()?),
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
        if rk || uv {
            return Err(err::UNSUPPORTED_OPTION.into());
        }
        if !alg_ok {
            return Err(err::UNSUPPORTED_ALGORITHM.into());
        }
        let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let excluded = exclude.iter().any(|id| self.check_cred(&rp, id).is_some());
        if !up {
            return Err(Stop::NeedUp);
        }
        if excluded {
            return Err(err::CREDENTIAL_EXCLUDED.into());
        }

        // new credential
        let mut id = [0u8; 64];
        let sk = loop {
            rng(&mut id[..32]);
            if let Some(sk) = self.derive(&rp, &id[..32]) {
                break sk;
            }
        };
        let tag = self.mac(b'i', &rp, &id[..32]).finalize().into_bytes();
        id[32..].copy_from_slice(&tag);

        let mut ad = Vec::with_capacity(256);
        ad.extend_from_slice(&rp);
        ad.push(0x41); // UP | AT
        ad.extend_from_slice(&[0, 0, 0, 0]); // sign count
        ad.extend_from_slice(&AAGUID);
        ad.extend_from_slice(&(id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&id);
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut c = W::new(); // COSE_Key, ES256
        c.map(5);
        c.uint(1);
        c.uint(2);
        c.uint(3);
        c.int(-7);
        c.int(-1);
        c.uint(1);
        c.int(-2);
        c.bytes(pt.x().unwrap());
        c.int(-3);
        c.bytes(pt.y().unwrap());
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

    fn get_assertion(&mut self, body: &[u8], touched: bool) -> Res {
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
        let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let (id, sk) = allow
            .iter()
            .find_map(|id| self.check_cred(&rp, id).map(|k| (*id, k)))
            .ok_or(err::NO_CREDENTIALS)?;
        if want_up && !touched {
            return Err(Stop::NeedUp);
        }

        let mut ad = Vec::with_capacity(37);
        ad.extend_from_slice(&rp);
        ad.push(if want_up { 0x01 } else { 0x00 });
        ad.extend_from_slice(&[0, 0, 0, 0]);
        let mut msg = ad.clone();
        msg.extend_from_slice(hash);
        let sig: Signature = sk.sign(&msg);

        let mut w = W::new();
        w.map(3);
        w.uint(1);
        w.map(2);
        w.text("id");
        w.bytes(id);
        w.text("type");
        w.text("public-key");
        w.uint(2);
        w.bytes(&ad);
        w.uint(3);
        w.bytes(sig.to_der().as_bytes());
        Ok(w.0)
    }

    fn reset(&mut self, up: bool, rng: &mut dyn FnMut(&mut [u8])) -> Res {
        if !up {
            return Err(Stop::NeedUp);
        }
        rng(&mut self.master);
        self.dirty = true;
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
    w.bool(false);
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
