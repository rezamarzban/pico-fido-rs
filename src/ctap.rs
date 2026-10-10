//! Minimal stateless CTAP2 authenticator (getInfo / makeCredential / getAssertion).
//!
//! Credentials are *not stored*: the credential ID is `nonce(32) || HMAC(master, rp, nonce)(32)`
//! and the ES256 private key is re-derived from `HMAC(master, rp, nonce)` on every use.
//! The only persistent secret is the 32-byte `master` key (see store.rs / keys.rs).
//! No resident keys, no PIN, sign counter is always 0, attestation is "none".
//!
//! Policy (SECURITY.md): every signature needs a fresh button press. The authenticator enforces
//! this itself: the `up` option of getAssertion is validated but can never switch the touch off.
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::cbor::{self, R, W};

pub const AAGUID: [u8; 16] = [0; 16];
pub const MAX_MSG: usize = 1200;
/// Reset is only accepted this long after power-up (CTAP 2.2 rule for authenticators without a display).
pub const RESET_WINDOW_MS: u64 = 10_000;

pub mod err {
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const INVALID_LENGTH: u8 = 0x03;
    pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
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
    /// Reset was approved. Persist this new master key with `keys::replace`, call `set_key` with
    /// the key it reports as active, and answer success (0x00) only if it reports `ok`;
    /// otherwise answer `err::OTHER`.
    Reset([u8; 32]),
}

enum Stop {
    Err(u8),
    NeedUp,
    Reset([u8; 32]),
}
impl From<u8> for Stop {
    fn from(c: u8) -> Self {
        Stop::Err(c)
    }
}
type Res = Result<Vec<u8>, Stop>;

pub struct Ctap {
    /// `None` = key storage unreadable/corrupt: the device refuses to work (never re-keys silently)
    /// until the user performs an explicit reset.
    master: Option<[u8; 32]>,
}

impl Ctap {
    pub fn new(master: Option<[u8; 32]>) -> Self {
        Ctap { master }
    }
    /// Sets the active master key (`None` = refuse to operate). The caller must only pass the key
    /// that the next boot will load from flash (see keys::replace).
    pub fn set_key(&mut self, key: Option<[u8; 32]>) {
        self.master = key;
    }

    /// `req` = CTAP command byte + CBOR. `up` = user pressed the button for this request.
    /// `now_ms` = time since power-up *at which the request arrived*. Re-entrant: call first with
    /// `up = false`; on `NeedUp` call again with `true` and the SAME `now_ms`, so that waiting
    /// for the button never makes a request that arrived in time look late (reset window).
    pub fn handle(
        &mut self,
        req: &[u8],
        up: bool,
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Resp {
        let Some((&cmd, body)) = req.split_first() else {
            return Resp::Err(err::INVALID_LENGTH);
        };
        let r = match cmd {
            0x01 | 0x02 => cbor::validate(body).map_err(Stop::Err).and_then(|_| {
                if cmd == 1 {
                    self.make_credential(body, up, rng)
                } else {
                    self.get_assertion(body, up)
                }
            }),
            0x04 | 0x07 | 0x0B if !body.is_empty() => Err(Stop::Err(err::INVALID_LENGTH)),
            0x04 => Ok(get_info()),
            0x07 => self.reset(up, now_ms, rng),
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
            Err(Stop::Reset(k)) => Resp::Reset(k),
        }
    }

    fn key(&self) -> Result<&[u8; 32], Stop> {
        self.master.as_ref().ok_or(Stop::Err(err::OTHER))
    }

    fn mac(master: &[u8; 32], tag: u8, rp: &[u8; 32], nonce: &[u8]) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(master).unwrap();
        m.update(&[tag]);
        m.update(rp);
        m.update(nonce);
        m
    }

    fn derive(master: &[u8; 32], rp: &[u8; 32], nonce: &[u8]) -> Option<SigningKey> {
        let k = Self::mac(master, b'k', rp, nonce).finalize().into_bytes();
        SigningKey::from_bytes(&k).ok()
    }

    /// Returns the signing key if `id` is a credential created by this device for this RP.
    fn check_cred(master: &[u8; 32], rp: &[u8; 32], id: &[u8]) -> Option<SigningKey> {
        if id.len() != 64 {
            return None;
        }
        Self::mac(master, b'i', rp, &id[..32])
            .verify_slice(&id[32..])
            .ok()?;
        Self::derive(master, rp, &id[..32])
    }

    fn make_credential(&mut self, body: &[u8], up: bool, rng: &mut dyn FnMut(&mut [u8])) -> Res {
        let mut r = R::new(body);
        let (mut hash, mut rp_id, mut user_id) = (None, None, None);
        let (mut have_user, mut have_params) = (false, false);
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
                3 => {
                    have_user = true;
                    for _ in 0..r.map()? {
                        if r.text()? == "id" {
                            user_id = Some(r.bytes()?);
                        } else {
                            r.skip()?;
                        }
                    }
                }
                4 => {
                    have_params = true;
                    for _ in 0..r.array()? {
                        let (mut alg, mut ty) = (None, None);
                        for _ in 0..r.map()? {
                            match r.text()? {
                                "alg" => alg = Some(r.int()?),
                                "type" => ty = Some(r.text()?),
                                _ => r.skip()?,
                            }
                        }
                        if alg.is_none() || ty.is_none() {
                            return Err(err::CBOR_UNEXPECTED_TYPE.into());
                        }
                        alg_ok |= alg == Some(-7) && ty == Some("public-key");
                    }
                }
                5 => {
                    for _ in 0..r.array()? {
                        if let Some(id) = descriptor(&mut r)? {
                            exclude.push(id);
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
        if !have_user || !have_params {
            return Err(err::MISSING_PARAMETER.into());
        }
        let user_id = user_id.ok_or(err::CBOR_UNEXPECTED_TYPE)?;
        if hash.len() != 32 || user_id.is_empty() || user_id.len() > 64 {
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
        let master = self.key()?;
        let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let excluded = exclude
            .iter()
            .any(|id| Self::check_cred(master, &rp, id).is_some());
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
            if let Some(sk) = Self::derive(master, &rp, &id[..32]) {
                break sk;
            }
        };
        let tag = Self::mac(master, b'i', &rp, &id[..32])
            .finalize()
            .into_bytes();
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
        let (mut uv, mut pin) = (false, false);
        let mut allow: Vec<&[u8]> = Vec::new();

        for _ in 0..r.map()? {
            match r.uint()? {
                1 => rp_id = Some(r.text()?),
                2 => hash = Some(r.bytes()?),
                3 => {
                    for _ in 0..r.array()? {
                        if let Some(id) = descriptor(&mut r)? {
                            allow.push(id);
                        }
                    }
                }
                5 => {
                    for _ in 0..r.map()? {
                        match r.text()? {
                            // validated, but deliberately not honoured: signing always needs a touch
                            "up" => {
                                r.bool()?;
                            }
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
        let master = self.key()?;
        let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let (id, sk) = allow
            .iter()
            .find_map(|id| Self::check_cred(master, &rp, id).map(|k| (*id, k)))
            .ok_or(err::NO_CREDENTIALS)?;
        if !touched {
            return Err(Stop::NeedUp);
        }

        let mut ad = Vec::with_capacity(37);
        ad.extend_from_slice(&rp);
        ad.push(0x01); // UP: the button was pressed for this signature
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

    fn reset(&mut self, up: bool, now_ms: u64, rng: &mut dyn FnMut(&mut [u8])) -> Res {
        if now_ms > RESET_WINDOW_MS {
            return Err(err::NOT_ALLOWED.into()); // replug the key and try again
        }
        if !up {
            return Err(Stop::NeedUp);
        }
        let mut k = [0u8; 32];
        rng(&mut k);
        Err(Stop::Reset(k))
    }
}

/// Parses a PublicKeyCredentialDescriptor. Both `type` and `id` are required
/// (a missing member is reported as CBOR_UNEXPECTED_TYPE, as CTAP2 recommends for nested structures).
/// Returns the id only for type "public-key" (other types are ignored, per spec).
fn descriptor<'a>(r: &mut R<'a>) -> Result<Option<&'a [u8]>, u8> {
    let (mut id, mut ty) = (None, None);
    for _ in 0..r.map()? {
        match r.text()? {
            "id" => id = Some(r.bytes()?),
            "type" => ty = Some(r.text()?),
            _ => r.skip()?,
        }
    }
    match (id, ty) {
        (Some(id), Some(ty)) => Ok(if ty == "public-key" { Some(id) } else { None }),
        _ => Err(err::CBOR_UNEXPECTED_TYPE),
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
