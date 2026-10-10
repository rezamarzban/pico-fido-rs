//! Minimal stateless CTAP2 authenticator (getInfo / makeCredential / getAssertion / clientPIN).
//!
//! Credentials are *not stored*: the credential ID is `nonce(32) || HMAC(master, rp, nonce)(32)`
//! and the ES256 private key is re-derived from `HMAC(master, rp, nonce)` on every use.
//! The only persistent secret is the 32-byte `master` key (see store.rs / keys.rs).
//! No resident keys, sign counter is always 0, attestation is "none".
//!
//! PIN (optional): with a PIN set, the master key is stored only *wrapped* under a key derived
//! from the PIN (wrap.rs, Argon2id). It is unwrapped by `getPinToken` and kept in RAM only while
//! the returned pinUvAuthToken is valid (`TOKEN_LIFETIME_MS`), then wiped (`tick`, `lock`).
//! PIN attempts are counted persistently BEFORE a guess is evaluated (store.rs).
//!
//! Policy (SECURITY.md): every signature needs a fresh button press. The authenticator enforces
//! this itself: the `up` option of getAssertion is validated but can never switch the touch off.
//! The PIN adds "something you know" on top of the button, it never replaces it.
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::SecretKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::cbor::{self, R, W};
use crate::pin::{self, Shared};
use crate::store::{Record, Replaced, Vault, TRIES_MAX};
use crate::wrap;

pub const AAGUID: [u8; 16] = [0; 16];
pub const MAX_MSG: usize = 1200;
/// Reset is only accepted this long after power-up (CTAP 2.2 rule for authenticators without a display).
pub const RESET_WINDOW_MS: u64 = 10_000;
/// Minimum PIN length in Unicode code points. A long passphrase matters: anyone who can read the
/// flash can try PINs offline at Argon2 speed (SECURITY.md).
pub const MIN_PIN_LEN: usize = 10;
/// How long a pinUvAuthToken (and with it the unwrapped master key in RAM) stays valid.
pub const TOKEN_LIFETIME_MS: u64 = 120_000;
/// Wrong PINs in a row (since power-up) before a power cycle is required.
const MAX_BOOT_FAILS: u8 = 3;

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
    pub const PIN_INVALID: u8 = 0x31;
    pub const PIN_BLOCKED: u8 = 0x32;
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    pub const PIN_AUTH_BLOCKED: u8 = 0x34;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const PIN_REQUIRED: u8 = 0x36;
    pub const PIN_POLICY_VIOLATION: u8 = 0x37;
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

/// State of the master key.
enum Key {
    /// Key storage unreadable/corrupt/unknown: the device refuses to work (never re-keys
    /// silently) until the user performs an explicit reset.
    Broken,
    /// No PIN set: the plain key is available.
    Plain([u8; 32]),
    /// PIN set, no valid session: only the wrapped record is known, the key is NOT in RAM.
    Locked(Record),
    /// PIN set and a session is valid: the unwrapped key is in RAM until the token expires.
    Unlocked([u8; 32], Record),
}

struct Token {
    bytes: [u8; 32],
    expires: u64,
}

pub struct Ctap {
    key: Key,
    /// Key agreement key of the PIN protocol (regenerated after PIN changes and wrong PINs).
    agree: Option<SecretKey>,
    token: Option<Token>,
    /// Wrong PINs since power-up (RAM only, so a power cycle clears it, as CTAP requires).
    boot_fails: u8,
}

/// Parsed clientPIN request fields.
struct P<'a> {
    v: u8,
    agree: Option<p256::PublicKey>,
    auth: Option<&'a [u8]>,
    new_enc: Option<&'a [u8]>,
    hash_enc: Option<&'a [u8]>,
}

/// Outcome of persisting a new record.
enum Commit {
    /// The new record is durable and every older record was verified destroyed.
    Done,
    /// The new record is durable and is what the next boot loads, but an older record (possibly the
    /// plaintext key, or the key wrapped under the old PIN) could not be wiped and may still be
    /// readable in flash. The firmware state already equals the new record.
    OldRemains,
    /// Nothing changed (or the state is unknown and the key is refused): see `commit`.
    Failed,
}

/// The CTAP answer for a commit plus the retry-counter work that has to go with it. Anything but a
/// complete success is reported as an error so that nobody is told "PIN set" / "reset done" while
/// old key material may still be readable or the retry counter is not in the required state.
/// The running state is adopted either way, so it always matches the flash.
fn commit_result(c: Commit, tries_ok: bool) -> Res {
    match c {
        Commit::Done if tries_ok => Ok(Vec::new()),
        _ => Err(err::OTHER.into()),
    }
}

fn key_from(rec: Option<Record>) -> Key {
    match rec {
        None => Key::Broken,
        Some(r) if !r.wrapped => Key::Plain(r.body),
        Some(r) => Key::Locked(r),
    }
}

impl Ctap {
    /// `rec` = the record the boot loader found (`None` = unreadable/corrupt).
    pub fn new(rec: Option<Record>) -> Self {
        Ctap {
            key: key_from(rec),
            agree: None,
            token: None,
            boot_fails: 0,
        }
    }

    fn wipe_token(&mut self) {
        if let Some(t) = &mut self.token {
            t.bytes.zeroize();
        }
        self.token = None;
    }

    /// Replaces the key state, wiping the old secrets and any token.
    fn set_key(&mut self, k: Key) {
        self.wipe_token();
        if let Key::Plain(m) | Key::Unlocked(m, _) = &mut self.key {
            m.zeroize();
        }
        self.key = k;
    }

    /// Ends a PIN session now: wipes the unwrapped key and the token (USB reset, suspend, expiry).
    pub fn lock(&mut self) {
        // The ephemeral ClientPIN key-agreement key ends with the session as well
        // (`SecretKey` zeroizes itself on drop).
        self.agree = None;
        let rec = match &self.key {
            Key::Unlocked(_, r) => Some(r.clone()),
            _ => None,
        };
        match rec {
            Some(r) => self.set_key(Key::Locked(r)),
            None => self.wipe_token(),
        }
    }

    /// Call regularly (about once a second) so an expired session is wiped even when idle.
    pub fn tick(&mut self, now_ms: u64) {
        if matches!(&self.token, Some(t) if now_ms >= t.expires) {
            self.lock();
        }
    }

    /// Persists `rec` and makes the running state equal to what the next boot will load.
    fn commit(&mut self, vault: &mut dyn Vault, rec: &Record) -> Commit {
        self.agree = None;
        match vault.replace(rec) {
            Replaced::New(saved) => {
                self.set_key(key_from(Some(rec.clone())));
                if saved.old_wiped {
                    Commit::Done
                } else {
                    Commit::OldRemains
                }
            }
            Replaced::Kept(k) => {
                self.set_key(key_from(Some(k)));
                Commit::Failed
            }
            Replaced::NoKey | Replaced::Unknown => {
                self.set_key(Key::Broken);
                Commit::Failed
            }
        }
    }

    /// Same as [`handle_at`](Self::handle_at) for a request that is processed the moment it
    /// arrives (`arrived_ms == now_ms`).
    #[allow(dead_code)]
    pub fn handle(
        &mut self,
        req: &[u8],
        up: bool,
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Resp {
        self.handle_at(req, up, now_ms, now_ms, rng, vault)
    }

    /// `req` = CTAP command byte + CBOR. `up` = user pressed the button for this request.
    ///
    /// Two clocks, both in ms since power-up, which must not be mixed up:
    /// * `arrived_ms` = when the request ARRIVED. Only the 10 s reset window is judged on it, so a
    ///   delayed button press never makes a request that arrived in time look late.
    /// * `now_ms` = the CURRENT time. PIN token / session expiry is judged on it, so a request that
    ///   waited for the button past the end of the session is refused instead of being authorised
    ///   by a stale timestamp.
    ///
    /// Re-entrant: call first with `up = false`; on `NeedUp` call again with `true` and the SAME
    /// `arrived_ms` (but the current `now_ms`). Nothing that cannot be repeated (PIN attempts, flash
    /// writes) happens before the button press has been requested for commands that need it.
    pub fn handle_at(
        &mut self,
        req: &[u8],
        up: bool,
        arrived_ms: u64,
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Resp {
        self.tick(now_ms);
        let Some((&cmd, body)) = req.split_first() else {
            return Resp::Err(err::INVALID_LENGTH);
        };
        let r = match cmd {
            0x01 | 0x02 | 0x06 => cbor::validate(body)
                .map_err(Stop::Err)
                .and_then(|_| match cmd {
                    1 => self.make_credential(body, up, now_ms, rng),
                    2 => self.get_assertion(body, up, now_ms),
                    _ => self.client_pin(body, up, now_ms, rng, vault),
                }),
            0x04 | 0x07 | 0x0B if !body.is_empty() => Err(Stop::Err(err::INVALID_LENGTH)),
            0x04 => Ok(self.get_info()),
            0x07 => self.reset(up, arrived_ms, rng, vault),
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

    /// The master key, if it may be used right now.
    fn master(&self) -> Result<&[u8; 32], Stop> {
        match &self.key {
            Key::Plain(m) | Key::Unlocked(m, _) => Ok(m),
            Key::Locked(_) => Err(err::PIN_REQUIRED.into()),
            Key::Broken => Err(err::OTHER.into()),
        }
    }

    /// Test probe: is the usable master key currently held in RAM?
    #[cfg(test)]
    pub fn key_in_ram(&self) -> bool {
        matches!(self.key, Key::Plain(_) | Key::Unlocked(..))
    }

    /// Error for PIN commands that need a PIN when none is set.
    fn no_pin_error(&self) -> u8 {
        if matches!(self.key, Key::Broken) {
            err::OTHER
        } else {
            err::PIN_NOT_SET
        }
    }

    /// The wrapped record, if a PIN is set.
    fn pin_rec(&self) -> Option<&Record> {
        match &self.key {
            Key::Locked(r) | Key::Unlocked(_, r) => Some(r),
            _ => None,
        }
    }

    /// Checks the PIN authentication of a makeCredential / getAssertion request.
    /// Returns whether the request was authenticated with the PIN (UV flag).
    fn check_pin(
        &self,
        now_ms: u64,
        hash: &[u8],
        param: Option<&[u8]>,
        proto: Option<u64>,
    ) -> Result<bool, Stop> {
        match &self.key {
            Key::Broken => Err(err::OTHER.into()),
            Key::Plain(_) => {
                if param.is_some() {
                    Err(err::PIN_NOT_SET.into())
                } else {
                    Ok(false)
                }
            }
            Key::Locked(_) | Key::Unlocked(..) => {
                let Some(param) = param else {
                    return Err(err::PIN_REQUIRED.into());
                };
                let v = match proto {
                    Some(v @ (1 | 2)) => v as u8,
                    Some(_) => return Err(err::INVALID_PARAMETER.into()),
                    None => return Err(err::MISSING_PARAMETER.into()),
                };
                match &self.token {
                    Some(t)
                        if now_ms < t.expires && pin::verify_token(v, &t.bytes, &[hash], param) =>
                    {
                        Ok(true)
                    }
                    _ => Err(err::PIN_AUTH_INVALID.into()),
                }
            }
        }
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

    fn make_credential(
        &mut self,
        body: &[u8],
        up: bool,
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Res {
        let mut r = R::new(body);
        let (mut hash, mut rp_id, mut user_id) = (None, None, None);
        let (mut have_user, mut have_params) = (false, false);
        let (mut alg_ok, mut rk, mut uv) = (false, false, false);
        let (mut pin_param, mut pin_proto) = (None, None);
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
                8 => pin_param = Some(r.bytes()?),
                9 => pin_proto = Some(r.uint()?),
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
        let pin_ok = self.check_pin(now_ms, hash, pin_param, pin_proto)?;
        if rk || uv {
            return Err(err::UNSUPPORTED_OPTION.into());
        }
        if !alg_ok {
            return Err(err::UNSUPPORTED_ALGORITHM.into());
        }
        let master = self.master()?;
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
        ad.push(0x41 | if pin_ok { 0x04 } else { 0 }); // UP | AT (| UV when the PIN was verified)
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

    fn get_assertion(&mut self, body: &[u8], touched: bool, now_ms: u64) -> Res {
        let mut r = R::new(body);
        let (mut rp_id, mut hash) = (None, None);
        let mut uv = false;
        let (mut pin_param, mut pin_proto) = (None, None);
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
                6 => pin_param = Some(r.bytes()?),
                7 => pin_proto = Some(r.uint()?),
                _ => r.skip()?,
            }
        }
        let rp_id = rp_id.ok_or(err::MISSING_PARAMETER)?;
        let hash = hash.ok_or(err::MISSING_PARAMETER)?;
        if hash.len() != 32 {
            return Err(err::INVALID_PARAMETER.into());
        }
        let pin_ok = self.check_pin(now_ms, hash, pin_param, pin_proto)?;
        if uv {
            return Err(err::UNSUPPORTED_OPTION.into());
        }
        let master = self.master()?;
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
        ad.push(0x01 | if pin_ok { 0x04 } else { 0 }); // UP: button pressed (| UV: PIN verified)
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

    /// Factory reset: a new random master key, no PIN, retry counter cleared. Works in every
    /// state (also when locked or broken); that is the recovery path for a forgotten PIN.
    fn reset(
        &mut self,
        up: bool,
        arrived_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Res {
        if arrived_ms > RESET_WINDOW_MS {
            return Err(err::NOT_ALLOWED.into()); // replug the key and try again
        }
        if !up {
            return Err(Stop::NeedUp);
        }
        let mut k = [0u8; 32];
        rng(&mut k);
        let rec = Record::plain(k);
        k.zeroize();
        let c = self.commit(vault, &rec);
        self.boot_fails = 0;
        let tries_ok = !matches!(c, Commit::Failed) && vault.clear_tries().is_ok();
        commit_result(c, tries_ok)
    }

    // ---- authenticatorClientPIN -----------------------------------------------------------------

    fn client_pin(
        &mut self,
        body: &[u8],
        up: bool,
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Res {
        let mut r = R::new(body);
        let (mut proto, mut sub) = (None, None);
        let (mut agree, mut auth, mut new_enc, mut hash_enc) = (None, None, None, None);
        for _ in 0..r.map()? {
            match r.uint()? {
                1 => proto = Some(r.uint()?),
                2 => sub = Some(r.uint()?),
                3 => agree = Some(pin::parse_cose(&mut r)?),
                4 => auth = Some(r.bytes()?),
                5 => new_enc = Some(r.bytes()?),
                6 => hash_enc = Some(r.bytes()?),
                _ => r.skip()?,
            }
        }
        let sub = sub.ok_or(err::MISSING_PARAMETER)?;
        if sub == 1 {
            return self.pin_retries(vault);
        }
        let v = match proto {
            Some(v @ (1 | 2)) => v as u8,
            Some(_) => return Err(err::INVALID_PARAMETER.into()),
            None => return Err(err::MISSING_PARAMETER.into()),
        };
        let p = P {
            v,
            agree,
            auth,
            new_enc,
            hash_enc,
        };
        match sub {
            2 => {
                let pk = self.agree_key(rng).public_key();
                let mut w = W::new();
                w.map(1);
                w.uint(1);
                w.0.extend_from_slice(&pin::cose_key(&pk));
                Ok(w.0)
            }
            3 => self.set_pin(&p, up, rng, vault),
            4 => self.change_pin(&p, up, rng, vault),
            5 => self.get_token(&p, now_ms, rng, vault),
            _ => Err(err::INVALID_PARAMETER.into()),
        }
    }

    fn agree_key(&mut self, rng: &mut dyn FnMut(&mut [u8])) -> &SecretKey {
        self.agree.get_or_insert_with(|| pin::new_secret(rng))
    }

    fn shared(&mut self, p: &P, rng: &mut dyn FnMut(&mut [u8])) -> Result<Shared, Stop> {
        let peer = p.agree.as_ref().ok_or(err::MISSING_PARAMETER)?;
        let sk = self.agree_key(rng);
        Ok(Shared::derive(p.v, sk, peer))
    }

    fn pin_retries(&self, vault: &mut dyn Vault) -> Res {
        let used = vault.tries_used().map_err(|_| Stop::Err(err::OTHER))?;
        let left = (TRIES_MAX as u8).saturating_sub(used);
        let need_power_cycle = self.boot_fails >= MAX_BOOT_FAILS;
        let mut w = W::new();
        w.map(if need_power_cycle { 2 } else { 1 });
        w.uint(3);
        w.uint(left as u64);
        if need_power_cycle {
            w.uint(4);
            w.bool(true);
        }
        Ok(w.0)
    }

    /// Validates a padded newPin block and returns LEFT(SHA-256(PIN), 16).
    fn pin_hash_of(block: &[u8]) -> Result<[u8; 16], u8> {
        if block.len() != 64 {
            return Err(err::PIN_POLICY_VIOLATION);
        }
        let n = block.iter().position(|&b| b == 0).unwrap_or(64);
        if n == 64 || block[n..].iter().any(|&b| b != 0) {
            return Err(err::PIN_POLICY_VIOLATION);
        }
        let pin = core::str::from_utf8(&block[..n]).map_err(|_| err::PIN_POLICY_VIOLATION)?;
        if pin.chars().count() < MIN_PIN_LEN {
            return Err(err::PIN_POLICY_VIOLATION);
        }
        let h = Sha256::digest(&block[..n]);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h[..16]);
        Ok(out)
    }

    fn new_pin_hash(sh: &Shared, enc: &[u8]) -> Result<[u8; 16], Stop> {
        let mut pt = sh.decrypt(enc).ok_or(err::INVALID_PARAMETER)?;
        let h = Self::pin_hash_of(&pt);
        pt.zeroize();
        Ok(h?)
    }

    fn rewrap(
        master: &[u8; 32],
        hash: &[u8; 16],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Option<Record> {
        let mut salt = [0u8; 16];
        rng(&mut salt);
        wrap::wrap(master, hash, salt)
    }

    /// Checks the PIN hash the platform sent. The attempt is persisted BEFORE it is evaluated;
    /// a correct PIN forgives earlier failures. Returns the unwrapped master key.
    fn verify_pin(
        &mut self,
        sh: &Shared,
        hash_enc: Option<&[u8]>,
        vault: &mut dyn Vault,
    ) -> Result<[u8; 32], Stop> {
        let hash_enc = hash_enc.ok_or(err::MISSING_PARAMETER)?;
        let rec = match self.pin_rec() {
            Some(r) => r.clone(),
            None => return Err(err::PIN_NOT_SET.into()),
        };
        let used = vault.tries_used().map_err(|_| Stop::Err(err::OTHER))?;
        if used as usize >= TRIES_MAX {
            return Err(err::PIN_BLOCKED.into());
        }
        if self.boot_fails >= MAX_BOOT_FAILS {
            return Err(err::PIN_AUTH_BLOCKED.into());
        }
        let page = vault.begin_try().map_err(|_| Stop::Err(err::OTHER))?;

        let mut master = None;
        if let Some(mut h) = sh.decrypt(hash_enc) {
            if h.len() == 16 {
                let mut a = [0u8; 16];
                a.copy_from_slice(&h);
                master = wrap::unwrap(&rec, &a);
                a.zeroize();
            }
            h.zeroize();
        }
        match master {
            Some(mut m) => {
                if vault.finish_try(page).is_err() {
                    // The PIN is right but the attempt could not be recorded as correct. Fail
                    // closed: no key and no token (the attempt stays counted as a failure).
                    m.zeroize();
                    return Err(err::OTHER.into());
                }
                self.boot_fails = 0;
                Ok(m)
            }
            None => {
                self.boot_fails += 1;
                self.agree = None;
                let left = TRIES_MAX - used as usize - 1;
                let code = if left == 0 {
                    err::PIN_BLOCKED
                } else if self.boot_fails >= MAX_BOOT_FAILS {
                    err::PIN_AUTH_BLOCKED
                } else {
                    err::PIN_INVALID
                };
                Err(code.into())
            }
        }
    }

    fn set_pin(
        &mut self,
        p: &P,
        up: bool,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Res {
        match &self.key {
            Key::Plain(_) => {}
            Key::Broken => return Err(err::OTHER.into()),
            _ => return Err(err::PIN_AUTH_INVALID.into()), // a PIN is already set
        }
        let new_enc = p.new_enc.ok_or(err::MISSING_PARAMETER)?;
        let auth = p.auth.ok_or(err::MISSING_PARAMETER)?;
        let sh = self.shared(p, rng)?;
        if !sh.verify(&[new_enc], auth) {
            return Err(err::PIN_AUTH_INVALID.into());
        }
        let mut hash = Self::new_pin_hash(&sh, new_enc)?;
        if !up {
            hash.zeroize();
            return Err(Stop::NeedUp); // setting a PIN needs the button, like every other change
        }
        let rec = match self.master() {
            Ok(m) => Self::rewrap(m, &hash, rng),
            Err(e) => {
                hash.zeroize();
                return Err(e);
            }
        };
        hash.zeroize();
        let rec = rec.ok_or(err::OTHER)?;
        let c = self.commit(vault, &rec);
        let tries_ok = !matches!(c, Commit::Failed) && vault.clear_tries().is_ok();
        commit_result(c, tries_ok)
    }

    fn change_pin(
        &mut self,
        p: &P,
        up: bool,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Res {
        if self.pin_rec().is_none() {
            return Err(self.no_pin_error().into());
        }
        let new_enc = p.new_enc.ok_or(err::MISSING_PARAMETER)?;
        let hash_enc = p.hash_enc.ok_or(err::MISSING_PARAMETER)?;
        let auth = p.auth.ok_or(err::MISSING_PARAMETER)?;
        let sh = self.shared(p, rng)?;
        if !sh.verify(&[new_enc, hash_enc], auth) {
            return Err(err::PIN_AUTH_INVALID.into());
        }
        if !up {
            return Err(Stop::NeedUp);
        }
        let mut master = self.verify_pin(&sh, Some(hash_enc), vault)?;
        let mut new_hash = match Self::new_pin_hash(&sh, new_enc) {
            Ok(h) => h,
            Err(e) => {
                master.zeroize();
                return Err(e);
            }
        };
        let rec = Self::rewrap(&master, &new_hash, rng);
        master.zeroize();
        new_hash.zeroize();
        let rec = rec.ok_or(err::OTHER)?;
        // verify_pin already reset the retry counter
        let c = self.commit(vault, &rec);
        commit_result(c, true)
    }

    fn get_token(
        &mut self,
        p: &P,
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]),
        vault: &mut dyn Vault,
    ) -> Res {
        let Some(rec) = self.pin_rec().cloned() else {
            return Err(self.no_pin_error().into());
        };
        let sh = self.shared(p, rng)?;
        let mut master = self.verify_pin(&sh, p.hash_enc, vault)?;
        self.set_key(Key::Unlocked(master, rec));
        master.zeroize();
        let mut t = [0u8; 32];
        rng(&mut t);
        let enc = sh.encrypt(&t, rng);
        self.token = Some(Token {
            bytes: t,
            expires: now_ms.saturating_add(TOKEN_LIFETIME_MS),
        });
        t.zeroize();
        self.agree = None;
        let mut w = W::new();
        w.map(1);
        w.uint(2);
        w.bytes(&enc);
        Ok(w.0)
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

impl Ctap {
    fn get_info(&self) -> Vec<u8> {
        // `versions` stays FIDO_2_0 on purpose: declaring FIDO_2_1 would promise 2.1 features
        // (credential management, permissions, ...) that are not implemented. PIN protocol 2 and
        // minPINLength (a 2.1 field, harmless for 2.0 clients) are advertised so that clients can
        // pick the protocol and show the PIN policy before trying to set a PIN.
        let mut w = W::new();
        w.map(7);
        w.uint(1);
        w.arr(1);
        w.text("FIDO_2_0");
        w.uint(3);
        w.bytes(&AAGUID);
        w.uint(4);
        w.map(4);
        w.text("rk");
        w.bool(false);
        w.text("up");
        w.bool(true);
        w.text("plat");
        w.bool(false);
        w.text("clientPin");
        w.bool(self.pin_rec().is_some());
        w.uint(5);
        w.uint(MAX_MSG as u64);
        w.uint(6);
        w.arr(2); // PIN/UV auth protocols, in order of preference
        w.uint(2);
        w.uint(1);
        w.uint(8);
        w.uint(64);
        w.uint(13); // minPINLength
        w.uint(MIN_PIN_LEN as u64);
        w.0
    }
}
