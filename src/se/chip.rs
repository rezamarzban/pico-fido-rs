//! ATECC608A command layer. `Bus` is the only hardware dependency (I2C + delay), so everything
//! here runs unchanged against the fake chip in host-test/se.

use super::auth;
use super::proto::{self, Error};

/// Hardware access needed by the driver.
pub trait Bus {
    /// Holds SDA low for >= 60 us (wake pulse) and waits tWHI (>= 1.5 ms) afterwards.
    fn wake_pulse(&mut self);
    /// Raw I2C write to the chip (the first byte is the word address).
    fn write(&mut self, data: &[u8]) -> Result<(), ()>;
    /// Raw I2C read from the chip. A busy chip NACKs its address: that is `Err`.
    fn read(&mut self, buf: &mut [u8]) -> Result<(), ()>;
    fn delay_ms(&mut self, ms: u32);
}

/// Proof of knowledge of the PIN key, replayed inside every wake session that uses a key slot
/// with ReqAuth. Lives in RAM only.
#[derive(Clone)]
pub struct Auth {
    pub slot: u8,
    pub key: [u8; 32],
}

/// Operations the rest of the firmware needs. Object safe, so `se::ecdsa` can reach the chip
/// through one global without being generic over the bus.
pub trait ChipOps {
    /// 32 random bytes from the chip's NIST SP 800-90A DRBG / TRNG.
    fn random(&mut self) -> Result<[u8; 32], Error>;
    /// 72-bit serial number.
    fn serial(&mut self) -> Result<auth::Serial, Error>;
    /// Creates a new random P-256 private key inside `slot` (the old key is gone) and returns the
    /// public key X||Y. `auth`: PIN authorisation for slots with ReqAuth.
    fn gen_key_auth(&mut self, slot: u8, auth: Option<&Auth>) -> Result<[u8; 64], Error>;
    /// Public key X||Y of the private key in `slot`.
    fn public_key(&mut self, slot: u8) -> Result<[u8; 64], Error>;
    /// ECDSA P-256 signature r||s over the 32-byte digest, made inside the chip.
    fn sign_auth(&mut self, slot: u8, digest: &[u8; 32], auth: Option<&Auth>) -> Result<[u8; 64], Error>;
    /// Runs only the PIN authorisation. `Err(Status(1))` = wrong PIN.
    fn check_pin(&mut self, auth: &Auth) -> Result<(), Error>;
    fn counter(&mut self, id: u8) -> Result<u32, Error>;
    fn counter_inc(&mut self, id: u8) -> Result<u32, Error>;

    fn gen_key(&mut self, slot: u8) -> Result<[u8; 64], Error> {
        self.gen_key_auth(slot, None)
    }
    fn sign(&mut self, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
        self.sign_auth(slot, digest, None)
    }
}

pub struct Atecc<B: Bus> {
    bus: B,
    awake: bool,
    sn: Option<auth::Serial>,
}

const WAKE_OK: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

impl<B: Bus> Atecc<B> {
    pub fn new(bus: B) -> Self {
        Self { bus, awake: false, sn: None }
    }

    pub fn into_bus(self) -> B {
        self.bus
    }

    fn wake(&mut self) -> Result<(), Error> {
        for _ in 0..3 {
            self.bus.wake_pulse();
            let mut r = [0u8; 4];
            if self.bus.read(&mut r).is_ok() && r == WAKE_OK {
                self.awake = true;
                return Ok(());
            }
        }
        self.awake = false;
        Err(Error::Bus)
    }

    fn idle(&mut self) {
        // Keeps TempKey, lets the chip save power; a failure only means it is already asleep.
        let _ = self.bus.write(&[proto::WORD_IDLE]);
        self.awake = false;
    }

    /// One command inside an already awake session. Returns the payload length in `out`.
    fn command(
        &mut self,
        opcode: u8,
        p1: u8,
        p2: u16,
        data: &[u8],
        out: &mut [u8; proto::MAX_RESP],
    ) -> Result<usize, Error> {
        let mut frame = [0u8; proto::MAX_CMD];
        let n = proto::build_command(&mut frame, opcode, p1, p2, data)?;
        self.bus.write(&frame[..n]).map_err(|_| Error::Bus)?;
        self.bus.delay_ms(proto::typ_exec_ms(opcode));
        let mut waited = proto::typ_exec_ms(opcode);
        let max = proto::max_exec_ms(opcode) * 2;
        // First byte = count. A busy chip NACKs.
        let mut first = [0u8; 1];
        loop {
            if self.bus.read(&mut first).is_ok() {
                break;
            }
            if waited >= max {
                return Err(Error::Bus);
            }
            self.bus.delay_ms(2);
            waited += 2;
        }
        let count = first[0] as usize;
        if !(4..=proto::MAX_RESP).contains(&count) {
            return Err(Error::Crc);
        }
        out[0] = first[0];
        if count > 1 {
            self.bus.read(&mut out[1..count]).map_err(|_| Error::Bus)?;
        }
        let payload = proto::parse_response(&out[..count])?;
        let len = payload.len();
        // Move the payload to the front for the caller.
        out.copy_within(1..1 + len, 0);
        Ok(len)
    }

    /// Wake, run `f`, idle. Retries once from the wake-up if the chip reports a communication
    /// problem (0xFF) or an about-to-expire watchdog (0xEE).
    fn session<R>(&mut self, mut f: impl FnMut(&mut Self) -> Result<R, Error>) -> Result<R, Error> {
        let mut last = Error::Bus;
        for _ in 0..2 {
            if let Err(e) = self.wake() {
                last = e;
                continue;
            }
            let r = f(self);
            self.idle();
            match r {
                Ok(v) => return Ok(v),
                Err(Error::Status(0xFF)) | Err(Error::Status(0xEE)) | Err(Error::Crc) | Err(Error::Bus) => {
                    last = r.err().unwrap_or(Error::Bus);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    fn check_slot(slot: u8) -> Result<(), Error> {
        if slot < 16 { Ok(()) } else { Err(Error::Param) }
    }

    /// Inside a session: serial number from config-zone block 0 (bytes 0-3 and 8-12).
    fn serial_in_session(&mut self) -> Result<auth::Serial, Error> {
        if let Some(s) = self.sn {
            return Ok(s);
        }
        let mut r = [0u8; proto::MAX_RESP];
        let n = self.command(proto::OP_READ, proto::READ_CONFIG_32, 0, &[], &mut r)?;
        if n != 32 {
            return Err(Error::Param);
        }
        let mut s = [0u8; 9];
        s[..4].copy_from_slice(&r[..4]);
        s[4..].copy_from_slice(&r[8..13]);
        self.sn = Some(s);
        Ok(s)
    }

    /// Inside a session: Nonce (random) + CheckMac with the PIN key. Leaves the chip authorised for
    /// the slots whose AuthKey is `a.slot`, until it goes to sleep.
    fn authorize(&mut self, a: &Auth) -> Result<(), Error> {
        let sn = self.serial_in_session()?;
        let mut r = [0u8; proto::MAX_RESP];
        let num_in = [0u8; 20];
        let n = self.command(proto::OP_NONCE, proto::NONCE_RANDOM, 0, &num_in, &mut r)?;
        if n != 32 {
            return Err(Error::Param);
        }
        let mut rand = [0u8; 32];
        rand.copy_from_slice(&r[..32]);
        let tk = auth::nonce_tempkey(&rand, &num_in);
        let resp = auth::check_mac_response(&a.key, &tk, &[0u8; 13], &sn);
        // CheckMac data: 32 bytes ignored in this mode, 32-byte response, 13 bytes OtherData.
        let mut d = [0u8; 77];
        d[32..64].copy_from_slice(&resp);
        let n = self.command(proto::OP_CHECKMAC, proto::CHECKMAC_MODE_TEMPKEY, a.slot as u16, &d, &mut r)?;
        if n != 0 {
            return Err(Error::Param);
        }
        Ok(())
    }
}

fn fixed<const N: usize>(payload: &[u8]) -> Result<[u8; N], Error> {
    if payload.len() != N {
        return Err(Error::Param);
    }
    let mut a = [0u8; N];
    a.copy_from_slice(payload);
    Ok(a)
}

impl<B: Bus> ChipOps for Atecc<B> {
    fn random(&mut self) -> Result<[u8; 32], Error> {
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_RANDOM, proto::RANDOM_MODE, 0, &[], &mut r)?;
            fixed::<32>(&r[..n])
        })
    }

    fn serial(&mut self) -> Result<auth::Serial, Error> {
        self.session(|c| c.serial_in_session())
    }

    fn gen_key_auth(&mut self, slot: u8, auth: Option<&Auth>) -> Result<[u8; 64], Error> {
        Self::check_slot(slot)?;
        self.session(|c| {
            if let Some(a) = auth {
                c.authorize(a)?;
            }
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_GENKEY, proto::GENKEY_CREATE, slot as u16, &[], &mut r)?;
            fixed::<64>(&r[..n])
        })
    }

    fn public_key(&mut self, slot: u8) -> Result<[u8; 64], Error> {
        Self::check_slot(slot)?;
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_GENKEY, proto::GENKEY_PUBLIC, slot as u16, &[], &mut r)?;
            fixed::<64>(&r[..n])
        })
    }

    fn sign_auth(&mut self, slot: u8, digest: &[u8; 32], auth: Option<&Auth>) -> Result<[u8; 64], Error> {
        Self::check_slot(slot)?;
        self.session(|c| {
            if let Some(a) = auth {
                c.authorize(a)?;
            }
            let mut r = [0u8; proto::MAX_RESP];
            // Digest -> TempKey (pass-through), then external sign with the slot key.
            let n = c.command(proto::OP_NONCE, proto::NONCE_PASSTHROUGH, 0, digest, &mut r)?;
            if n != 0 {
                return Err(Error::Param);
            }
            let n = c.command(proto::OP_SIGN, proto::SIGN_EXTERNAL, slot as u16, &[], &mut r)?;
            fixed::<64>(&r[..n])
        })
    }

    fn check_pin(&mut self, auth: &Auth) -> Result<(), Error> {
        self.session(|c| c.authorize(auth))
    }

    fn counter(&mut self, id: u8) -> Result<u32, Error> {
        if id > 1 {
            return Err(Error::Param);
        }
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_COUNTER, proto::COUNTER_READ, id as u16, &[], &mut r)?;
            proto::counter_value(&r[..n])
        })
    }

    fn counter_inc(&mut self, id: u8) -> Result<u32, Error> {
        if id > 1 {
            return Err(Error::Param);
        }
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_COUNTER, proto::COUNTER_INC, id as u16, &[], &mut r)?;
            proto::counter_value(&r[..n])
        })
    }
}
