//! ATECC608A command layer. `Bus` is the only hardware dependency (I2C + delay), so everything
//! here runs unchanged against the fake chip in host-test/se.

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

/// Operations the rest of the firmware needs. Object safe, so `se::ecdsa` can reach the chip
/// through one global without being generic over the bus.
pub trait ChipOps {
    /// 32 random bytes from the chip's NIST SP 800-90A DRBG / TRNG.
    fn random(&mut self) -> Result<[u8; 32], Error>;
    /// Creates a new random P-256 private key inside `slot` (the old key is gone) and returns the
    /// public key X||Y.
    fn gen_key(&mut self, slot: u8) -> Result<[u8; 64], Error>;
    /// Public key X||Y of the private key in `slot`.
    fn public_key(&mut self, slot: u8) -> Result<[u8; 64], Error>;
    /// ECDSA P-256 signature r||s over the 32-byte digest, made inside the chip.
    fn sign(&mut self, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], Error>;
    /// Reads 32-byte block `block` of data slot `slot` in the clear (a slot configured as a
    /// clear-readable data slot: atecc608a/CONFIG.md, slot 13).
    fn read_block(&mut self, slot: u8, block: u8) -> Result<[u8; 32], Error>;
    /// Writes 32 bytes into block `block` of data slot `slot` in the clear.
    fn write_block(&mut self, slot: u8, block: u8, data: &[u8; 32]) -> Result<(), Error>;
    fn counter(&mut self, id: u8) -> Result<u32, Error>;
    fn counter_inc(&mut self, id: u8) -> Result<u32, Error>;
    /// Serial number, revision, I2C address and lock state (Info + two config-zone reads).
    fn info(&mut self) -> Result<proto::ChipInfo, Error>;
}

pub struct Atecc<B: Bus> {
    bus: B,
}

const WAKE_OK: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

impl<B: Bus> Atecc<B> {
    pub fn new(bus: B) -> Self {
        Self { bus }
    }

    pub fn into_bus(self) -> B {
        self.bus
    }

    fn wake(&mut self) -> Result<(), Error> {
        for _ in 0..3 {
            self.bus.wake_pulse();
            let mut r = [0u8; 4];
            if self.bus.read(&mut r).is_ok() && r == WAKE_OK {
                return Ok(());
            }
        }
        Err(Error::Bus)
    }

    fn idle(&mut self) {
        // Lets the chip save power; a failure only means it is already asleep.
        let _ = self.bus.write(&[proto::WORD_IDLE]);
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

    fn gen_key(&mut self, slot: u8) -> Result<[u8; 64], Error> {
        Self::check_slot(slot)?;
        self.session(|c| {
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

    fn sign(&mut self, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
        Self::check_slot(slot)?;
        self.session(|c| {
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

    fn read_block(&mut self, slot: u8, block: u8) -> Result<[u8; 32], Error> {
        Self::check_slot(slot)?;
        if block > 12 {
            return Err(Error::Param);
        }
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_READ, proto::ZONE_DATA_32, proto::data_block_addr(slot, block), &[], &mut r)?;
            fixed::<32>(&r[..n])
        })
    }

    fn write_block(&mut self, slot: u8, block: u8, data: &[u8; 32]) -> Result<(), Error> {
        Self::check_slot(slot)?;
        if block > 12 {
            return Err(Error::Param);
        }
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_WRITE, proto::ZONE_DATA_32, proto::data_block_addr(slot, block), data, &mut r)?;
            if n != 0 {
                return Err(Error::Param);
            }
            Ok(())
        })
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

    fn info(&mut self) -> Result<proto::ChipInfo, Error> {
        self.session(|c| {
            let mut r = [0u8; proto::MAX_RESP];
            let n = c.command(proto::OP_INFO, proto::INFO_REVISION, 0, &[], &mut r)?;
            let revision: [u8; 4] = fixed(&r[..n])?;
            let n = c.command(proto::OP_READ, proto::READ_CONFIG_32, proto::config_block_addr(0), &[], &mut r)?;
            let block0: [u8; 32] = fixed(&r[..n])?;
            let n = c.command(proto::OP_READ, proto::READ_CONFIG_32, proto::config_block_addr(2), &[], &mut r)?;
            let block2: [u8; 32] = fixed(&r[..n])?;
            proto::parse_info(&revision, &block0, &block2)
        })
    }
}
