//! Minimal async driver for the Microchip ATECC608A/B over I2C.
//!
//! Only what this authenticator needs: wake/sleep, Info, Random, GenKey, Sign (external digest),
//! config-zone read/write and the two Lock commands. Every command wakes the chip first and puts
//! it to sleep afterwards, so there is no idle-watchdog state to track.
use embassy_time::Timer;
use embedded_hal_async::i2c::I2c;

/// The concrete bus type used on the board.
pub type Bus = embassy_rp::i2c::I2c<'static, embassy_rp::peripherals::I2C0, embassy_rp::i2c::Async>;

/// 7-bit I2C address (0xC0 in the chip's 8-bit notation). TNG parts use a different one.
pub const ADDR: u8 = 0x60;
/// Not-reserved address whose address byte (0x80) holds SDA low for ~7 bit times; used as wake pulse
/// because embassy-rp refuses to address the reserved address 0x00.
const WAKE_ADDR: u8 = 0x40;

const OP_LOCK: u8 = 0x17;
const OP_NONCE: u8 = 0x16;
const OP_RANDOM: u8 = 0x1B;
const OP_READ: u8 = 0x02;
const OP_WRITE: u8 = 0x12;
const OP_GENKEY: u8 = 0x40;
const OP_SIGN: u8 = 0x41;
const OP_INFO: u8 = 0x30;

#[derive(Debug, Clone, Copy, PartialEq, defmt::Format)]
pub enum Error {
    I2c,
    Wake,
    Crc,
    Timeout,
    Size,
    /// Status byte returned by the chip (0x0F = execution error, 0x03 = parse error, ...).
    Status(u8),
}

/// CRC-16 (poly 0x8005, bits fed LSB first). Returns bytes in wire order (low byte first).
pub fn crc16(data: &[u8]) -> [u8; 2] {
    let mut crc: u16 = 0;
    for &b in data {
        for bit in 0..8 {
            let d = (b >> bit) & 1;
            let c = ((crc >> 15) & 1) as u8;
            crc <<= 1;
            if d != c {
                crc ^= 0x8005;
            }
        }
    }
    crc.to_le_bytes()
}

pub struct Atecc<I> {
    i2c: I,
}

impl<I: I2c> Atecc<I> {
    pub fn new(i2c: I) -> Self {
        Atecc { i2c }
    }

    async fn wake(&mut self) -> Result<(), Error> {
        for _ in 0..3 {
            // The chip never ACKs this; the error is expected and ignored.
            let _ = self.i2c.write(WAKE_ADDR, &[0x00]).await;
            Timer::after_micros(2500).await;
            let mut r = [0u8; 4];
            if self.i2c.read(ADDR, &mut r).await.is_ok() && r[0] == 0x04 && r[1] == 0x11 {
                return Ok(());
            }
            Timer::after_millis(2).await;
        }
        Err(Error::Wake)
    }

    async fn sleep(&mut self) {
        let _ = self.i2c.write(ADDR, &[0x01]).await;
    }

    /// Send one command and read its response payload into `out` (empty `out` = status-only reply).
    async fn exec(
        &mut self,
        op: u8,
        p1: u8,
        p2: u16,
        data: &[u8],
        out: &mut [u8],
        max_ms: u32,
    ) -> Result<(), Error> {
        if data.len() > 32 || out.len() > 64 {
            return Err(Error::Size);
        }
        let count = 7 + data.len();
        let mut pkt = [0u8; 40];
        pkt[0] = 0x03; // word address: command
        pkt[1] = count as u8;
        pkt[2] = op;
        pkt[3] = p1;
        pkt[4..6].copy_from_slice(&p2.to_le_bytes());
        pkt[6..6 + data.len()].copy_from_slice(data);
        let crc = crc16(&pkt[1..count - 1]);
        pkt[count - 1..count + 1].copy_from_slice(&crc);

        self.wake().await?;
        let r = self.run(&pkt[..count + 1], out, max_ms).await;
        self.sleep().await;
        r
    }

    async fn run(&mut self, pkt: &[u8], out: &mut [u8], max_ms: u32) -> Result<(), Error> {
        let exp = if out.is_empty() { 4 } else { out.len() + 3 };
        let mut buf = [0u8; 72];
        self.i2c.write(ADDR, pkt).await.map_err(|_| Error::I2c)?;
        let mut waited = 0;
        loop {
            Timer::after_millis(2).await;
            waited += 2;
            // The chip NACKs its address while it is busy executing.
            if self.i2c.read(ADDR, &mut buf[..exp]).await.is_ok() {
                break;
            }
            if waited >= max_ms {
                return Err(Error::Timeout);
            }
        }
        let n = buf[0] as usize;
        if n < 4 || n > exp {
            return Err(Error::Size);
        }
        if crc16(&buf[..n - 2])[..] != buf[n - 2..n] {
            return Err(Error::Crc);
        }
        if n == 4 {
            let s = buf[1];
            return if s == 0 && out.is_empty() { Ok(()) } else { Err(Error::Status(s)) };
        }
        if n != exp {
            return Err(Error::Size);
        }
        out.copy_from_slice(&buf[1..n - 2]);
        Ok(())
    }

    /// DevRev word. Cheap "is the chip there" check.
    pub async fn info(&mut self) -> Result<[u8; 4], Error> {
        let mut o = [0u8; 4];
        self.exec(OP_INFO, 0, 0, &[], &mut o, 20).await?;
        Ok(o)
    }

    /// Hardware RNG, any length.
    pub async fn random(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for chunk in out.chunks_mut(32) {
            let mut r = [0u8; 32];
            self.exec(OP_RANDOM, 0, 0, &[], &mut r, 60).await?;
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        Ok(())
    }

    /// Create a new P-256 private key in `slot` (old key is destroyed). Returns public key X||Y.
    pub async fn gen_key(&mut self, slot: u8) -> Result<[u8; 64], Error> {
        let mut o = [0u8; 64];
        self.exec(OP_GENKEY, 0x04, slot as u16, &[], &mut o, 150).await?;
        Ok(o)
    }

    /// ECDSA over an already-hashed 32-byte digest. Returns raw r||s.
    pub async fn sign_digest(&mut self, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
        // Load the digest into TempKey (pass-through), then sign it with an external-sign key.
        self.exec(OP_NONCE, 0x03, 0, digest, &mut [], 60).await?;
        let mut o = [0u8; 64];
        self.exec(OP_SIGN, 0x80, slot as u16, &[], &mut o, 150).await?;
        Ok(o)
    }

    pub async fn read_config(&mut self) -> Result<[u8; 128], Error> {
        let mut cfg = [0u8; 128];
        for block in 0..4u16 {
            let mut b = [0u8; 32];
            self.exec(OP_READ, 0x80, block << 3, &[], &mut b, 40).await?;
            cfg[block as usize * 32..][..32].copy_from_slice(&b);
        }
        Ok(cfg)
    }

    /// Write one 4-byte word of the config zone (only possible while the config zone is unlocked).
    pub async fn write_config_word(&mut self, byte_off: usize, w: [u8; 4]) -> Result<(), Error> {
        let addr = ((byte_off / 32) << 3 | (byte_off % 32) / 4) as u16;
        self.exec(OP_WRITE, 0x00, addr, &w, &mut [], 80).await
    }

    /// Irreversible. `crc` = CRC-16 of the whole 128-byte config zone.
    pub async fn lock_config(&mut self, crc: [u8; 2]) -> Result<(), Error> {
        self.exec(OP_LOCK, 0x00, u16::from_le_bytes(crc), &[], &mut [], 150).await
    }

    /// Irreversible. Locks the data zone without a CRC check.
    pub async fn lock_data(&mut self) -> Result<(), Error> {
        self.exec(OP_LOCK, 0x81, 0, &[], &mut [], 150).await
    }

    /// (config_locked, data_locked)
    pub async fn lock_state(&mut self) -> Result<(bool, bool), Error> {
        let cfg = self.read_config().await?;
        Ok((cfg[87] == 0x00, cfg[86] == 0x00))
    }
}

#[cfg(feature = "provision")]
pub mod provision {
    //! One-time, irreversible chip setup. Only compiled with `--features provision`.
    use super::*;
    use sha2::{Digest, Sha256};

    /// Number of ECC private-key slots used for credentials (slots 0..SLOTS).
    const SLOTS: usize = crate::keys::MAX_CREDS;
    // SlotConfig 0x2083: ExtSig + IntSig allowed, secret, GenKey allowed after lock.
    const SLOT_CFG: [u8; 2] = [0x83, 0x20];
    // KeyConfig 0x0033: private P-256 key, public key can be derived, lockable.
    const KEY_CFG: [u8; 2] = [0x33, 0x00];

    pub async fn run<I: I2c>(at: &mut Atecc<I>) {
        if let Err(e) = run_inner(at).await {
            defmt::error!("provisioning FAILED: {}", e);
        }
    }

    async fn run_inner<I: I2c>(at: &mut Atecc<I>) -> Result<(), Error> {
        let (cfg_locked, data_locked) = at.lock_state().await?;
        defmt::info!("provision: config locked={} data locked={}", cfg_locked, data_locked);

        if !cfg_locked {
            let cfg = at.read_config().await?;
            let mut want = cfg;
            for s in 0..SLOTS {
                want[20 + 2 * s..22 + 2 * s].copy_from_slice(&SLOT_CFG);
                want[96 + 2 * s..98 + 2 * s].copy_from_slice(&KEY_CFG);
            }
            let words = (20..52).step_by(4).chain((96..96 + 2 * SLOTS).step_by(4));
            for off in words {
                if cfg[off..off + 4] != want[off..off + 4] {
                    let w: [u8; 4] = want[off..off + 4].try_into().unwrap();
                    at.write_config_word(off, w).await?;
                }
            }
            let back = at.read_config().await?;
            if back[20..52] != want[20..52] || back[96..96 + 2 * SLOTS] != want[96..96 + 2 * SLOTS] {
                defmt::error!("provision: config read-back mismatch, NOT locking");
                return Err(Error::Crc);
            }
            at.lock_config(crc16(&back)).await?;
            defmt::info!("provision: config zone locked");
        }

        if !data_locked {
            at.lock_data().await?;
            defmt::info!("provision: data zone locked");
        }

        // Self-test: make a key, sign, verify in software.
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let pk = at.gen_key(0).await?;
        let msg = b"pico-fido-rs selftest";
        let digest: [u8; 32] = Sha256::digest(msg).into();
        let sig = at.sign_digest(0, &digest).await?;
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&pk);
        let ok = VerifyingKey::from_sec1_bytes(&sec1)
            .ok()
            .zip(Signature::from_slice(&sig).ok())
            .map(|(vk, s)| vk.verify(msg, &s).is_ok())
            .unwrap_or(false);
        if ok {
            defmt::info!("provision: ATECC selftest OK - chip is ready");
            Ok(())
        } else {
            defmt::error!("provision: selftest signature did not verify");
            Err(Error::Crc)
        }
    }
}
