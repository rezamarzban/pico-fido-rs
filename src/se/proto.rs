//! ATECC608A wire protocol: CRC-16, command framing, response parsing. Pure `core` code (no I/O,
//! no allocation) so it is unit-tested on the host (host-test/se).
//!
//! Frame layout (I2C, word address 0x03 = "command"):
//!   command : [0x03][count][opcode][param1][param2 lo][param2 hi][data...][crc lo][crc hi]
//!   response: [count][data...][crc lo][crc hi]            (count includes itself and the CRC)
//! CRC covers `count .. last data byte`, polynomial 0x8005, bits processed LSB first, sent LSB first.

pub const ADDR_7BIT: u8 = 0x60; // default 8-bit address 0xC0
pub const WORD_RESET: u8 = 0x00;
pub const WORD_SLEEP: u8 = 0x01;
pub const WORD_IDLE: u8 = 0x02;
pub const WORD_COMMAND: u8 = 0x03;

pub const OP_COUNTER: u8 = 0x24;
pub const OP_INFO: u8 = 0x30;
pub const OP_READ: u8 = 0x02;
pub const OP_WRITE: u8 = 0x12;
pub const OP_GENKEY: u8 = 0x40;
pub const OP_NONCE: u8 = 0x16;
pub const OP_RANDOM: u8 = 0x1B;
pub const OP_SIGN: u8 = 0x41;

/// Largest command frame we build: Nonce pass-through (32 bytes data) = 1+1+1+1+2+32+2 = 40.
pub const MAX_CMD: usize = 48;
/// Largest response we accept: GenKey/Sign = 1 + 64 + 2 = 67.
pub const MAX_RESP: usize = 67;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// I2C transfer failed (NACK, bus error) or the chip never became ready.
    Bus,
    /// Response CRC wrong or malformed length.
    Crc,
    /// Chip status byte (0x03 parse, 0x05 ECC fault, 0x07 self-test, 0x08 health, 0x0F exec, 0xEE
    /// watchdog, 0xFF comm).
    Status(u8),
    /// Slot / argument out of range, or the response had an unexpected size.
    Param,
}

/// CRC-16 as used by the CryptoAuthentication family (same as cryptoauthlib `atCRC`).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        for shift in 0..8 {
            let data_bit = (b >> shift) & 1;
            let crc_bit = ((crc >> 15) & 1) as u8;
            crc <<= 1;
            if data_bit != crc_bit {
                crc ^= 0x8005;
            }
        }
    }
    crc
}

/// Builds a command frame (including the word address byte). Returns the frame length.
pub fn build_command(
    out: &mut [u8; MAX_CMD],
    opcode: u8,
    p1: u8,
    p2: u16,
    data: &[u8],
) -> Result<usize, Error> {
    let count = 7 + data.len(); // count + opcode + p1 + p2(2) + data + crc(2)
    if 1 + count > MAX_CMD {
        return Err(Error::Param);
    }
    out[0] = WORD_COMMAND;
    out[1] = count as u8;
    out[2] = opcode;
    out[3] = p1;
    out[4..6].copy_from_slice(&p2.to_le_bytes());
    out[6..6 + data.len()].copy_from_slice(data);
    let crc = crc16(&out[1..6 + data.len()]).to_le_bytes();
    out[6 + data.len()] = crc[0];
    out[7 + data.len()] = crc[1];
    Ok(1 + count)
}

/// Validates a complete response frame and returns its payload (without count and CRC).
/// A 4-byte frame is a status frame: status 0x00 is success (empty payload), anything else an error.
pub fn parse_response(frame: &[u8]) -> Result<&[u8], Error> {
    if frame.len() < 4 || frame[0] as usize != frame.len() {
        return Err(Error::Crc);
    }
    let n = frame.len();
    let crc = crc16(&frame[..n - 2]).to_le_bytes();
    if frame[n - 2] != crc[0] || frame[n - 1] != crc[1] {
        return Err(Error::Crc);
    }
    if n == 4 {
        return match frame[1] {
            0x00 => Ok(&frame[1..1]),
            s => Err(Error::Status(s)),
        };
    }
    Ok(&frame[1..n - 2])
}

/// Command parameters used by this firmware. See atecc608a/CONFIG.md for the chip configuration.
pub const GENKEY_CREATE: u8 = 0x04; // create a new random private key in the slot, return pub key
pub const GENKEY_PUBLIC: u8 = 0x00; // compute the public key of the slot's private key
pub const NONCE_PASSTHROUGH: u8 = 0x03; // load 32 bytes into TempKey unchanged
pub const SIGN_EXTERNAL: u8 = 0x80; // sign the message digest held in TempKey
pub const COUNTER_READ: u8 = 0x00;
pub const COUNTER_INC: u8 = 0x01;
pub const RANDOM_MODE: u8 = 0x00; // update the EEPROM seed (normal use)
pub const INFO_REVISION: u8 = 0x00; // 4 bytes: device revision (00 00 60 xx for the ATECC608)
pub const READ_CONFIG_32: u8 = 0x80; // config zone, 32-byte block (bit 7 = 32 bytes, zone bits = 0)
pub const ZONE_DATA_32: u8 = 0x82; // data zone, 32-byte block, in the clear (bit 7 = 32 bytes, zone 2 = data)
/// Word address of 32-byte block `block` of data slot `slot`: block << 8 | slot << 3.
pub const fn data_block_addr(slot: u8, block: u8) -> u16 {
    ((block as u16) << 8) | ((slot as u16) << 3)
}
/// Read word address of config block `b` (32 bytes): block << 3.
pub const fn config_block_addr(b: u8) -> u16 {
    (b as u16) << 3
}

/// What the display shows about the chip itself (read once at start-up).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChipInfo {
    /// 9-byte serial number (starts 01 23, ends EE).
    pub serial: [u8; 9],
    /// Info(revision): 4 bytes, `00 00 60 03` for an ATECC608A/B.
    pub revision: [u8; 4],
    /// The chip's own I2C address (7 bit) as set in the configuration.
    pub i2c_addr: u8,
    /// LockConfig (config byte 87) is 0x00: the configuration is frozen.
    pub config_locked: bool,
    /// LockValue (config byte 86) is 0x00: the data zone is locked.
    pub data_locked: bool,
}

/// Builds `ChipInfo` from the Info(revision) answer and config blocks 0 (bytes 0..32) and
/// 2 (bytes 64..96). Lock bytes: 0x55 = unlocked, anything else (0x00) = locked.
pub fn parse_info(revision: &[u8], block0: &[u8], block2: &[u8]) -> Result<ChipInfo, Error> {
    if revision.len() != 4 || block0.len() != 32 || block2.len() != 32 {
        return Err(Error::Param);
    }
    let mut serial = [0u8; 9];
    serial[..4].copy_from_slice(&block0[..4]); // SN0..SN3
    serial[4..].copy_from_slice(&block0[8..13]); // SN4..SN8
    let mut rev = [0u8; 4];
    rev.copy_from_slice(revision);
    Ok(ChipInfo {
        serial,
        revision: rev,
        i2c_addr: block0[16] >> 1,
        data_locked: block2[86 - 64] != 0x55,
        config_locked: block2[87 - 64] != 0x55,
    })
}

/// Counter response: 4 bytes little-endian.
pub fn counter_value(payload: &[u8]) -> Result<u32, Error> {
    if payload.len() != 4 {
        return Err(Error::Param);
    }
    Ok(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]))
}

/// Worst-case execution time (ms) of a command on the ATECC608A at 2.5-5 V (datasheet table),
/// rounded up. Used as the poll timeout; the chip is polled earlier.
pub fn max_exec_ms(opcode: u8) -> u32 {
    match opcode {
        OP_COUNTER => 25,
        OP_INFO => 10,
        OP_READ => 10,
        OP_WRITE => 26,
        OP_GENKEY => 115,
        OP_NONCE => 29,
        OP_RANDOM => 23,
        OP_SIGN => 70,
        _ => 200,
    }
}

/// Typical execution time (ms): sleep this long before the first poll.
pub fn typ_exec_ms(opcode: u8) -> u32 {
    match opcode {
        OP_COUNTER => 20,
        OP_INFO => 1,
        OP_READ => 1,
        OP_WRITE => 7,
        OP_GENKEY => 59,
        OP_NONCE => 7,
        OP_RANDOM => 15,
        OP_SIGN => 50,
        _ => 2,
    }
}
