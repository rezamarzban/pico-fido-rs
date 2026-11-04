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

pub const OP_CHECKMAC: u8 = 0x28;
pub const OP_COUNTER: u8 = 0x24;
pub const OP_GENKEY: u8 = 0x40;
pub const OP_INFO: u8 = 0x30;
pub const OP_LOCK: u8 = 0x17;
pub const OP_NONCE: u8 = 0x16;
pub const OP_RANDOM: u8 = 0x1B;
pub const OP_READ: u8 = 0x02;
pub const OP_SELFTEST: u8 = 0x77;
pub const OP_SIGN: u8 = 0x41;

/// Largest command frame we build: CheckMac (77 bytes data) = 1+1+1+1+2+77+2 = 85.
pub const MAX_CMD: usize = 96;
/// Largest response we accept: GenKey/Sign = 1 + 64 + 2 = 67.
pub const MAX_RESP: usize = 67;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// I2C transfer failed (NACK, bus error) or the chip never became ready.
    Bus,
    /// Response CRC wrong or malformed length.
    Crc,
    /// Chip status byte (0x03 parse, 0x05 ECC fault, 0x07 self-test, 0x08 health, 0x0F exec, 0xEE
    /// watchdog, 0xFF comm). 0x01 = miscompare.
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

/// Slot bit-fields used by this firmware. See atecc608a/CONFIG.md for the chip configuration.
pub const GENKEY_CREATE: u8 = 0x04; // create a new random private key in the slot, return pub key
pub const GENKEY_PUBLIC: u8 = 0x00; // compute the public key of the slot's private key
pub const NONCE_RANDOM: u8 = 0x00; // NumIn (20 bytes) + chip RNG -> TempKey; returns the chip random
pub const NONCE_PASSTHROUGH: u8 = 0x03; // load 32 bytes into TempKey unchanged
pub const SIGN_EXTERNAL: u8 = 0x80; // sign the message digest held in TempKey
pub const READ_CONFIG_32: u8 = 0x80; // config zone, 32-byte block
pub const CHECKMAC_MODE_TEMPKEY: u8 = 0x01; // block 1 = slot key, block 2 = TempKey (random nonce)
pub const COUNTER_READ: u8 = 0x00;
pub const COUNTER_INC: u8 = 0x01;
pub const RANDOM_MODE: u8 = 0x00; // update the EEPROM seed (normal use)

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
        OP_CHECKMAC => 40,
        OP_COUNTER => 25,
        OP_GENKEY => 115,
        OP_INFO => 5,
        OP_NONCE => 29,
        OP_RANDOM => 23,
        OP_READ => 5,
        OP_SELFTEST => 625,
        OP_SIGN => 70,
        _ => 200,
    }
}

/// Typical execution time (ms): sleep this long before the first poll.
pub fn typ_exec_ms(opcode: u8) -> u32 {
    match opcode {
        OP_CHECKMAC => 5,
        OP_COUNTER => 20,
        OP_GENKEY => 59,
        OP_NONCE => 7,
        OP_RANDOM => 15,
        OP_SIGN => 50,
        _ => 2,
    }
}
