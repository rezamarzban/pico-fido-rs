//! CTAPHID framing: reassembles 64-byte packets into messages and back. No I/O, no async.
use alloc::vec;
use alloc::vec::Vec;

use crate::ctap::MAX_MSG;

pub type Pkt = [u8; 64];

pub const PING: u8 = 0x01;
#[allow(dead_code)]
pub const MSG: u8 = 0x03;
pub const INIT: u8 = 0x06;
pub const WINK: u8 = 0x08;
pub const CBOR: u8 = 0x10;
pub const CANCEL: u8 = 0x11;
pub const KEEPALIVE: u8 = 0x3B;
pub const ERROR: u8 = 0x3F;

const BROADCAST: u32 = 0xFFFF_FFFF;
/// CBOR supported, no CTAP1/U2F (NMSG)
const CAPS: u8 = 0x04 | 0x08;

pub enum Rx {
    None,
    /// Send this reply immediately: (channel, command, payload).
    Reply(u32, u8, Vec<u8>),
    /// A complete CTAP2 request. Call `Hid::end()` when the answer has been sent.
    Cbor(u32, Vec<u8>),
    /// Host cancelled the running request.
    Cancel,
}

struct Asm {
    cid: u32,
    cmd: u8,
    len: usize,
    buf: Vec<u8>,
    seq: u8,
}

pub struct Hid {
    next_cid: u32,
    asm: Option<Asm>,
    active: Option<u32>,
}

fn err(cid: u32, code: u8) -> Rx {
    Rx::Reply(cid, ERROR, vec![code])
}

impl Hid {
    pub fn new() -> Self {
        Hid { next_cid: 0, asm: None, active: None }
    }

    pub fn end(&mut self) {
        self.active = None;
    }

    pub fn rx(&mut self, p: &Pkt) -> Rx {
        let cid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        if cid == 0 {
            return err(cid, 0x0B);
        }
        if p[4] & 0x80 != 0 {
            let cmd = p[4] & 0x7F;
            let len = ((p[5] as usize) << 8) | p[6] as usize;
            if cmd == INIT {
                return self.init(cid, len, p);
            }
            if cid == BROADCAST {
                return err(cid, 0x0B);
            }
            if let Some(a) = self.active {
                return if a == cid && cmd == CANCEL { Rx::Cancel } else if a == cid { Rx::None } else { err(cid, 0x06) };
            }
            if let Some(a) = &self.asm {
                if a.cid != cid {
                    return err(cid, 0x06);
                }
            }
            self.asm = None;
            if len > MAX_MSG {
                return err(cid, 0x03);
            }
            let n = len.min(57);
            let a = Asm { cid, cmd, len, buf: p[7..7 + n].to_vec(), seq: 0 };
            return self.progress(a);
        }
        // continuation packet
        if self.active.is_some() {
            return Rx::None;
        }
        match self.asm.take() {
            Some(mut a) if a.cid == cid => {
                if p[4] != a.seq {
                    return err(cid, 0x04);
                }
                a.seq += 1;
                let n = (a.len - a.buf.len()).min(59);
                a.buf.extend_from_slice(&p[5..5 + n]);
                self.progress(a)
            }
            Some(a) => {
                self.asm = Some(a);
                err(cid, 0x06)
            }
            None => Rx::None,
        }
    }

    fn progress(&mut self, a: Asm) -> Rx {
        if a.buf.len() < a.len {
            self.asm = Some(a);
            return Rx::None;
        }
        match a.cmd {
            CBOR => {
                self.active = Some(a.cid);
                Rx::Cbor(a.cid, a.buf)
            }
            PING | WINK => Rx::Reply(a.cid, a.cmd, a.buf),
            _ => err(a.cid, 0x01), // MSG (U2F) and anything unknown
        }
    }

    fn init(&mut self, cid: u32, len: usize, p: &Pkt) -> Rx {
        if len != 8 {
            return err(cid, 0x03);
        }
        if matches!(&self.asm, Some(a) if a.cid == cid) {
            self.asm = None;
        }
        let new = if cid == BROADCAST {
            self.next_cid += 1;
            self.next_cid
        } else {
            cid
        };
        let mut d = Vec::with_capacity(17);
        d.extend_from_slice(&p[7..15]);
        d.extend_from_slice(&new.to_be_bytes());
        d.extend_from_slice(&[2, 0, 0, 0, CAPS]);
        Rx::Reply(cid, INIT, d)
    }
}

/// Split a message into 64-byte packets.
pub fn frames(cid: u32, cmd: u8, data: &[u8]) -> Vec<Pkt> {
    let mut out = Vec::new();
    let mut p = [0u8; 64];
    p[..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = 0x80 | cmd;
    p[5] = (data.len() >> 8) as u8;
    p[6] = data.len() as u8;
    let n = data.len().min(57);
    p[7..7 + n].copy_from_slice(&data[..n]);
    out.push(p);
    let (mut off, mut seq) = (n, 0u8);
    while off < data.len() {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = seq;
        seq += 1;
        let n = (data.len() - off).min(59);
        p[5..5 + n].copy_from_slice(&data[off..off + n]);
        off += n;
        out.push(p);
    }
    out
}
