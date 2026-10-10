//! Tiny CBOR reader/writer: only what CTAP2 needs (definite lengths only).
use alloc::vec::Vec;

pub const UNEXPECTED_TYPE: u8 = 0x11;
pub const INVALID_CBOR: u8 = 0x12;

pub struct W(pub Vec<u8>);

impl W {
    pub fn new() -> Self {
        W(Vec::new())
    }
    fn head(&mut self, major: u8, v: u64) {
        let m = major << 5;
        if v < 24 {
            self.0.push(m | v as u8);
        } else if v <= 0xff {
            self.0.extend_from_slice(&[m | 24, v as u8]);
        } else if v <= 0xffff {
            self.0.push(m | 25);
            self.0.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xffff_ffff {
            self.0.push(m | 26);
            self.0.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.0.push(m | 27);
            self.0.extend_from_slice(&v.to_be_bytes());
        }
    }
    pub fn uint(&mut self, v: u64) {
        self.head(0, v)
    }
    pub fn int(&mut self, v: i64) {
        if v >= 0 {
            self.head(0, v as u64)
        } else {
            self.head(1, (-1 - v) as u64)
        }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.head(2, b.len() as u64);
        self.0.extend_from_slice(b);
    }
    pub fn text(&mut self, s: &str) {
        self.head(3, s.len() as u64);
        self.0.extend_from_slice(s.as_bytes());
    }
    pub fn arr(&mut self, n: u64) {
        self.head(4, n)
    }
    pub fn map(&mut self, n: u64) {
        self.head(5, n)
    }
    pub fn bool(&mut self, b: bool) {
        self.0.push(if b { 0xf5 } else { 0xf4 });
    }
}

pub struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        R { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], u8> {
        let end = self.p.checked_add(n).ok_or(INVALID_CBOR)?;
        let s = self.b.get(self.p..end).ok_or(INVALID_CBOR)?;
        self.p = end;
        Ok(s)
    }
    /// Reads one item head. Rejects indefinite lengths and non-minimal integer/length encodings
    /// (CTAP2 canonical CBOR). Major type 7 is returned as `(7, n)` with `n` = the additional
    /// information (20..=23 simple values, 25..=27 float16/32/64); a float's payload is consumed
    /// but kept as-is, because CTAP2 canonical CBOR does not re-encode floating-point values.
    fn head(&mut self) -> Result<(u8, u64), u8> {
        let b = self.take(1)?[0];
        let ai = b & 31;
        if b >> 5 == 7 {
            return match ai {
                20..=23 => Ok((7, ai as u64)),
                25 => {
                    self.take(2)?;
                    Ok((7, 25))
                }
                26 => {
                    self.take(4)?;
                    Ok((7, 26))
                }
                27 => {
                    self.take(8)?;
                    Ok((7, 27))
                }
                _ => Err(INVALID_CBOR), // unassigned simple values, break, reserved
            };
        }
        let (v, min) = match ai {
            0..=23 => (ai as u64, 0),
            24 => (self.take(1)?[0] as u64, 24),
            25 => (
                u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
                0x100,
            ),
            26 => (
                u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            _ => return Err(INVALID_CBOR),
        };
        if v < min {
            return Err(INVALID_CBOR);
        }
        Ok((b >> 5, v))
    }
    fn typed(&mut self, major: u8) -> Result<u64, u8> {
        match self.head()? {
            (m, v) if m == major => Ok(v),
            _ => Err(UNEXPECTED_TYPE),
        }
    }
    pub fn map(&mut self) -> Result<u64, u8> {
        self.typed(5)
    }
    pub fn array(&mut self) -> Result<u64, u8> {
        self.typed(4)
    }
    pub fn uint(&mut self) -> Result<u64, u8> {
        self.typed(0)
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], u8> {
        let n = usize::try_from(self.typed(2)?).map_err(|_| INVALID_CBOR)?;
        self.take(n)
    }
    pub fn text(&mut self) -> Result<&'a str, u8> {
        let n = usize::try_from(self.typed(3)?).map_err(|_| INVALID_CBOR)?;
        core::str::from_utf8(self.take(n)?).map_err(|_| INVALID_CBOR)
    }
    pub fn int(&mut self) -> Result<i64, u8> {
        match self.head()? {
            (0, v) if v <= i64::MAX as u64 => Ok(v as i64),
            (1, v) if v <= i64::MAX as u64 => Ok(-1 - v as i64),
            _ => Err(UNEXPECTED_TYPE),
        }
    }
    pub fn bool(&mut self) -> Result<bool, u8> {
        match self.head()? {
            (7, 20) => Ok(false),
            (7, 21) => Ok(true),
            _ => Err(UNEXPECTED_TYPE),
        }
    }
    pub fn skip(&mut self) -> Result<(), u8> {
        self.skip_depth(0)
    }
    fn skip_depth(&mut self, depth: u8) -> Result<(), u8> {
        if depth > MAX_DEPTH {
            return Err(INVALID_CBOR);
        }
        let (major, v) = self.head()?;
        match major {
            2 | 3 => {
                self.take(usize::try_from(v).map_err(|_| INVALID_CBOR)?)?;
            }
            4 => (0..v).try_for_each(|_| self.skip_depth(depth + 1))?,
            5 => (0..v).try_for_each(|_| {
                self.skip_depth(depth + 1)?;
                self.skip_depth(depth + 1)
            })?,
            6 => return Err(INVALID_CBOR), // tags are not allowed
            _ => {}
        }
        Ok(())
    }

    fn at_end(&self) -> bool {
        self.p == self.b.len()
    }
}

/// Maximum container nesting allowed in a CTAP2 request.
const MAX_DEPTH: u8 = 4;

/// Checks a whole CTAP2 request body once, centrally, before any command parses it:
/// exactly one top-level map, minimal integer/length encodings, no tags or indefinite lengths,
/// valid UTF-8 text, map keys that are integers or text strings in canonical order (shorter
/// encoding first, then bytewise; this also rules out duplicates), nesting <= 4, no trailing bytes.
/// Floats and simple values are accepted (they can only appear in fields the commands skip, since
/// the recognised fields are type-checked when parsed).
pub fn validate(body: &[u8]) -> Result<(), u8> {
    let mut r = R::new(body);
    if body.first().map(|b| b >> 5) != Some(5) {
        return Err(if body.is_empty() {
            INVALID_CBOR
        } else {
            UNEXPECTED_TYPE
        });
    }
    walk(&mut r, 0)?;
    if r.at_end() {
        Ok(())
    } else {
        Err(INVALID_CBOR)
    }
}

fn walk(r: &mut R, depth: u8) -> Result<(), u8> {
    let (major, v) = r.head()?;
    match major {
        0 | 1 => {}
        2 => {
            r.take(usize::try_from(v).map_err(|_| INVALID_CBOR)?)?;
        }
        3 => {
            let n = usize::try_from(v).map_err(|_| INVALID_CBOR)?;
            core::str::from_utf8(r.take(n)?).map_err(|_| INVALID_CBOR)?;
        }
        4 | 5 => {
            if depth >= MAX_DEPTH {
                return Err(INVALID_CBOR);
            }
            if major == 4 {
                for _ in 0..v {
                    walk(r, depth + 1)?;
                }
            } else {
                let buf = r.b;
                let mut prev: Option<&[u8]> = None;
                for _ in 0..v {
                    let start = r.p;
                    match buf.get(start).map(|b| b >> 5) {
                        Some(0 | 1 | 3) => {} // integer or text string
                        Some(_) => return Err(UNEXPECTED_TYPE),
                        None => return Err(INVALID_CBOR),
                    }
                    walk(r, depth + 1)?;
                    let key = &buf[start..r.p];
                    if let Some(p) = prev {
                        if !key_less(p, key) {
                            return Err(INVALID_CBOR); // duplicate or out of canonical order
                        }
                    }
                    prev = Some(key);
                    walk(r, depth + 1)?;
                }
            }
        }
        7 => {}
        _ => return Err(INVALID_CBOR), // tags (6)
    }
    Ok(())
}

/// CTAP2 canonical key order: a shorter encoded key sorts first, equal lengths compare bytewise.
fn key_less(a: &[u8], b: &[u8]) -> bool {
    a.len() < b.len() || (a.len() == b.len() && a < b)
}
