//! Continuous health tests on the raw ring-oscillator output (no hardware access, host-testable).
//!
//! Modelled on the two mandatory tests of NIST SP 800-90B section 4.4, run on raw bytes with the
//! conservative assumption of >= 1 bit of entropy per byte (alpha = 2^-20):
//! * Repetition Count Test: the same byte `RCT_CUTOFF` times in a row is a failure.
//! * Adaptive Proportion Test: in a window of `APT_WINDOW` bytes, the first byte of the window
//!   occurring `APT_CUTOFF` times or more is a failure.
//! Additionally, two identical consecutive 64-byte samples are a failure; this catches a source
//! frozen on a non-uniform pattern, which the two tests above cannot see.
//!
//! These are failure detectors only. They do not prove that the source has any particular
//! amount of entropy; see SECURITY.md.

pub const SAMPLE: usize = 64;
const RCT_CUTOFF: u32 = 21;
const APT_WINDOW: u32 = 512;
const APT_CUTOFF: u32 = 410;

pub struct Health {
    last: [u8; SAMPLE],
    have_last: bool,
    run_byte: u8,
    run_len: u32,
    apt_ref: u8,
    apt_seen: u32,
    apt_hits: u32,
}

impl Health {
    pub const fn new() -> Self {
        Health {
            last: [0; SAMPLE],
            have_last: false,
            run_byte: 0,
            run_len: 0,
            apt_ref: 0,
            apt_seen: 0,
            apt_hits: 0,
        }
    }

    /// Feeds one raw sample. Returns `false` if the source must be considered failed.
    pub fn feed(&mut self, s: &[u8; SAMPLE]) -> bool {
        if self.have_last && self.last == *s {
            return false;
        }
        self.last = *s;
        self.have_last = true;
        for &b in s {
            if self.run_len > 0 && b == self.run_byte {
                self.run_len += 1;
                if self.run_len >= RCT_CUTOFF {
                    return false;
                }
            } else {
                self.run_byte = b;
                self.run_len = 1;
            }
            if self.apt_seen == 0 {
                self.apt_ref = b;
                self.apt_seen = 1;
                self.apt_hits = 1;
            } else {
                self.apt_seen += 1;
                if b == self.apt_ref {
                    self.apt_hits += 1;
                    if self.apt_hits >= APT_CUTOFF {
                        return false;
                    }
                }
                if self.apt_seen == APT_WINDOW {
                    self.apt_seen = 0;
                }
            }
        }
        true
    }
}
