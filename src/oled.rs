//! Device status on an SSD1306 128x64 OLED (I2C0, SDA = GP16, SCL = GP17, address 0x3C), a
//! port of the MicroPython `ssd1306.py` driver (same init sequence) with a built-in 5x7 font.
//!
//! * Feature `oled` (on by default; `build.sh` adds it too, `-O` leaves it out). No display connected: the init write is not acknowledged,
//!   the display stays off and is probed again every 5 s. Nothing else depends on it.
//! * Everything runs on the MAIN thread from `wdog::poll_wait` (the idle / user-presence waits):
//!   no extra task, and the interrupt executor (USB, RAM-guard refresh) is never blocked by I2C.
//!   A frame is rendered every `FRAME_MS`, then pushed one 128-byte page per call (~12 ms each at
//!   100 kHz, ~3 ms at 400 kHz), so one call delays the main thread by at most one page.
//! * While a command is being processed (signature, PIN derivation) the display keeps the last
//!   frame; the BUSY state shows up in the next one.
//!
//! Layout (21 characters per line, upper case only):
//! ```text
//! FIDO OPEN USB OK            state (LOCK / OPEN / BUSY / FAULT), USB (-- / OK / SLP)
//! PIN SET PUF OK S1           PIN set or not, SRAM PUF state and helper slot
//! CPU 12% UP 1:23:45          CPU load estimate, uptime
//! RAM 153K/264K HP 12K        RAM in use (static + stack + PUF bytes), heap in use
//! STK 1.2K PK 5.0K            stack now, peak (peak needs --features stack_probe)
//! GRD 1990/S P500US           RAM-guard full refreshes per second, current period
//! CS61US LT480US P1234        longest refresh critical section, latest tick, packets handled
//! FW214K ST12/70K W3%         firmware size, key-value store use, erase budget used
//! ```
use core::cell::UnsafeCell;
use core::fmt::Write as _;

use defmt::info;
use embassy_rp::i2c::{Blocking, Config, I2c};
use embassy_rp::peripherals::{I2C0, PIN_16, PIN_17};
use embassy_time::Instant;
use heapless::String;
use portable_atomic::Ordering;

use crate::status as st;

const ADDR: u8 = 0x3C;
const W: usize = 128;
const PAGES: usize = 8;
const COLS: usize = 21;
const FRAME_MS: u32 = 500;
const RETRY_MS: u32 = 5_000;
/// The first retry after a failed start-up probe comes this early (modules need up to ~100 ms
/// after power-up before they acknowledge anything).
const FIRST_RETRY_MS: u32 = 500;
/// I2C clock. Most bare modules rely on the RP2040's internal pull-ups (about 50 kOhm) which
/// cannot meet the 400 kHz rise time; 100 kHz works with them. With 4.7 kOhm external pull-ups
/// 400_000 is fine (a page push then takes ~3 ms instead of ~12 ms).
const I2C_HZ: u32 = 100_000;
/// Wait before the first probe: the module is powered together with the Pico.
const POWER_UP_MS: u64 = 100;
const RAM_TOTAL: usize = 264 * 1024;
const FLASH_BASE: usize = 0x1000_0000;

unsafe extern "C" {
    static __sdata: u32;
    static __edata: u32;
    static __sidata: u32;
    static __ebss: u32;
    static _stack_start: u32;
}

/// 5x7 font, ASCII 32..=95 (space to underscore), one byte per column, bit 0 = top row.
#[rustfmt::skip]
const FONT: [[u8; 5]; 64] = [
    [0x00,0x00,0x00,0x00,0x00],[0x00,0x00,0x5F,0x00,0x00],[0x00,0x07,0x00,0x07,0x00],[0x14,0x7F,0x14,0x7F,0x14],
    [0x24,0x2A,0x7F,0x2A,0x12],[0x23,0x13,0x08,0x64,0x62],[0x36,0x49,0x55,0x22,0x50],[0x00,0x05,0x03,0x00,0x00],
    [0x00,0x1C,0x22,0x41,0x00],[0x00,0x41,0x22,0x1C,0x00],[0x14,0x08,0x3E,0x08,0x14],[0x08,0x08,0x3E,0x08,0x08],
    [0x00,0x50,0x30,0x00,0x00],[0x08,0x08,0x08,0x08,0x08],[0x00,0x60,0x60,0x00,0x00],[0x20,0x10,0x08,0x04,0x02],
    [0x3E,0x51,0x49,0x45,0x3E],[0x00,0x42,0x7F,0x40,0x00],[0x42,0x61,0x51,0x49,0x46],[0x21,0x41,0x45,0x4B,0x31],
    [0x18,0x14,0x12,0x7F,0x10],[0x27,0x45,0x45,0x45,0x39],[0x3C,0x4A,0x49,0x49,0x30],[0x01,0x71,0x09,0x05,0x03],
    [0x36,0x49,0x49,0x49,0x36],[0x06,0x49,0x49,0x29,0x1E],[0x00,0x36,0x36,0x00,0x00],[0x00,0x56,0x36,0x00,0x00],
    [0x08,0x14,0x22,0x41,0x00],[0x14,0x14,0x14,0x14,0x14],[0x00,0x41,0x22,0x14,0x08],[0x02,0x01,0x51,0x09,0x06],
    [0x32,0x49,0x79,0x41,0x3E],[0x7E,0x11,0x11,0x11,0x7E],[0x7F,0x49,0x49,0x49,0x36],[0x3E,0x41,0x41,0x41,0x22],
    [0x7F,0x41,0x41,0x22,0x1C],[0x7F,0x49,0x49,0x49,0x41],[0x7F,0x09,0x09,0x09,0x01],[0x3E,0x41,0x49,0x49,0x7A],
    [0x7F,0x08,0x08,0x08,0x7F],[0x00,0x41,0x7F,0x41,0x00],[0x20,0x40,0x41,0x3F,0x01],[0x7F,0x08,0x14,0x22,0x41],
    [0x7F,0x40,0x40,0x40,0x40],[0x7F,0x02,0x0C,0x02,0x7F],[0x7F,0x04,0x08,0x10,0x7F],[0x3E,0x41,0x41,0x41,0x3E],
    [0x7F,0x09,0x09,0x09,0x06],[0x3E,0x41,0x51,0x21,0x5E],[0x7F,0x09,0x19,0x29,0x46],[0x46,0x49,0x49,0x49,0x31],
    [0x01,0x01,0x7F,0x01,0x01],[0x3F,0x40,0x40,0x40,0x3F],[0x1F,0x20,0x40,0x20,0x1F],[0x3F,0x40,0x38,0x40,0x3F],
    [0x63,0x14,0x08,0x14,0x63],[0x07,0x08,0x70,0x08,0x07],[0x61,0x51,0x49,0x45,0x43],[0x00,0x7F,0x41,0x41,0x00],
    [0x02,0x04,0x08,0x10,0x20],[0x00,0x41,0x41,0x7F,0x00],[0x04,0x02,0x01,0x02,0x04],[0x40,0x40,0x40,0x40,0x40],
];

fn glyph(c: u8) -> &'static [u8; 5] {
    let c = c.to_ascii_uppercase();
    let i = if (32..=95).contains(&c) { c - 32 } else { b'?' - 32 };
    &FONT[i as usize]
}

fn put_line(buf: &mut [u8; W * PAGES], row: usize, text: &str) {
    let base = row * W;
    buf[base..base + W].fill(0);
    for (k, c) in text.bytes().take(COLS).enumerate() {
        let x = base + k * 6;
        buf[x..x + 5].copy_from_slice(glyph(c));
    }
}

fn now_ms() -> u32 {
    Instant::now().as_millis() as u32
}

/// Bytes -> (whole KiB, tenths).
fn kib10(bytes: usize) -> (usize, usize) {
    (bytes / 1024, bytes % 1024 * 10 / 1024)
}

struct Oled {
    i2c: I2c<'static, I2C0, Blocking>,
    buf: [u8; W * PAGES],
    ok: bool,
    next_page: Option<u8>,
    last_frame_ms: u32,
    retry_ms: u32,
    // snapshots for the rates
    wall_us: u64,
    idle_us: u32,
    busy_us: u32,
    refreshes: u32,
    cpu: u32,
    hz: u32,
}

impl Oled {
    fn cmds(&mut self, c: &[u8]) -> bool {
        // Control byte 0x00: everything after it is a command byte.
        let mut tx = [0u8; 32];
        tx[0] = 0x00;
        tx[1..1 + c.len()].copy_from_slice(c);
        self.i2c.blocking_write(ADDR, &tx[..1 + c.len()]).is_ok()
    }

    /// The init sequence of ssd1306.py (page addressing mode instead of horizontal, contrast 0x80).
    fn init_display(&mut self) -> bool {
        const SEQ: [u8; 26] = [
            0xAE, // display off
            0x20, 0x02, // page addressing
            0x40, // start line 0
            0xA1, // segment remap
            0xA8, 0x3F, // mux ratio 64
            0xC8, // COM scan direction
            0xD3, 0x00, // display offset
            0xDA, 0x12, // COM pins
            0xD5, 0x80, // clock divide
            0xD9, 0xF1, // pre-charge
            0xDB, 0x30, // VCOM deselect
            0x81, 0x80, // contrast
            0xA4, 0xA6, // follow RAM, not inverted
            0xAD, 0x30, // internal IREF (as in ssd1306.py)
            0x8D, 0x14, // charge pump on
        ];
        if !self.cmds(&SEQ[..]) {
            info!("oled: init sequence not acknowledged (wiring, address or pull-ups?)");
            return false;
        }
        self.buf.fill(0);
        for p in 0..PAGES as u8 {
            if self.push_page(p).is_err() {
                info!("oled: clearing page {} failed", p);
                return false;
            }
        }
        self.cmds(&[0xAF]) // display on
    }

    fn push_page(&mut self, p: u8) -> Result<(), ()> {
        if !self.cmds(&[0xB0 | p, 0x00, 0x10]) {
            return Err(());
        }
        let mut tx = [0u8; 1 + W];
        tx[0] = 0x40; // data
        tx[1..].copy_from_slice(&self.buf[p as usize * W..(p as usize + 1) * W]);
        self.i2c.blocking_write(ADDR, &tx).map_err(|_| ())
    }

    /// The IR PIN entry screen (see `ir_pin.rs`). Shows the key count and a `*` per key, never
    /// the codes.
    fn render_entry(&mut self) {
        let kind = st::ENTRY_KIND.load(Ordering::Relaxed);
        let step = st::ENTRY_STEP.load(Ordering::Relaxed);
        let n = st::ENTRY_COUNT.load(Ordering::Relaxed) as usize;
        let msg = st::ENTRY_MSG.load(Ordering::Relaxed);
        self.buf.fill(0);
        put_line(
            &mut self.buf,
            0,
            match kind {
                1 => "SET IR PIN",
                3 => "NEW IR PIN",
                _ => "ENTER IR PIN",
            },
        );
        put_line(
            &mut self.buf,
            1,
            match (kind, step) {
                (1 | 3, 2) => "STEP 2/2: REPEAT",
                (1 | 3, _) => "STEP 1/2: ENTER",
                _ => "PRESS REMOTE KEYS",
            },
        );
        let mut s: String<32> = String::new();
        let _ = write!(s, "KEYS {}  (MIN 8)", n);
        put_line(&mut self.buf, 2, &s);
        let mut stars: String<24> = String::new();
        for _ in 0..n.min(COLS) {
            let _ = stars.push('*');
        }
        put_line(&mut self.buf, 3, &stars);
        put_line(
            &mut self.buf,
            5,
            match msg {
                1 => "NEED 8 KEYS",
                2 => "DIFFERENT - AGAIN",
                _ if kind == 3 && step == 1 => "BUTTON ALONE: KEEP",
                _ => "",
            },
        );
        put_line(&mut self.buf, 6, "BUTTON: CONFIRM");
        put_line(&mut self.buf, 7, "HOLD 1.5S: CANCEL");
    }

    fn render(&mut self) {
        if st::ENTRY_KIND.load(Ordering::Relaxed) != 0 {
            self.render_entry();
            return;
        }
        // ---- rates since the last frame
        let wall = Instant::now().as_micros();
        let g = crate::guard::snapshot();
        let idle = st::IDLE_US.load(Ordering::Relaxed);
        let dw = wall.wrapping_sub(self.wall_us).max(1);
        let di = idle.wrapping_sub(self.idle_us) as u64;
        let db = g.busy_us.wrapping_sub(self.busy_us) as u64;
        // Sleep time includes the interrupt work done meanwhile (the refresh): take it out.
        let idle_net = di.saturating_sub(db).min(dw);
        self.cpu = (100 - idle_net * 100 / dw) as u32;
        self.hz = (g.refreshes.wrapping_sub(self.refreshes) as u64 * 1_000_000 / dw) as u32;
        self.wall_us = wall;
        self.idle_us = idle;
        self.busy_us = g.busy_us;
        self.refreshes = g.refreshes;

        let mut s: String<32> = String::new();
        let mut line = |buf: &mut [u8; W * PAGES], row: usize, f: &dyn Fn(&mut String<32>)| {
            s.clear();
            f(&mut s);
            put_line(buf, row, &s);
        };

        // ---- 0: FIDO state, USB
        let fault = crate::puf::led_fault();
        let state = if fault {
            "FAULT"
        } else if !crate::guard::has_seed() {
            "LOCK"
        } else if st::BUSY.load(Ordering::Relaxed) {
            "BUSY"
        } else {
            "OPEN"
        };
        let usb = match st::USB.load(Ordering::Relaxed) {
            st::USB_CONFIGURED => "OK",
            st::USB_SUSPENDED => "SLP",
            _ => "--",
        };
        line(&mut self.buf, 0, &|s| {
            let _ = write!(s, "FIDO {} USB {}", state, usb);
        });

        // ---- 1: PIN, PUF
        let pin = if crate::env::pin_set() { "SET" } else { "NO" };
        let puf = st::PUF.load(Ordering::Relaxed);
        let slot = st::PUF_SLOT.load(Ordering::Relaxed);
        line(&mut self.buf, 1, &|s| match puf {
            st::PUF_OFF => {
                let _ = write!(s, "PIN {} PUF OFF", pin);
            }
            st::PUF_BLANK => {
                let _ = write!(s, "PIN {} PUF BLANK", pin);
            }
            st::PUF_DAMAGED => {
                let _ = write!(s, "PIN {} PUF BAD", pin);
            }
            st::PUF_NOISY => {
                let _ = write!(s, "PIN {} PUF NOISY S{}", pin, slot);
            }
            _ => {
                let _ = write!(s, "PIN {} PUF OK S{}", pin, slot);
            }
        });

        // ---- 2: CPU, uptime
        let up = Instant::now().as_secs();
        let cpu = self.cpu;
        line(&mut self.buf, 2, &|s| {
            let _ = write!(s, "CPU {}% UP {}:{:02}:{:02}", cpu, up / 3600, up / 60 % 60, up % 60);
        });

        // ---- 3: RAM
        // SAFETY: only the addresses of linker symbols are taken.
        let (statics, flash_end, top) = unsafe {
            let sdata = &raw const __sdata as usize;
            (
                (&raw const __ebss as usize).saturating_sub(sdata),
                (&raw const __sidata as usize) + (&raw const __edata as usize).saturating_sub(sdata),
                &raw const _stack_start as usize,
            )
        };
        let sp = cortex_m::register::msp::read() as usize;
        let stack = top.saturating_sub(sp);
        let reserved = if cfg!(feature = "sram_puf") { 512 } else { 0 };
        let ram_k = (statics + stack + reserved) / 1024;
        let heap_k = crate::heap_used() / 1024;
        line(&mut self.buf, 3, &|s| {
            let _ = write!(s, "RAM {}K/{}K HP {}K", ram_k, RAM_TOTAL / 1024, heap_k);
        });

        // ---- 4: stack
        let (sw, st10) = kib10(stack);
        #[cfg(feature = "stack_probe")]
        let peak = Some(kib10(crate::stack_probe::peak()));
        #[cfg(not(feature = "stack_probe"))]
        let peak: Option<(usize, usize)> = None;
        line(&mut self.buf, 4, &|s| {
            let _ = match peak {
                Some((pw, pt)) => write!(s, "STK {}.{}K PK {}.{}K", sw, st10, pw, pt),
                None => write!(s, "STK {}.{}K PK --", sw, st10),
            };
        });

        // ---- 5: RAM guard refresh
        let (hz, period) = (self.hz, g.period_us);
        line(&mut self.buf, 5, &|s| {
            let _ = write!(s, "GRD {}/S P{}US", hz, period);
        });

        // ---- 6: guard timing, packets
        let pk = st::PKTS.load(Ordering::Relaxed);
        line(&mut self.buf, 6, &|s| {
            let _ = write!(s, "CS{}US LT{}US P{}", g.max_cs_us, g.max_late_us, pk);
        });

        // ---- 7: flash
        let fw_k = flash_end.saturating_sub(FLASH_BASE) / 1024;
        let (su, st_total) = (
            st::STORE_USED.load(Ordering::Relaxed) as usize * 4 / 1024,
            st::STORE_TOTAL.load(Ordering::Relaxed) as usize * 4 / 1024,
        );
        let (lu, lt) = (
            st::LIFE_USED.load(Ordering::Relaxed) as u64,
            st::LIFE_TOTAL.load(Ordering::Relaxed) as u64,
        );
        let wear = if lt > 0 { Some(lu * 100 / lt) } else { None };
        line(&mut self.buf, 7, &|s| {
            let _ = match wear {
                Some(w) => write!(s, "FW{}K ST{}/{}K W{}%", fw_k, su, st_total, w),
                None => write!(s, "FW{}K ST--", fw_k),
            };
        });
    }

    fn poll(&mut self) {
        let now = now_ms();
        if !self.ok {
            if now.wrapping_sub(self.retry_ms) >= RETRY_MS {
                self.retry_ms = now;
                self.ok = self.init_display();
                self.next_page = None;
                self.last_frame_ms = now.wrapping_sub(FRAME_MS);
            }
            return;
        }
        match self.next_page {
            Some(p) => {
                if self.push_page(p).is_err() {
                    self.ok = false;
                    self.retry_ms = now;
                    return;
                }
                self.next_page = if (p as usize) + 1 < PAGES { Some(p + 1) } else { None };
            }
            None => {
                if st::REDRAW.swap(false, Ordering::Relaxed)
                    || now.wrapping_sub(self.last_frame_ms) >= FRAME_MS
                {
                    self.last_frame_ms = now;
                    self.render();
                    self.next_page = Some(0);
                }
            }
        }
    }
}

/// Main-thread-only cell: `init` runs once in `main`, `poll` only from `wdog::poll_wait` (which
/// only the main thread calls), never from an interrupt or another task.
struct MainOnly(UnsafeCell<Option<Oled>>);
// SAFETY: see above, there is a single accessor thread.
unsafe impl Sync for MainOnly {}
static OLED: MainOnly = MainOnly(UnsafeCell::new(None));

/// Sets up I2C0 (`I2C_HZ`, internal pull-ups on) and tries to start the display. Call once from `main`.
pub fn init(i2c: I2C0, scl: PIN_17, sda: PIN_16) {
    let mut cfg = Config::default();
    cfg.frequency = I2C_HZ;
    let bus = I2c::new_blocking(i2c, scl, sda, cfg);
    // MicroPython's `machine.I2C` switches the internal pull-ups on, and the usual
    // `I2C(0, sda=Pin(16), scl=Pin(17))` example works with modules that have none of their own.
    // embassy-rp leaves them OFF by default, so without this the bus never goes high and the
    // display is never acknowledged. Done AFTER the driver set up the pads (it may rewrite them).
    // With external pull-ups the extra internal ones (in parallel) are harmless.
    for pin in [16usize, 17] {
        embassy_rp::pac::PADS_BANK0
            .gpio(pin)
            .modify(|w| w.set_pue(true));
    }
    embassy_time::block_for(embassy_time::Duration::from_millis(POWER_UP_MS));
    let mut o = Oled {
        i2c: bus,
        buf: [0; W * PAGES],
        ok: false,
        next_page: None,
        last_frame_ms: 0,
        retry_ms: now_ms(),
        wall_us: Instant::now().as_micros(),
        idle_us: 0,
        busy_us: 0,
        refreshes: 0,
        cpu: 0,
        hz: 0,
    };
    o.ok = o.init_display();
    if o.ok {
        info!("oled: display found at 0x3C");
    } else {
        info!("oled: no display answered at 0x3C (I2C0: SDA GP16, SCL GP17), retrying every 5 s");
        // Retry soon (the module may just have been slow to power up), then every RETRY_MS.
        o.retry_ms = now_ms().wrapping_sub(RETRY_MS - FIRST_RETRY_MS);
    }
    // SAFETY: single writer, before any `poll`.
    unsafe { *OLED.0.get() = Some(o) };
}

/// One step of display work (a frame render or one page push). Cheap when there is nothing to do.
pub fn poll() {
    // SAFETY: main thread only (see `MainOnly`).
    if let Some(o) = unsafe { (*OLED.0.get()).as_mut() } {
        o.poll();
    }
}
