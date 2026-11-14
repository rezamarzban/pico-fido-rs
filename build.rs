//! Generates the linker memory map (`memory.x`) from the selected `flash_*` Cargo feature and
//! puts it where the linker finds it. The last 104 KiB of flash are left out of the FLASH region
//! (src/layout.rs): 72 KiB OpenSK key-value store (STORE_PAGES in src/main.rs), 2 x 8 KiB site
//! directory sectors, 12 KiB signature counter (all sealed with AES-256-GCM) and one 4 KiB sector of
//! SRAM-PUF helper data. The first 1 KiB of RAM is also taken out of the linker's RAM: nothing may
//! write it, src/puf.rs reads its power-up state as the root of the encryption keys. Because this is the single
//! source of the flash size, the linker layout cannot disagree with `FLASH_SIZE` in main.rs.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let sizes: Vec<u32> = [
        ("CARGO_FEATURE_FLASH_2M", 2u32),
        ("CARGO_FEATURE_FLASH_4M", 4),
        ("CARGO_FEATURE_FLASH_8M", 8),
        ("CARGO_FEATURE_FLASH_16M", 16),
    ]
    .iter()
    .filter(|(var, _)| env::var_os(var).is_some())
    .map(|&(_, mb)| mb)
    .collect();
    if sizes.len() != 1 {
        panic!("enable exactly one of the flash_2m / flash_4m / flash_8m / flash_16m features (not --all-features)");
    }
    let flash_kib = sizes[0] * 1024;

    // SRAM PUF: the first 1 KiB of RAM stays outside every linker section (src/puf.rs REGION_BYTES).
    let memory = format!(
        "MEMORY {{\n\
         \x20   BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100\n\
         \x20   /* last 104K of the {flash_kib}K flash: PUF helper (4K) + counter (12K) + directory B (8K) + directory A (8K) + key-value store (72K) */\n\
         \x20   FLASH : ORIGIN = 0x10000100, LENGTH = {flash_kib}K - 0x100 - 104K\n\
         \x20   PUF   : ORIGIN = 0x20000000, LENGTH = 1K\n\
         \x20   RAM   : ORIGIN = 0x20000400, LENGTH = 264K - 1K\n\
         }}\n"
    );

    // Put `memory.x` in our output directory and ensure it's on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(memory.as_bytes())
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=build.rs");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tlink-rp.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}
