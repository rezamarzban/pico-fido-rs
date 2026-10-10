//! Generates the linker memory map (`memory.x`) from the selected `flash_*` Cargo feature and
//! puts it where the linker finds it. The last 8 KiB of flash are left out of the FLASH region:
//! they hold the two master-key slots (src/store.rs, src/keys.rs). Because this is the single
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

    let memory = format!(
        "MEMORY {{\n\
         \x20   BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100\n\
         \x20   /* last 8K of the {flash_kib}K flash is reserved for the two master-key slots */\n\
         \x20   FLASH : ORIGIN = 0x10000100, LENGTH = {flash_kib}K - 0x100 - 8K\n\
         \x20   RAM   : ORIGIN = 0x20000000, LENGTH = 264K\n\
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
