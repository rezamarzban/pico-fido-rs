MEMORY {
    BOOT2   : ORIGIN = 0x10000000, LENGTH = 0x100
    /* last 4K of the 2 MB flash is reserved for the master key (keys.rs) */
    FLASH   : ORIGIN = 0x10000100, LENGTH = 2048K - 0x100 - 4K
    RAM   : ORIGIN = 0x20000000, LENGTH = 264K
}
