# Low flash wear: the simple path

A fully stateless key (private key derived on the fly from PUF + PIN + app ID) was considered and
not chosen: the device cannot check PIN strength, PIN guessing is unlimited, losing the PUF key loses
every account, and it needs a large OpenSK patch that is hard to test. The simple path below removes
the main source of flash writes instead.

## Where the writes come from

- **Signature counter:** OpenSK writes it to flash on every registration and every login
  (`use_signature_counter` defaults to `true`). This is the main source of wear.
- **Resident credentials (passkeys):** stored in the key-value store.
- **PIN retry counter:** one byte per PIN entry, one erase about every 8 entries.
- **setPIN, reset, PUF enrolment:** rare, user-initiated.

## The change

One file, `src/env/mod.rs`, in `CUSTOMIZATION`:

```rust
pub const CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    default_min_pin_length: 10,
    use_signature_counter: false,      // no flash write per registration / login
    max_supported_resident_keys: 0,    // no resident credentials are stored
    ..DEFAULT_CUSTOMIZATION
};
```

OpenSK defaults are `true` and `150`. With `0`, `makeCredential` with `rk=true` fails with a
"store full" error, and OpenSK's customization check does not reject `0`.

## Result

- Registration and login with non-resident credentials write nothing to flash.
- Remaining writes: PIN entry (counter) and rare events (setPIN, reset, PUF enrolment).

## What you lose

- Passkeys and usernameless login.
- Clone detection by sites (the counter stays 0; the PUF binding makes cloning impractical).
- Credential management and large blobs (they need the resident store).

## Unchanged

PIN retry counter and lockout, PIN + PUF protection (Argon2id), U2F.

## Status

Not applied to the project and not built or tested. After building, try one non-resident
registration and one login on the device.
