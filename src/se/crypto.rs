//! OpenSK `Crypto` for this board: ECDSA in the ATECC608A, everything else in software.

use opensk::api::crypto::software_crypto::{
    SoftwareAes256, SoftwareEcdh, SoftwareHkdf256, SoftwareHmac256, SoftwareSha256,
};
use opensk::api::crypto::Crypto;

use super::ecdsa::SeEcdsa;

pub struct PicoCrypto;

impl Crypto for PicoCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = SeEcdsa;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = SoftwareHkdf256;
}
