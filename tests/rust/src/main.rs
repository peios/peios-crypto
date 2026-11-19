//! An aws-lc-rs program built with aws-lc-sys in system mode, so that it
//! links libpcrypto as a system AWS-LC: it hashes, signs and verifies, and
//! seals and opens.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair, UnparsedPublicKey,
};

const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
    0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
    0x15, 0xad,
];

fn main() {
    assert_eq!(digest(&SHA256, b"abc").as_ref(), ABC_SHA256, "SHA-256 digest");

    let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate an RSA key");
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), b"message", &mut signature)
        .expect("sign");
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref())
        .verify(b"message", &signature)
        .expect("verify");

    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[7; 32]).expect("AES key"));
    let mut sealed = b"plaintext".to_vec();
    sealing
        .seal_in_place_append_tag(Nonce::assume_unique_for_key([1; 12]), Aad::empty(), &mut sealed)
        .expect("seal");
    let opened = sealing
        .open_in_place(Nonce::assume_unique_for_key([1; 12]), Aad::empty(), &mut sealed)
        .expect("open");
    assert_eq!(opened, b"plaintext", "AES-256-GCM round trip");

    println!("system-awslc: ok");
}
