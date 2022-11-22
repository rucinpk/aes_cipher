use crate::AESKey;
use crate::{encrypt_block, AESOptimization};

use super::padding::pad_message_pkcs7;

pub fn encrypt_ecb<'a, T>(message: &'a str, mut key: T) -> String
where
    T: AESKey + Copy,
{
    let padded_message = pad_message_pkcs7(message, 16);
    let mut ciphertext: String = "".to_owned();
    for i in (0..padded_message.len()).step_by(32) {
        let result = encrypt_block(
            &padded_message[i..i + 32],
            key,
            AESOptimization::NoOptimization,
        );
        ciphertext += &result;
    }

    ciphertext
}
//pub fn decrypt_ecb<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn encrypt_cbc<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn decrypt_cbc<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn encrypt_ctr<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn decrypt_ctr<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn encrypt_gcm<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn decrypt_gcm<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn encrypt_ofb<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn decrypt_ofb<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn encrypt_ad<'a, T>(message: &'a str, mut key: T) -> String {}
//pub fn decrypt_ad<'a, T>(message: &'a str, mut key: T) -> String {} // associated data
