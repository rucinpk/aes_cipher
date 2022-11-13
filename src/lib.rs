//AES Implementation based on FIPS PUB 197

use common::{
    cipher_operations::{
        add_round_key, add_round_key_no_mem, inv_mix_columns, inv_shift_rows, inv_sub_bytes,
        inv_sub_bytes_no_mem, merged_op, merged_op_inverse, mix_columns, sub_bytes,
        sub_bytes_no_mem, sub_rows,
    },
    key::AESKey,
    utils::decode_hex_to_array,
    State,
};

mod common;

pub enum AESKeyLength {
    Nk4,
    Nk6,
    Nk8,
}

pub enum AESOptimization {
    NoOptimization,
    MemoryEfficient,
    SpeedEfficient,
}

pub enum ModeOfOperation {
    EBC,
    CBC,
    CTR,
    GCM,
}

pub fn get_round_subkey_for_no_mem<T>(round: usize, key: &T, inverse_columns: bool) -> [[u8; 4]; 4]
where
    T: AESKey,
{
    let mut expansion_counter = key.key_length();
    let mock_state = State::get_empty_state();

    let mut key_buffer = key.get_key();
    let mut key_state =
        State::from_words([key_buffer[0], key_buffer[1], key_buffer[2], key_buffer[3]]);

    for _ in 0..round + 1 {
        key_state = State::from_words([
            key_buffer[(expansion_counter + 0) % key.key_length()],
            key_buffer[(expansion_counter + 1) % key.key_length()],
            key_buffer[(expansion_counter + 2) % key.key_length()],
            key_buffer[(expansion_counter + 3) % key.key_length()],
        ]);

        let (_, new_expansion_counter) = add_round_key_no_mem(
            mock_state,
            &mut key_buffer,
            expansion_counter,
            key.key_length(),
        );

        expansion_counter = new_expansion_counter;
    }
    if inverse_columns {
        inv_mix_columns(&mut key_state);
    }

    for (j, _) in key_state.into_iter().step_by(4).enumerate() {
        let index = (j + expansion_counter) % key.key_length();

        key_buffer[index] = [
            key_state[4 * j + 0],
            key_state[4 * j + 1],
            key_state[4 * j + 2],
            key_state[4 * j + 3],
        ];
    }
    [
        key_buffer[(expansion_counter + 0) % key.key_length()],
        key_buffer[(expansion_counter + 1) % key.key_length()],
        key_buffer[(expansion_counter + 2) % key.key_length()],
        key_buffer[(expansion_counter + 3) % key.key_length()],
    ]
}

pub fn decrypt<'a, T>(ciphertext: &'a str, mut key: T, optimization: AESOptimization) -> String
where
    T: AESKey,
{
    let ciphertext = decode_hex_to_array(ciphertext);
    let mut state = State::from_hex_vector(&ciphertext);
    let num_rounds = key.num_rounds();
    let mut round = num_rounds;

    let sub_key = match optimization {
        AESOptimization::MemoryEfficient => get_round_subkey_for_no_mem(round, &key, false),
        _ => {
            key.key_expansion(true);
            key.get_round_subkey(round)
        }
    };
    add_round_key(&mut state, [sub_key[0], sub_key[1], sub_key[2], sub_key[3]]);
    round -= 1;

    while round > 0 {
        match optimization {
            AESOptimization::NoOptimization => {
                state = inv_sub_bytes(state);
                state = inv_shift_rows(state);
                inv_mix_columns(&mut state);
                add_round_key(&mut state, key.get_round_subkey(round));
            }
            AESOptimization::MemoryEfficient => {
                state = inv_sub_bytes_no_mem(state);
                state = inv_shift_rows(state);
                inv_mix_columns(&mut state);
                let key_buffer = get_round_subkey_for_no_mem(round, &key, true);
                add_round_key(
                    &mut state,
                    [key_buffer[0], key_buffer[1], key_buffer[2], key_buffer[3]],
                );
            }
            AESOptimization::SpeedEfficient => {
                state = merged_op_inverse(state, round, &key);
            }
        }
        round -= 1;
    }

    let sub_key = match optimization {
        AESOptimization::MemoryEfficient => {
            let key_buffer = key.get_key();
            [key_buffer[0], key_buffer[1], key_buffer[2], key_buffer[3]]
        }
        _ => key.get_round_subkey(round),
    };
    match optimization {
        AESOptimization::MemoryEfficient => {
            state = inv_sub_bytes_no_mem(state);
        }
        _ => {
            state = inv_sub_bytes(state);
        }
    }
    state = inv_shift_rows(state);

    add_round_key(&mut state, [sub_key[0], sub_key[1], sub_key[2], sub_key[3]]);

    hex::encode(*state)
}

pub fn encrypt<'a, T>(message: &'a str, mut key: T, optimization: AESOptimization) -> String
where
    T: AESKey,
{
    let message = decode_hex_to_array(message);
    let mut state = State::from_hex_vector(&message);

    match optimization {
        AESOptimization::MemoryEfficient => {}
        _ => {
            key.key_expansion(false);
            add_round_key(&mut state, key.get_round_subkey(0));
        }
    }

    let mut expansion_counter = key.key_length();
    let mut key_buffer = key.get_key();

    match optimization {
        AESOptimization::MemoryEfficient => {
            for c in 0..4 {
                state[4 * c + 0] ^= key_buffer[c][0];
                state[4 * c + 1] ^= key_buffer[c][1];
                state[4 * c + 2] ^= key_buffer[c][2];
                state[4 * c + 3] ^= key_buffer[c][3];
            }
        }
        _ => {}
    }

    for round in 1..key.num_rounds() {
        match optimization {
            AESOptimization::NoOptimization => {
                state = sub_bytes(state);
                state = sub_rows(state);
                state = mix_columns(state);
                add_round_key(&mut state, key.get_round_subkey(round));
            }
            AESOptimization::MemoryEfficient => {
                state = sub_bytes_no_mem(state);
                state = sub_rows(state);
                state = mix_columns(state);

                let (new_state, new_expansion_counter) = add_round_key_no_mem(
                    state,
                    &mut key_buffer,
                    expansion_counter,
                    key.key_length(),
                );
                state = new_state;

                expansion_counter = new_expansion_counter;
            }
            AESOptimization::SpeedEfficient => {
                state = merged_op(state, round, &key);
            }
        }
    }
    match optimization {
        AESOptimization::MemoryEfficient => {
            state = sub_bytes_no_mem(state);
            state = sub_rows(state);
            let (new_state, _) =
                add_round_key_no_mem(state, &mut key_buffer, expansion_counter, key.key_length());
            state = new_state;
        }
        _ => {
            state = sub_bytes(state);
            state = sub_rows(state);
            add_round_key(&mut state, key.get_round_subkey(key.num_rounds()));
        }
    }

    hex::encode(*state)
}

#[cfg(test)]
mod tests {

    use crate::common::{
        cipher_operations::{inv_sub_byte_no_mem, mult, sbox_no_mem},
        key::{KeyNk4, KeyNk6, KeyNk8},
    };

    use super::*;

    #[test]
    fn it_mults() {
        let l = 0x57;
        let r = 0x83;
        let result = mult(l, r);
        assert_eq!(result, 0xc1);

        let l = 0x57;
        let r = 0x13;
        let result = mult(l, r);
        assert_eq!(result, 0xfe);
    }

    #[test]
    fn it_sub_byte_no_mem() {
        let b = 0x53;
        let expected = 0xed;
        let result = sbox_no_mem(b);
        assert_eq!(expected, result);
    }
    #[test]
    fn it_inv_sub_byte_no_mem() {
        let b = 0xed;
        let expected = 0x53;
        let result = inv_sub_byte_no_mem(b);
        assert_eq!(expected, result);
    }

    #[test]
    fn it_sub_byte_then_inv_sub_byte_no_mem() {
        let b = 0x53;
        let result = sbox_no_mem(b);
        let result = inv_sub_byte_no_mem(result);
        assert_eq!(b, result);
    }
    #[test]
    fn it_encrypts_message_128_key() {
        let key = KeyNk4::new("000102030405060708090a0b0c0d0e0f");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::NoOptimization,
        );
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a");

        let key = KeyNk4::new("000102030405060708090a0b0c0d0e0f");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::SpeedEfficient,
        );
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a");

        let key = KeyNk4::new("000102030405060708090a0b0c0d0e0f");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::MemoryEfficient,
        );
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn it_encrypts_message_192_key() {
        let key = KeyNk6::new("000102030405060708090a0b0c0d0e0f1011121314151617");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::NoOptimization,
        );
        assert_eq!(result, "dda97ca4864cdfe06eaf70a0ec0d7191");

        let key = KeyNk6::new("000102030405060708090a0b0c0d0e0f1011121314151617");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::SpeedEfficient,
        );
        assert_eq!(result, "dda97ca4864cdfe06eaf70a0ec0d7191");

        let key = KeyNk6::new("000102030405060708090a0b0c0d0e0f1011121314151617");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::MemoryEfficient,
        );
        assert_eq!(result, "dda97ca4864cdfe06eaf70a0ec0d7191");
    }

    #[test]
    fn it_encrypts_message_256_key() {
        let key = KeyNk8::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::NoOptimization,
        );
        assert_eq!(result, "8ea2b7ca516745bfeafc49904b496089");

        let key = KeyNk8::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::MemoryEfficient,
        );
        assert_eq!(result, "8ea2b7ca516745bfeafc49904b496089");

        let key = KeyNk8::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        let result = encrypt(
            "00112233445566778899aabbccddeeff",
            key,
            AESOptimization::SpeedEfficient,
        );
        assert_eq!(result, "8ea2b7ca516745bfeafc49904b496089");
    }

    #[test]
    fn it_decrypts_message_128_key() {
        let key = KeyNk4::new("000102030405060708090a0b0c0d0e0f");
        let result = decrypt(
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            key,
            AESOptimization::NoOptimization,
        );
        assert_eq!(result, "00112233445566778899aabbccddeeff");
        let key = KeyNk4::new("000102030405060708090a0b0c0d0e0f");
        let result = decrypt(
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            key,
            AESOptimization::SpeedEfficient,
        );
        assert_eq!(result, "00112233445566778899aabbccddeeff");
        let key = KeyNk4::new("000102030405060708090a0b0c0d0e0f");
        let result = decrypt(
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            key,
            AESOptimization::MemoryEfficient,
        );
        assert_eq!(result, "00112233445566778899aabbccddeeff");
    }
    #[test]
    fn it_decrypts_message_192_key() {
        let ciphertext = "dda97ca4864cdfe06eaf70a0ec0d7191";
        let expected_plaintext = "00112233445566778899aabbccddeeff";

        let key = KeyNk6::new("000102030405060708090a0b0c0d0e0f1011121314151617");

        let result = decrypt::<KeyNk6>(ciphertext, key, AESOptimization::NoOptimization);
        assert_eq!(result, expected_plaintext);
        let key = KeyNk6::new("000102030405060708090a0b0c0d0e0f1011121314151617");

        let result = decrypt::<KeyNk6>(ciphertext, key, AESOptimization::MemoryEfficient);
        assert_eq!(result, expected_plaintext);
        let key = KeyNk6::new("000102030405060708090a0b0c0d0e0f1011121314151617");

        let result = decrypt::<KeyNk6>(ciphertext, key, AESOptimization::SpeedEfficient);
        assert_eq!(result, expected_plaintext);
    }
    #[test]
    fn it_decrypts_message_256_key() {
        let ciphertext = "8ea2b7ca516745bfeafc49904b496089";
        let expected_plaintext = "00112233445566778899aabbccddeeff";

        let key = KeyNk8::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let result = decrypt::<KeyNk8>(ciphertext, key, AESOptimization::NoOptimization);
        assert_eq!(result, expected_plaintext);

        let key = KeyNk8::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let result = decrypt::<KeyNk8>(ciphertext, key, AESOptimization::SpeedEfficient);
        assert_eq!(result, expected_plaintext);

        let key = KeyNk8::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let result = decrypt::<KeyNk8>(ciphertext, key, AESOptimization::MemoryEfficient);
        assert_eq!(result, expected_plaintext);
    }

    #[test]
    fn it_expands_key_128_bit_key() {
        let mut key = KeyNk4::new("2b7e151628aed2a6abf7158809cf4f3c");
        key.key_expansion(false);
        assert_eq!(key.get_round_key(0), [0x2b, 0x7e, 0x15, 0x16]);
        assert_eq!(key.get_round_key(5), [0x88, 0x54, 0x2c, 0xb1]);
        assert_eq!(key.get_round_key(10), [0x59, 0x35, 0x80, 0x7a]);
        assert_eq!(key.get_round_key(43), [0xb6, 0x63, 0x0c, 0xa6]);
    }
}
