use crate::common::{
    math::{rot_word, xor_word},
    State,
};

use super::{
    cipher_operations::{inv_mix_columns, sub_word},
    utils::decode_to_hex_vector,
};

pub trait AESKey {
    fn init_round_keys(&mut self) {
        for i in 0..self.key_length() {
            self.set_round_key(i, self.get_key_as_row(i));
        }
    }
    fn get_key(&self) -> [[u8; 4]; 8] {
        let mut key_buffer = [[u8::default(); 4]; 8];
        for i in 0..self.key_length() {
            key_buffer[i] = self.get_key_as_row(i);
        }
        key_buffer
    }
    fn get_key_as_row(&self, i: usize) -> [u8; 4] {
        [
            self.get_key_at(4 * i),
            self.get_key_at(4 * i + 1),
            self.get_key_at(4 * i + 2),
            self.get_key_at(4 * i + 3),
        ]
    }

    fn key_expansion(&mut self, inverse: bool) {
        self.init_round_keys();
        let mut i = self.key_length();

        let rcons = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
        let mut rcoun_counter = 0;
        while i < 4 * (self.num_rounds() + 1) {
            let mut temp = self.get_round_key(i - 1);

            if i % self.key_length() == 0 {
                temp = sub_word(rot_word(temp));
                temp = xor_word(temp, [rcons[rcoun_counter], 0, 0, 0]);
                rcoun_counter += 1;
            } else if self.key_length() > 6 && i % self.key_length() == 4 {
                temp = sub_word(temp);
            }
            self.set_round_key(i, xor_word(self.get_round_key(i - self.key_length()), temp));
            i += 1;
        }
        if inverse {
            self.mix_key_columns();
        }
    }
    fn get_round_subkey(&self, round: usize) -> [[u8; 4]; 4] {
        [
            self.get_round_key(round * 4),
            self.get_round_key(round * 4 + 1),
            self.get_round_key(round * 4 + 2),
            self.get_round_key(round * 4 + 3),
        ]
    }

    fn key_to_state<const N: usize>(&self) -> [State; N] {
        let mut states: [State; N] = [State::default(); N];

        for i in 0..self.num_rounds() {
            states[i] = State::from_words(self.get_round_subkey(i))
        }
        states
    }
    fn mix_key_column<const N: usize>(&mut self, i: usize, states: &mut [State; N]) {
        for (j, _) in states[i].into_iter().step_by(4).enumerate() {
            self.set_round_key(i * 4 + j, states[i].get_row(j));
        }
    }
    fn mix_round_key<const N: usize>(&mut self, states: &mut [State; N]) {
        for i in 1..self.num_rounds() {
            inv_mix_columns(&mut states[i]);
            self.mix_key_column(i, states);
        }
    }

    fn mix_key_columns(&mut self);
    fn num_rounds(&self) -> usize;
    fn key_length(&self) -> usize;
    fn get_round_key(&self, i: usize) -> [u8; 4];
    fn set_round_key(&mut self, i: usize, value: [u8; 4]);
    fn get_key_at(&self, i: usize) -> u8;
}
#[derive(Copy, Clone)]
pub struct KeyNk4 {
    data: [u8; 16],
    round_keys: [[u8; 4]; 44],
}
#[derive(Copy, Clone)]
pub struct KeyNk6 {
    data: [u8; 24],
    round_keys: [[u8; 4]; 72],
}
#[derive(Copy, Clone)]
pub struct KeyNk8 {
    data: [u8; 32],
    round_keys: [[u8; 4]; 120],
}

impl KeyNk4 {
    pub fn new(key_data: &str) -> KeyNk4 {
        KeyNk4 {
            data: decode_to_hex_vector(key_data)
                .try_into()
                .unwrap_or_else(|v: Vec<u8>| {
                    panic!("Expected a Vec of length {} but it was {}", 16, v.len())
                }),
            round_keys: [[u8::default(); 4]; 44],
        }
    }
}
impl KeyNk6 {
    pub fn new(key_data: &str) -> KeyNk6 {
        KeyNk6 {
            data: decode_to_hex_vector(key_data)
                .try_into()
                .unwrap_or_else(|v: Vec<u8>| {
                    panic!("Expected a Vec of length {} but it was {}", 24, v.len())
                }),
            round_keys: [[u8::default(); 4]; 72],
        }
    }
}
impl KeyNk8 {
    pub fn new(key_data: &str) -> KeyNk8 {
        KeyNk8 {
            data: decode_to_hex_vector(key_data)
                .try_into()
                .unwrap_or_else(|v: Vec<u8>| {
                    panic!("Expected a Vec of length {} but it was {}", 32, v.len())
                }),
            round_keys: [[u8::default(); 4]; 120],
        }
    }
}
impl AESKey for KeyNk4 {
    fn num_rounds(&self) -> usize {
        10
    }
    fn get_round_key(&self, i: usize) -> [u8; 4] {
        self.round_keys[i]
    }
    fn key_length(&self) -> usize {
        4
    }
    fn set_round_key(&mut self, i: usize, value: [u8; 4]) {
        self.round_keys[i] = value;
    }

    fn get_key_at(&self, i: usize) -> u8 {
        self.data[i]
    }
    fn mix_key_columns(&mut self) {
        let mut states = self.key_to_state::<10>();
        self.mix_round_key::<10>(&mut states);
    }
}
impl AESKey for KeyNk6 {
    fn set_round_key(&mut self, i: usize, value: [u8; 4]) {
        self.round_keys[i] = value;
    }
    fn mix_key_columns(&mut self) {
        let mut states = self.key_to_state::<12>();
        self.mix_round_key::<12>(&mut states);
    }
    fn get_key_at(&self, i: usize) -> u8 {
        self.data[i]
    }

    fn num_rounds(&self) -> usize {
        12
    }
    fn get_round_key(&self, i: usize) -> [u8; 4] {
        self.round_keys[i]
    }
    fn key_length(&self) -> usize {
        6
    }
}
impl AESKey for KeyNk8 {
    fn mix_key_columns(&mut self) {
        let mut states = self.key_to_state::<14>();
        self.mix_round_key::<14>(&mut states);
    }
    fn set_round_key(&mut self, i: usize, value: [u8; 4]) {
        self.round_keys[i] = value;
    }

    fn get_key_at(&self, i: usize) -> u8 {
        self.data[i]
    }

    fn num_rounds(&self) -> usize {
        14
    }

    fn key_length(&self) -> usize {
        8
    }
    fn get_round_key(&self, i: usize) -> [u8; 4] {
        self.round_keys[i]
    }
}
