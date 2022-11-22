pub mod cipher_operations;
pub mod constants;
pub mod key;
pub mod math;
pub mod modes;
pub mod padding;
pub mod sbox;
pub mod t_tables;
pub mod utils;
use std::ops::{Deref, DerefMut};

#[derive(Copy, Clone, Debug)]
pub struct State {
    data: [u8; 4 * 4],
}

impl Deref for State {
    type Target = [u8; 4 * 4];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            data: [u8::default(); 4 * 4],
        }
    }
}

impl DerefMut for State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl State {
    pub fn from_hex_vector(message: &[u8; 4 * 4]) -> State {
        let mut data: [u8; 4 * 4] = [u8::default(); 4 * 4];

        for (i, byte) in message.iter().enumerate() {
            data[i] = *byte;
        }
        State { data }
    }
    pub fn from_words(words: [[u8; 4]; 4]) -> State {
        let mut data: [u8; 4 * 4] = [u8::default(); 4 * 4];
        let mut iterator = 0;
        for word in words.iter() {
            for j in word.iter() {
                data[iterator] = *j;
                iterator += 1;
            }
        }
        State { data }
    }
    pub fn get_empty_state() -> State {
        let data: [u8; 4 * 4] = [u8::default(); 4 * 4];
        State { data }
    }
    pub fn get_row(&self, i: usize) -> [u8; 4] {
        [
            self.data[4 * i + 0],
            self.data[4 * i + 1],
            self.data[4 * i + 2],
            self.data[4 * i + 3],
        ]
    }
    pub fn get_row_as_word(&self, i: usize) -> u32 {
        let result: u32 = ((self.data[4 * i + 0] as u32) << 24)
            ^ ((self.data[4 * i + 1] as u32) << 16)
            ^ ((self.data[4 * i + 2] as u32) << 8)
            ^ (self.data[4 * i + 3] as u32);
        result
    }
}
