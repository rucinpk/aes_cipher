pub fn sub_word(data: [u8; 4]) -> [u8; 4] {
    return [
        sub_byte(data[0]),
        sub_byte(data[1]),
        sub_byte(data[2]),
        sub_byte(data[3]),
    ];
}

use crate::common::{math::mul, State};

use super::{
    constants::{AES_POLYNOMIAL, AES_POLYNOMIAL_DEGREE},
    key::AESKey,
    math::{rot_word, xor_word},
    sbox::*,
    t_tables::*,
};
pub fn get_mixed_column(b1: u8, b2: u8, b3: u8, b4: u8, m1: u8, m2: u8, m3: u8, m4: u8) -> [u8; 4] {
    [
        mul(b1, m1) ^ mul(b2, m2) ^ mul(b3, m3) ^ mul(b4, m4),
        mul(b1, m4) ^ mul(b2, m1) ^ mul(b3, m2) ^ mul(b4, m3),
        mul(b1, m3) ^ mul(b2, m4) ^ mul(b3, m1) ^ mul(b4, m2),
        mul(b1, m2) ^ mul(b2, m3) ^ mul(b3, m4) ^ mul(b4, m1),
    ]
}
pub fn get_mixed_columns(state: &mut State, m1: u8, m2: u8, m3: u8, m4: u8) -> [[u8; 4]; 4] {
    [
        get_mixed_column(state[0], state[1], state[2], state[3], m1, m2, m3, m4),
        get_mixed_column(state[4], state[5], state[6], state[7], m1, m2, m3, m4),
        get_mixed_column(state[8], state[9], state[10], state[11], m1, m2, m3, m4),
        get_mixed_column(state[12], state[13], state[14], state[15], m1, m2, m3, m4),
    ]
}
pub fn inv_mix_columns(state: &mut State) {
    let mixed_columns = get_mixed_columns(state, 0x0e, 0x0b, 0x0d, 0x09);

    for i in 0..16 {
        state[i] = mixed_columns[i / 4][i % 4];
    }
}

pub fn mix_columns(mut state: State) -> State {
    let mixed_columns = get_mixed_columns(&mut state, 0x02, 0x03, 1, 1);

    for i in 0..16 {
        state[i] = mixed_columns[i / 4][i % 4];
    }

    state
}
pub fn get_sbox_index(byte: u8) -> (u8, u8) {
    (byte >> 4, byte & 0x0F)
}
pub fn sub_byte(byte: u8) -> u8 {
    let (x, y) = get_sbox_index(byte);
    SBOX_TABLE[x as usize][y as usize]
}
pub fn inv_sub_byte(byte: u8) -> u8 {
    let (x, y) = get_sbox_index(byte);
    INVERSE_SBOX_TABLE[x as usize][y as usize]
}

pub fn sub_bytes(mut state: State) -> State {
    for byte in state.iter_mut() {
        *byte = sub_byte(*byte);
    }
    state
}

pub fn byte_degree(mut b: u16) -> usize {
    let mut ctr = 14;

    while ctr > 0 {
        if b >= 0x8000 {
            return ctr + 1;
        }
        b <<= 1;
        ctr -= 1;
    }

    return ctr + 1;
}

pub fn reduce_poly(mut polynomial: u16) -> u8 {
    let mut polynomial_degree = byte_degree(polynomial);

    while polynomial_degree >= AES_POLYNOMIAL_DEGREE {
        (polynomial, polynomial_degree) = reduce_and_get_degree(polynomial);
    }

    polynomial as u8
}
fn reduce_and_get_degree(polynomial: u16) -> (u16, usize) {
    let polynomial_degree = byte_degree(polynomial);
    let reduced_polynomial =
        polynomial ^ (AES_POLYNOMIAL << (polynomial_degree - AES_POLYNOMIAL_DEGREE));
    (reduced_polynomial, byte_degree(reduced_polynomial))
}
fn multiply_byte(a: u8, b: u8, i: usize, j: usize) -> u16 {
    if ((0x80 >> i) & a) != 0 && ((0x80 >> j) & b) != 0 {
        return 0x8000 >> (i + j) + 1;
    }
    0
}
pub fn mult(a: u8, b: u8) -> u8 {
    let mut prod_byte: u16 = 0;
    for i in 0..8 {
        for j in 0..8 {
            prod_byte ^= multiply_byte(a, b, i, j);
        }
    }
    reduce_poly(prod_byte)
}

pub fn inverse(byte: u8) -> u8 {
    if byte == 0 {
        return 0;
    }
    for i in 0..0xFF {
        let mult_res: u8 = mult(byte, i + 1);
        if mult_res == 1 {
            return i + 1;
        }
    }
    0x1c
}
pub fn sbox_no_mem(byte: u8) -> u8 {
    let q = inverse(byte);

    return q
        ^ ((q << 1) | (q >> 7))
        ^ ((q << 2) | (q >> 6))
        ^ ((q << 3) | (q >> 5))
        ^ ((q << 4) | (q >> 4))
        ^ 0x63;
}
pub fn inv_sub_byte_no_mem(q: u8) -> u8 {
    let q = ((q << 1) | (q >> 7)) ^ ((q << 3) | (q >> 5)) ^ ((q << 6) | (q >> 2)) ^ 0x05;

    inverse(q)
}
pub fn sub_bytes_no_mem(mut state: State) -> State {
    for byte in state.iter_mut() {
        *byte = sbox_no_mem(*byte);
    }
    state
}
pub fn inv_sub_bytes_no_mem(mut state: State) -> State {
    for byte in state.iter_mut() {
        *byte = inv_sub_byte_no_mem(*byte);
    }
    state
}
pub fn inv_sub_bytes(mut state: State) -> State {
    for byte in state.iter_mut() {
        *byte = inv_sub_byte(*byte);
    }
    state
}

pub fn sub_rows(mut state: State) -> State {
    let temp = state[1];

    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    state.swap(2, 10);
    state.swap(6, 14);

    let temp = state[15];

    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
    state
}

pub fn inv_shift_rows(mut state: State) -> State {
    let temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    state.swap(2, 10);
    state.swap(6, 14);

    let temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;

    state
}
pub fn add_round_key(state: &mut State, round_key: [[u8; 4]; 4]) {
    for (i, byte) in state.iter_mut().enumerate() {
        *byte ^= round_key[i / 4][i % 4];
    }
}

pub fn merged_op_inverse<T>(mut state: State, i: usize, key: &T) -> State
where
    T: AESKey,
{
    let mut w1 = xor_word(TD0[state[0] as usize], TD1[state[13] as usize]);
    w1 = xor_word(w1, TD2[state[10] as usize]);
    w1 = xor_word(w1, TD3[state[7] as usize]);

    let mut w2 = xor_word(TD0[state[4] as usize], TD1[state[1] as usize]);
    w2 = xor_word(w2, TD2[state[14] as usize]);
    w2 = xor_word(w2, TD3[state[11] as usize]);

    let mut w3 = xor_word(TD0[state[8] as usize], TD1[state[5] as usize]);
    w3 = xor_word(w3, TD2[state[2] as usize]);
    w3 = xor_word(w3, TD3[state[15] as usize]);

    let mut w4 = xor_word(TD0[state[12] as usize], TD1[state[9] as usize]);
    w4 = xor_word(w4, TD2[state[6] as usize]);
    w4 = xor_word(w4, TD3[state[3] as usize]);

    let w = [w1, w2, w3, w4];

    for j in 0..4 {
        state[4 * j + 0] = w[j][0] ^ key.get_round_key(i * 4 + j)[0];
        state[4 * j + 1] = w[j][1] ^ key.get_round_key(i * 4 + j)[1];
        state[4 * j + 2] = w[j][2] ^ key.get_round_key(i * 4 + j)[2];
        state[4 * j + 3] = w[j][3] ^ key.get_round_key(i * 4 + j)[3];
    }
    state
}
pub fn merged_op<T>(mut state: State, i: usize, key: &T) -> State
where
    T: AESKey,
{
    let mut w1 = xor_word(T0[state[0] as usize], T1[state[5] as usize]);
    w1 = xor_word(w1, T2[state[10] as usize]);
    w1 = xor_word(w1, T3[state[15] as usize]);

    let mut w2 = xor_word(T0[state[4] as usize], T1[state[9] as usize]);
    w2 = xor_word(w2, T2[state[14] as usize]);
    w2 = xor_word(w2, T3[state[3] as usize]);

    let mut w3 = xor_word(T0[state[8] as usize], T1[state[13] as usize]);
    w3 = xor_word(w3, T2[state[2] as usize]);
    w3 = xor_word(w3, T3[state[7] as usize]);

    let mut w4 = xor_word(T0[state[12] as usize], T1[state[1] as usize]);
    w4 = xor_word(w4, T2[state[6] as usize]);
    w4 = xor_word(w4, T3[state[11] as usize]);

    let w = [w1, w2, w3, w4];

    for j in 0..4 {
        state[4 * j + 0] = w[j][0] ^ key.get_round_key(i * 4 + j)[0];
        state[4 * j + 1] = w[j][1] ^ key.get_round_key(i * 4 + j)[1];
        state[4 * j + 2] = w[j][2] ^ key.get_round_key(i * 4 + j)[2];
        state[4 * j + 3] = w[j][3] ^ key.get_round_key(i * 4 + j)[3];
    }

    state
}

pub fn mult_one(b: u8) -> u8 {
    let high_bit = b & 0x80;
    let mut temp = b;
    temp = temp << 1;
    if high_bit != 0 {
        temp ^= 0x1b;
    }
    temp
}

pub fn get_rcon(n: usize) -> u8 {
    let mut c = 1;
    for _ in 1..n {
        c = mult_one(c);
    }
    c
}

pub fn get_next_key(
    prev_key: [u8; 4],
    current_key: [u8; 4],
    key_length: usize,
    expansion_counter: usize,
) -> [u8; 4] {
    let mut temp = prev_key;

    if expansion_counter % key_length == 0 {
        temp = rot_word(temp);
        temp = sub_word(temp);
        let n = expansion_counter / key_length;
        let rcon = get_rcon(n);
        temp[0] ^= rcon;
    } else if key_length > 6 && expansion_counter % key_length == 4 {
        temp = sub_word(temp);
    }
    xor_word(current_key, temp)
}

pub fn add_round_key_no_mem(
    mut state: State,
    key_buffer: &mut [[u8; 4]; 8],
    key_expansion_counter: usize,
    key_length: usize,
) -> (State, usize) {
    let mut key_expansion_counter = key_expansion_counter;

    for _ in 0..4 {
        key_buffer[key_expansion_counter % key_length] = get_next_key(
            key_buffer[(key_expansion_counter - 1) % key_length],
            key_buffer[key_expansion_counter % key_length],
            key_length,
            key_expansion_counter,
        );
        key_expansion_counter += 1;
    }

    for c in 0..4 {
        let index = (key_expansion_counter + c) % key_length;

        state[4 * c + 0] ^= key_buffer[index][0];
        state[4 * c + 1] ^= key_buffer[index][1];
        state[4 * c + 2] ^= key_buffer[index][2];
        state[4 * c + 3] ^= key_buffer[index][3];
    }

    (state, key_expansion_counter)
}
