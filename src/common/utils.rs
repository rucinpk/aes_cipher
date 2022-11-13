use std::num::ParseIntError;

pub fn decode_hex(message: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..message.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&message[i..i + 2], 16))
        .collect()
}
pub fn decode_hex_to_array(message: &str) -> [u8; 16] {
    let vec = decode_hex(message);

    let mut data: [u8; 4 * 4] = [u8::default(); 4 * 4];

    for (i, byte) in vec.unwrap().iter().enumerate() {
        data[i] = *byte;
    }
    data
}
pub fn decode_hex_to_array_64(message: &str) -> [u8; 24] {
    let vec = decode_hex(message);

    let mut data: [u8; 24] = [u8::default(); 24];

    for (i, byte) in vec.unwrap().iter().enumerate() {
        data[i] = *byte;
    }
    data
}
pub fn decode_hex_to_array_128(message: &str) -> [u8; 32] {
    let vec = decode_hex(message);

    let mut data: [u8; 32] = [u8::default(); 32];

    for (i, byte) in vec.unwrap().iter().enumerate() {
        data[i] = *byte;
    }
    data
}
