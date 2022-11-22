use std::num::ParseIntError;

pub fn decode_hex(message: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..message.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&message[i..i + 2], 16))
        .collect()
}

pub fn decode_to_hex_vector(message: &str) -> Vec<u8> {
    decode_hex(message).unwrap()
}
