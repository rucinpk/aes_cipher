use super::utils::decode_hex;

pub fn pad_message_pkcs7(message: &str, block_size: usize) -> String {
    let bytes_length = message.as_bytes().len() / 2 as usize;

    let padded_value: usize = block_size - (bytes_length % block_size);
    let padding = std::iter::repeat(format!("{:#04x}", padded_value).strip_prefix("0x").unwrap())
        .take(padded_value)
        .collect::<String>();
    let result_string = message.to_owned() + &padding;

    result_string.to_lowercase()
}
pub fn unpad_message_pkcs7(message: &str) -> String {
    let padding_value = *decode_hex(message)
        .unwrap()
        .get((message.len() - 1) / 2)
        .unwrap() as usize;
    message[..message.len() - padding_value * 2]
        .to_string()
        .to_lowercase()
}
