pub fn rot_word(data: [u8; 4]) -> [u8; 4] {
    return [data[1], data[2], data[3], data[0]];
}

pub fn xor_word(x: [u8; 4], y: [u8; 4]) -> [u8; 4] {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
}
fn mul02(x: u8) -> u8 {
    let result = (x << 1) & 0xff;
    if x < 128 {
        //High bit is set
        return result;
    }
    result ^ 0x1b
}
fn mul03(x: u8) -> u8 {
    mul02(x) ^ x
}
pub fn mul(a: u8, mut b: u8) -> u8 {
    if b == 0x03 {
        return mul03(a);
    }
    if b == 0x02 {
        return mul02(a);
    }
    let mut result = 0;
    let mut a = a;

    while b > 0 {
        if b % 2 == 1 {
            result ^= a;
        }
        a = mul02(a);
        b >>= 1;
    }
    result
}
