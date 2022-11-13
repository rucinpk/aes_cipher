# AES Cipher in Rust

This is repository for AES Cipher developed in Rust and made for educational purposes only.
The implementation consits of 3 types of optimization:

## Memory optimization

- Round keys are not precomputed and only one round key is stored in memory
- There is no precomputed SBOX table

## Speed optimization

The implementation that uses precomputed T tables.
Round operations (shift_rows, mix_cols, sub_bytes) are merged to single operation

## Reference implementation

The original FIPS PUB 197 implementation