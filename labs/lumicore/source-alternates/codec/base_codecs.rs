use crate::codec::TextCodec;

/// Lowers base36 codec (DNS-label safe, anti-fingerprinting through case normalization).
#[derive(Debug, Clone, Copy, Default)]
pub struct LowerBase36;

impl TextCodec for LowerBase36 {
    fn encode_name(&self) -> &str {
        "lowerbase36"
    }

    fn encoded_len(&self, input_len: usize) -> usize {
        if input_len == 0 {
            return 0;
        }
        let blocks = input_len / 7;
        let rem = input_len % 7;
        blocks * 11 + lower_base36_encoded_chars_by_bytes(rem)
    }

    fn encode(&self, dst: &mut [u8], input: &[u8]) -> usize {
        if input.is_empty() {
            return 0;
        }

        let mut offset = 0;
        let mut src = input;

        while src.len() >= 7 {
            let val = u64_from_seven(src);
            write_base36_block(&mut dst[offset..offset + 11], val, 11);
            offset += 11;
            src = &src[7..];
        }

        if !src.is_empty() {
            let mut val: u64 = 0;
            for b in src {
                val = (val << 8) | u64::from(*b);
            }
            let char_count = lower_base36_encoded_chars_by_bytes(src.len());
            write_base36_block(&mut dst[offset..offset + char_count], val, char_count);
            offset += char_count;
        }

        offset
    }

    fn decode(&self, dst: &mut [u8], input: &[u8]) -> Result<usize, crate::codec::CodecError> {
        if input.is_empty() {
            return Ok(0);
        }

        let total = lower_base36_decoded_len(input.len())?;
        if dst.len() < total {
            return Err(crate::codec::CodecError::InvalidLength);
        }

        let mut out_offset = 0;
        let mut src = input;

        while !src.is_empty() {
            let (block_size, char_count) = lower_base36_next_decode_block(src.len());
            let val = read_base36_block(&src[..char_count])?;
            for i in (0..block_size).rev() {
                dst[out_offset + i] = (val >> (8 * (block_size - i - 1))) as u8;
            }
            out_offset += block_size;
            src = &src[char_count..];
        }

        Ok(total)
    }
}

#[inline(always)]
const fn lower_base36_encoded_chars_by_bytes(rem: usize) -> usize {
    match rem {
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 5,
        4 => 7,
        5 => 8,
        6 => 10,
        _ => 11,
    }
}

#[inline(always)]
const fn lower_base36_decoded_bytes_by_chars(rem: usize) -> usize {
    match rem {
        0 => 0,
        1 => 0,
        2 => 1,
        3 => 0,
        4 => 2,
        5 => 3,
        6 => 0,
        7 => 4,
        8 => 5,
        9 => 0,
        10 => 6,
        11 => 7,
        _ => 0,
    }
}

#[inline(always)]
fn u64_from_seven(src: &[u8]) -> u64 {
    u64::from(src[0]) << 48
        | u64::from(src[1]) << 40
        | u64::from(src[2]) << 32
        | u64::from(src[3]) << 24
        | u64::from(src[4]) << 16
        | u64::from(src[5]) << 8
        | u64::from(src[6])
}

const LOWER_BASE36_ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn write_base36_block(dst: &mut [u8], mut val: u64, count: usize) {
    for i in (0..count).rev() {
        dst[i] = LOWER_BASE36_ALPHABET[(val % 36) as usize];
        val /= 36;
    }
}

static LOWER_BASE36_DECODE_MAP: [u8; 256] = {
    let mut table = [0xFF; 256];
    let alphabet = *b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut i = 0;
    #[allow(clippy::deprecated_self)]
    while i < alphabet.len() {
        table[alphabet[i] as usize] = i as u8;
        table[(alphabet[i] - b'a' + b'A') as usize] = i as u8;
        i += 1;
    }
    table
};

fn read_base36_block(data: &[u8]) -> Result<u64, crate::codec::CodecError> {
    let mut val: u64 = 0;
    for ch in data {
        let digit = LOWER_BASE36_DECODE_MAP[*ch as usize];
        if digit == 0xFF {
            return Err(crate::codec::CodecError::InvalidInput);
        }
        val = val * 36 + u64::from(digit);
    }
    Ok(val)
}

fn lower_base36_decoded_len(encoded_len: usize) -> Result<usize, crate::codec::CodecError> {
    if encoded_len == 0 {
        return Ok(0);
    }
    let (blocks, rem) = (encoded_len / 11, encoded_len % 11);
    if rem >= 12 {
        return Err(crate::codec::CodecError::InvalidLength);
    }
    let decoded_rem = lower_base36_decoded_bytes_by_chars(rem);
    if rem != 0 && decoded_rem == 0 {
        return Err(crate::codec::CodecError::InvalidLength);
    }
    Ok(blocks * 7 + decoded_rem)
}

fn lower_base36_next_decode_block(remaining: usize) -> (usize, usize) {
    if remaining >= 11 {
        return (7, 11);
    }
    let bs = lower_base36_decoded_bytes_by_chars(remaining);
    (bs, remaining)
}
