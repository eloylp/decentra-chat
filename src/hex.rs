pub(crate) fn parse_fixed_hex<const N: usize>(input: &str) -> Result<[u8; N], String> {
    if input.len() != N * 2 {
        return Err(format!("expected exactly {} hex characters", N * 2));
    }

    let mut out = [0_u8; N];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0])
            .ok_or_else(|| format!("invalid hex character at byte {}", index * 2))?;
        let low = hex_value(chunk[1])
            .ok_or_else(|| format!("invalid hex character at byte {}", index * 2 + 1))?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

pub(crate) fn parse_hyphenated_fixed_hex<const N: usize>(
    input: &str,
    length_error: impl Into<String>,
) -> Result<[u8; N], String> {
    let mut hex = String::with_capacity(N * 2);
    for byte in input.bytes() {
        if byte != b'-' {
            hex.push(byte as char);
        }
    }
    if hex.len() != N * 2 {
        return Err(length_error.into());
    }

    parse_fixed_hex(&hex)
}

pub(crate) fn lower_hex<const N: usize>(bytes: &[u8; N]) -> String {
    let mut output = String::with_capacity(N * 2);
    for byte in bytes {
        output.push(nibble_hex(byte >> 4));
        output.push(nibble_hex(byte & 0x0f));
    }
    output
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn nibble_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("nibble value is always <= 15"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_hex_accepts_lowercase_and_uppercase() {
        assert_eq!(
            parse_fixed_hex::<4>("00aF10BC").expect("valid hex"),
            [0x00, 0xaf, 0x10, 0xbc]
        );
    }

    #[test]
    fn fixed_hex_rejects_wrong_lengths_and_invalid_digits() {
        assert_eq!(
            parse_fixed_hex::<2>("000").expect_err("wrong length"),
            "expected exactly 4 hex characters"
        );
        assert_eq!(
            parse_fixed_hex::<2>("0g00").expect_err("invalid digit"),
            "invalid hex character at byte 1"
        );
    }

    #[test]
    fn hyphenated_fixed_hex_strips_hyphens_before_parsing() {
        assert_eq!(
            parse_hyphenated_fixed_hex::<4>("00-af-10-bc", "bad length").expect("valid hex"),
            [0x00, 0xaf, 0x10, 0xbc]
        );
        assert_eq!(
            parse_hyphenated_fixed_hex::<4>("00-af-10", "bad length")
                .expect_err("wrong length"),
            "bad length"
        );
    }

    #[test]
    fn lower_hex_formats_lowercase() {
        assert_eq!(lower_hex(&[0x00, 0xaf, 0x10, 0xbc]), "00af10bc");
    }
}
