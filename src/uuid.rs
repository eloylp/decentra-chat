use rand::RngCore;

/// Generate a random non-zero UUID v4 byte array.
pub(crate) fn new_uuid_v4() -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

/// Return whether the byte array is a non-zero RFC 4122 UUID v4 value.
pub(crate) fn is_uuid_v4(bytes: &[u8; 16]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
        && bytes[6] & 0xf0 == 0x40
        && bytes[8] & 0xc0 == 0x80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_uuid_sets_version_and_variant_bits() {
        let uuid = new_uuid_v4();

        assert!(is_uuid_v4(&uuid));
        assert_eq!(uuid[6] & 0xf0, 0x40);
        assert_eq!(uuid[8] & 0xc0, 0x80);
    }

    #[test]
    fn uuid_v4_validation_rejects_zero_wrong_version_and_wrong_variant() {
        let zero = [0_u8; 16];
        assert!(!is_uuid_v4(&zero));

        let mut uuid = new_uuid_v4();
        uuid[6] = (uuid[6] & 0x0f) | 0x30;
        assert!(!is_uuid_v4(&uuid));

        let mut uuid = new_uuid_v4();
        uuid[8] &= 0x3f;
        assert!(!is_uuid_v4(&uuid));
    }
}
