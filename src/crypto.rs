use pgp::composed::key::SecretKeyParamsBuilder;
use pgp::composed::message::Message;
use pgp::composed::{KeyType, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{mpi, PublicKeyTrait, SecretKeyTrait, SignatureBytes};
use pgp::Deserializable;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    KeyGen(String),
    #[error("serialization failed: {0}")]
    Serialize(String),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("decrypted payload did not contain literal data")]
    MissingLiteralData,
}

/// A generated PGP identity keypair for DecentraChat.
pub struct KeyPair {
    pub secret: SignedSecretKey,
    pub public: SignedPublicKey,
}

impl KeyPair {
    /// Generate an unsigned-passphrase RSA keypair suitable for message signing.
    pub fn generate() -> Result<Self, CryptoError> {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .can_encrypt(true)
            .primary_user_id("decentra-chat".into())
            .preferred_hash_algorithms(vec![HashAlgorithm::SHA2_256].into())
            .preferred_symmetric_algorithms(vec![SymmetricKeyAlgorithm::AES256].into())
            .build()
            .map_err(|e| CryptoError::KeyGen(e.to_string()))?;

        let mut rng = rand::thread_rng();
        let secret = params
            .generate(&mut rng)
            .map_err(|e| CryptoError::KeyGen(e.to_string()))?
            .sign(&mut rng, || String::new())
            .map_err(|e| CryptoError::KeyGen(e.to_string()))?;
        let public = secret.clone().into();

        Ok(Self { secret, public })
    }
}

/// Serialize a public key to raw bytes for wire transmission and fingerprinting.
pub fn public_key_to_bytes(key: &SignedPublicKey) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    key.to_writer(&mut bytes)
        .map_err(|e| CryptoError::Serialize(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize a public key from raw bytes.
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<SignedPublicKey, CryptoError> {
    SignedPublicKey::from_bytes(bytes).map_err(|e| CryptoError::Deserialize(e.to_string()))
}

/// Serialize a secret key to raw bytes for local CLI identity files.
pub fn secret_key_to_bytes(key: &SignedSecretKey) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    key.to_writer(&mut bytes)
        .map_err(|e| CryptoError::Serialize(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize a local secret key from raw bytes.
pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SignedSecretKey, CryptoError> {
    SignedSecretKey::from_bytes(bytes).map_err(|e| CryptoError::Deserialize(e.to_string()))
}

/// DC fingerprint: SHA256(serialized_pub_key_bytes) -> fixed 32-byte array.
pub fn fingerprint(pub_key_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(pub_key_bytes).into()
}

/// Sign arbitrary bytes with the secret key and return a detached signature blob.
///
/// The blob is a compact DecentraChat wrapper around rpgp's `SignatureBytes`:
/// `1 | mpi_count | mpi...` for MPI signatures and `2 | len | bytes` for
/// native signatures. Verification rejects malformed or trailing data.
pub fn sign(key: &SignedSecretKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = key
        .create_signature(|| String::new(), HashAlgorithm::SHA2_256, data)
        .map_err(|e| CryptoError::Sign(e.to_string()))?;

    match signature {
        SignatureBytes::Mpis(values) => {
            let count = u8::try_from(values.len()).map_err(|_| {
                CryptoError::Serialize("signature contains too many MPI values".into())
            })?;
            let mut bytes = vec![1, count];
            for value in values {
                value
                    .to_writer(&mut bytes)
                    .map_err(|e| CryptoError::Serialize(e.to_string()))?;
            }
            Ok(bytes)
        }
        SignatureBytes::Native(value) => {
            let len = u32::try_from(value.len())
                .map_err(|_| CryptoError::Serialize("signature is too large".into()))?;
            let mut bytes = vec![2];
            bytes.extend(len.to_be_bytes());
            bytes.extend(value);
            Ok(bytes)
        }
    }
}

/// Verify a detached signature against a public key and message bytes.
pub fn verify(
    key: &SignedPublicKey,
    data: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let signature = match signature {
        [1, count, body @ ..] => {
            let mut body = body;
            let mut values = Vec::with_capacity(*count as usize);
            for _ in 0..*count {
                let (remaining, value) = mpi(body).map_err(|_| CryptoError::BadSignature)?;
                values.push(value.to_owned());
                body = remaining;
            }
            if !body.is_empty() {
                return Err(CryptoError::BadSignature);
            }
            SignatureBytes::Mpis(values)
        }
        [2, len @ ..] => {
            let (len_bytes, body) = len.split_at_checked(4).ok_or(CryptoError::BadSignature)?;
            let len = u32::from_be_bytes(
                len_bytes
                    .try_into()
                    .map_err(|_| CryptoError::BadSignature)?,
            ) as usize;
            if body.len() != len {
                return Err(CryptoError::BadSignature);
            }
            SignatureBytes::Native(body.to_vec())
        }
        _ => return Err(CryptoError::BadSignature),
    };

    key.verify_signature(HashAlgorithm::SHA2_256, data, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Encrypt payload bytes as an OpenPGP literal message for one peer public key.
pub fn encrypt_for_peer(
    key: &SignedPublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let literal = Message::new_literal_bytes("", plaintext);
    let encrypted = literal
        .encrypt_to_keys_seipdv1(rand::thread_rng(), SymmetricKeyAlgorithm::AES256, &[key])
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    encrypted
        .to_bytes()
        .map_err(|e| CryptoError::Serialize(e.to_string()))
}

/// Decrypt an OpenPGP-encrypted literal message with the local secret key.
pub fn decrypt_from_peer(
    key: &SignedSecretKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let encrypted =
        Message::from_bytes(ciphertext).map_err(|e| CryptoError::Deserialize(e.to_string()))?;
    let (decrypted, _) = encrypted
        .decrypt(|| String::new(), &[key])
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    decrypted
        .get_content()
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?
        .ok_or(CryptoError::MissingLiteralData)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"hello decentra-chat";

    #[test]
    fn generated_keypair_signs_and_verifies() {
        let keypair = KeyPair::generate().unwrap();
        let signature = sign(&keypair.secret, MESSAGE).unwrap();

        verify(&keypair.public, MESSAGE, &signature).unwrap();
    }

    #[test]
    fn signature_does_not_verify_with_different_key() {
        let signer = KeyPair::generate().unwrap();
        let verifier = KeyPair::generate().unwrap();
        let signature = sign(&signer.secret, MESSAGE).unwrap();

        assert!(matches!(
            verify(&verifier.public, MESSAGE, &signature),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let keypair = KeyPair::generate().unwrap();
        let bytes = public_key_to_bytes(&keypair.public).unwrap();

        assert_eq!(fingerprint(&bytes), fingerprint(&bytes));
    }

    #[test]
    fn imported_public_key_has_expected_fingerprint() {
        let keypair = KeyPair::generate().unwrap();
        let bytes = public_key_to_bytes(&keypair.public).unwrap();
        let expected = fingerprint(&bytes);

        let imported = public_key_from_bytes(&bytes).unwrap();
        let imported_bytes = public_key_to_bytes(&imported).unwrap();

        assert_eq!(fingerprint(&imported_bytes), expected);
    }

    #[test]
    fn tampered_message_returns_bad_signature() {
        let keypair = KeyPair::generate().unwrap();
        let signature = sign(&keypair.secret, MESSAGE).unwrap();
        let mut tampered = MESSAGE.to_vec();
        tampered[0] ^= 0xff;

        assert!(matches!(
            verify(&keypair.public, &tampered, &signature),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn payload_encrypts_and_decrypts_with_generated_keypair() {
        let keypair = KeyPair::generate().unwrap();
        let encrypted = encrypt_for_peer(&keypair.public, MESSAGE).unwrap();

        assert_ne!(encrypted, MESSAGE);
        assert_eq!(decrypt_from_peer(&keypair.secret, &encrypted).unwrap(), MESSAGE);
    }
}
