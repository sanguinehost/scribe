use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use rand::rngs::OsRng; // Corrected import for TryRngCore
// Removed unused rand::RngCore
use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::error::Unspecified as RingUnspecifiedError;
use secrecy::{ExposeSecret, SecretBox, SecretString}; // Removed SecretVec
use thiserror::Error;
// Removed unused argon2 imports: Config as Argon2Config, Variant, ThreadMode
// The necessary Argon2 items (Algorithm, Argon2, Params, Version) are imported on line 1.
use std::string::FromUtf8Error;
use tracing::error; // Import FromUtf8Error
// Removed duplicate/unused secrecy imports and rand::RngCore from lines 16-17
// Secrecy items like ExposeSecret, SecretBox are already imported on line 5.
// SecretVec is not used; Secret<Vec<u8>> is achieved via SecretBox::new(Box::new(vec_u8)).

const SALT_LEN: usize = 16; // 16 bytes for salt
const DEK_LEN: usize = 32; // 32 bytes for AES-256 DEK
const NONCE_LEN: usize = aead::NONCE_LEN; // Standard 12 bytes for AES-GCM from ring::aead

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Argon2 hashing error: {0}")]
    Argon2Error(#[from] argon2::Error),
    #[error("Random number generation error: {0}")]
    RandError(String),
    #[error("Ring AEAD unspecified error: {0}")]
    RingAeadError(RingUnspecifiedError), // Removed #[from]
    #[error("Base64 decoding error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Ciphertext too short (missing nonce or data)")]
    CiphertextTooShort,
    #[error("Invalid key length provided (must be 32 bytes for AES-256-GCM)")]
    InvalidKeyLength,
    #[error("Decryption failed (authentication tag mismatch or other unspecified AEAD error)")]
    DecryptionFailed, // More specific than just RingAeadError for decryption
    #[error("AES-GCM error: {0}")]
    AesGcmError(String),
    #[error("UTF-8 conversion error: {0}")]
    Utf8ConversionError(#[from] FromUtf8Error),
}

/// Generates a cryptographically secure random salt.
pub fn generate_salt() -> Result<String, CryptoError> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| CryptoError::RandError(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(&salt))
}

/// Generates a cryptographically secure random Data Encryption Key (DEK).
fn generate_dek_bytes() -> Result<Vec<u8>, CryptoError> {
    let mut dek_bytes = vec![0u8; DEK_LEN];
    OsRng
        .try_fill_bytes(&mut dek_bytes)
        .map_err(|e| CryptoError::RandError(e.to_string()))?;
    Ok(dek_bytes)
}

/// Generates a cryptographically secure random Data Encryption Key (DEK) wrapped in `SecretBox`.
pub fn generate_dek() -> Result<SecretBox<Vec<u8>>, CryptoError> {
    let dek_bytes = generate_dek_bytes()?;
    Ok(SecretBox::new(Box::new(dek_bytes)))
}

/// Public version of `generate_dek` for use in other modules.
pub fn crypto_generate_dek() -> Result<SecretBox<Vec<u8>>, CryptoError> {
    generate_dek()
}

/// Derives a Key Encryption Key (KEK) from a password and salt using Argon2id.
/// The output key length will be `DEK_LEN` (32 bytes for AES-256).
pub fn derive_kek(
    password: &SecretString,
    salt_str: &str,
) -> Result<SecretBox<Vec<u8>>, CryptoError> {
    // Changed KEK to Vec<u8> for consistency if it's also a key
    let password_bytes = password.expose_secret().as_bytes();
    let salt_bytes = URL_SAFE_NO_PAD.decode(salt_str)?;

    // Argon2id configuration
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13;

    let mem_cost = 65536; // 64MB previously; argon2 crate default is 19456 (19MiB)
    let time_cost = 3; // argon2 crate default is 2
    let lanes = 4; // argon2 crate default is 1
    // Per password-hash crate (which argon2 uses), default output length is 32 bytes.
    // If DEK_LEN is not 32, we might need to specify it.
    // For now, assuming DEK_LEN is 32, so we can use argon2 defaults for output or specify explicitly.
    let hash_length = DEK_LEN;

    let params = Params::new(mem_cost, time_cost, lanes, Some(hash_length))?;
    let argon2_context = Argon2::new(algorithm, version, params);

    let mut kek_bytes = vec![0u8; DEK_LEN];
    argon2_context.hash_password_into(password_bytes, &salt_bytes, &mut kek_bytes)?;

    Ok(SecretBox::new(Box::new(kek_bytes)))
}

/// Encrypts plaintext using AES-256-GCM with the given key.
/// Returns the ciphertext and the generated nonce separately.
/// Key material must be 32 bytes.
pub fn encrypt_gcm(
    plaintext: &[u8],
    key_material: &SecretBox<Vec<u8>>, // Reverted key_material type
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Returns (ciphertext, nonce_bytes)
    let exposed_key_slice = key_material.expose_secret(); // Single expose
    if exposed_key_slice.len() != DEK_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, exposed_key_slice).map_err(CryptoError::RingAeadError)?;
    let key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes_arr = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes_arr)
        .map_err(|e| CryptoError::RandError(e.to_string()))?;
    // Nonce does not need to be secret, but must be unique for each encryption with the same key.
    let nonce = Nonce::assume_unique_for_key(nonce_bytes_arr);

    // Encryption: ring's seal_in_place_append_tag operates on a mutable buffer
    // that initially contains the plaintext and appends the tag to it.
    let mut buffer = plaintext.to_vec(); // Copy plaintext to a mutable buffer
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer) // Added nonce argument
        .map_err(CryptoError::RingAeadError)?; // Manual mapping

    Ok((buffer, nonce_bytes_arr.to_vec())) // Return ciphertext and nonce_bytes separately
}

/// Decrypts ciphertext using AES-256-GCM with the given key and nonce.
/// Key material must be 32 bytes. Nonce must be 12 bytes.
pub fn decrypt_gcm(
    ciphertext: &[u8],                 // Ciphertext + tag
    nonce_bytes: &[u8],                // Separate nonce
    key_material: &SecretBox<Vec<u8>>, // Reverted key_material type
) -> Result<SecretBox<Vec<u8>>, CryptoError> {
    // Reverted return type
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::RandError("Invalid nonce length".into()));
    }
    if ciphertext.len() < AES_256_GCM.tag_len() {
        return Err(CryptoError::CiphertextTooShort);
    }
    let exposed_key_slice = key_material.expose_secret(); // Single expose
    if exposed_key_slice.len() != DEK_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, exposed_key_slice).map_err(CryptoError::RingAeadError)?;
    let key = LessSafeKey::new(unbound_key);

    let nonce_array: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::RandError("Nonce slice to array conversion failed".into()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_array);

    let mut buffer = ciphertext.to_vec();
    let plaintext_bytes_slice = key
        .open_in_place(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(SecretBox::new(Box::new(plaintext_bytes_slice.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();
        assert_ne!(salt1, salt2);
        assert!(!salt1.is_empty());
        // Check if it's valid base64 URL safe
        assert!(URL_SAFE_NO_PAD.decode(&salt1).is_ok());
    }

    #[test]
    fn test_generate_dek() {
        let dek1 = generate_dek().unwrap();
        let dek2 = generate_dek().unwrap();
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());
        assert_eq!(dek1.expose_secret().len(), DEK_LEN);
    }

    #[test]
    fn test_derive_kek() {
        let password = SecretString::from("test_password".to_string());
        let salt = generate_salt().unwrap();

        let kek1 = derive_kek(&password, &salt).unwrap();
        assert_eq!(kek1.expose_secret().len(), DEK_LEN);

        // Same password, same salt should produce same KEK
        let kek2 = derive_kek(&password, &salt).unwrap();
        assert_eq!(kek1.expose_secret(), kek2.expose_secret());

        // Different salt should produce different KEK
        let salt2 = generate_salt().unwrap();
        let kek3 = derive_kek(&password, &salt2).unwrap();
        assert_ne!(kek1.expose_secret(), kek3.expose_secret());

        // Different password should produce different KEK
        let password2 = SecretString::from("another_password".to_string());
        let kek4 = derive_kek(&password2, &salt).unwrap();
        assert_ne!(kek1.expose_secret(), kek4.expose_secret());
    }

    #[test]
    fn test_derive_kek_invalid_salt_format() {
        let password = SecretString::from("test_password_for_invalid_salt".to_string());
        // This salt contains characters not in the URL_SAFE_NO_PAD alphabet (e.g., '!')
        // and is also not the correct padding.
        let invalid_salt_str = "invalid-salt-string!";

        let result = derive_kek(&password, invalid_salt_str);

        match result {
            Err(CryptoError::Base64DecodeError(_)) => {
                // This is the expected error path for a salt that fails base64 decoding.
            }
            Ok(secret_val) => panic!(
                "Expected CryptoError::Base64DecodeError for invalid salt, got Ok({:?})",
                secret_val.expose_secret() // Expose for test display if absolutely needed, or just indicate Ok type
            ),
            Err(e) => panic!("Expected CryptoError::Base64DecodeError for invalid salt, got Err({e:?})"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_gcm_empty() {
        let key_material = generate_dek().unwrap();
        let plaintext = b"";

        let (ciphertext, nonce) = encrypt_gcm(plaintext, &key_material).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AES_256_GCM.tag_len());
        assert_eq!(nonce.len(), NONCE_LEN);

        let decrypted_secret_box_vec = decrypt_gcm(&ciphertext, &nonce, &key_material).unwrap();
        assert_eq!(
            decrypted_secret_box_vec.expose_secret().as_slice(),
            plaintext
        );
    }

    #[test]
    fn test_encrypt_decrypt_gcm_simple() {
        let key_material = generate_dek().unwrap();
        let plaintext = b"Hello, world!";

        let (ciphertext, nonce) = encrypt_gcm(plaintext, &key_material).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AES_256_GCM.tag_len());
        assert_eq!(nonce.len(), NONCE_LEN);

        let decrypted_secret_box_vec = decrypt_gcm(&ciphertext, &nonce, &key_material).unwrap();
        assert_eq!(
            decrypted_secret_box_vec.expose_secret().as_slice(),
            plaintext
        );
    }

    #[test]
    fn test_decrypt_gcm_tampered_ciphertext() {
        let key_material = generate_dek().unwrap();
        let plaintext = b"Important data";
        let (mut ciphertext, nonce) = encrypt_gcm(plaintext, &key_material).unwrap();

        // Tamper with the ciphertext portion by corrupting first byte
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        let result = decrypt_gcm(&ciphertext, &nonce, &key_material);
        match result {
            Err(CryptoError::DecryptionFailed) => { /* Test passes */ }
            Ok(_) => {
                panic!("Expected DecryptionFailed for tampered ciphertext, got Ok(<secret data>)")
            }
            Err(e) => panic!("Expected DecryptionFailed for tampered ciphertext, got Err({e:?})"),
        }
    }

    #[test]
    fn test_decrypt_gcm_tampered_nonce() {
        let key_material = generate_dek().unwrap();
        let plaintext = b"Another message";
        let (ciphertext, mut nonce) = encrypt_gcm(plaintext, &key_material).unwrap();

        // Tamper with the nonce
        if !nonce.is_empty() {
            nonce[0] ^= 0x01;
        }

        let result = decrypt_gcm(&ciphertext, &nonce, &key_material);
        match result {
            Err(CryptoError::DecryptionFailed) => { /* Test passes */ }
            Ok(_) => panic!("Expected DecryptionFailed for tampered nonce, got Ok(<secret data>)"),
            Err(e) => panic!("Expected DecryptionFailed for tampered nonce, got Err({e:?})"),
        }
    }

    #[test]
    fn test_decrypt_gcm_wrong_key() {
        let key_material1 = generate_dek().unwrap();
        let key_material2 = generate_dek().unwrap(); // Different key
        let plaintext = b"Secret message";

        let (ciphertext, nonce) = encrypt_gcm(plaintext, &key_material1).unwrap();
        let result = decrypt_gcm(&ciphertext, &nonce, &key_material2);
        match result {
            Err(CryptoError::DecryptionFailed) => { /* Test passes */ }
            Ok(_) => panic!("Expected DecryptionFailed for wrong key, got Ok(<secret data>)"),
            Err(e) => panic!("Expected DecryptionFailed for wrong key, got Err({e:?})"),
        }
    }

    #[test]
    fn test_decrypt_gcm_ciphertext_too_short() {
        let key_material = generate_dek().unwrap();
        let short_ciphertext = vec![1, 2, 3]; // Shorter than TAG_LEN
        let nonce_bytes = vec![0u8; NONCE_LEN]; // A valid nonce
        let result = decrypt_gcm(&short_ciphertext, &nonce_bytes, &key_material);
        assert!(matches!(result, Err(CryptoError::CiphertextTooShort)));
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let short_key_vec: Vec<u8> = vec![0; 16];
        let short_key = SecretBox::new(Box::new(short_key_vec));
        let plaintext = b"test";
        let result = encrypt_gcm(plaintext, &short_key);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let short_key_vec: Vec<u8> = vec![0; 16];
        let short_key = SecretBox::new(Box::new(short_key_vec));
        let ciphertext = vec![0u8; AES_256_GCM.tag_len() + 5];
        let nonce_bytes = vec![0u8; NONCE_LEN];
        let result = decrypt_gcm(&ciphertext, &nonce_bytes, &short_key);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));
    }

    #[test]
    fn test_encrypt_gcm_invalid_key_material() {
        let mut key_bytes = vec![0u8; DEK_LEN - 1];
        OsRng.try_fill_bytes(&mut key_bytes).unwrap();
        let key_material = SecretBox::new(Box::new(key_bytes));
        let plaintext = b"test data";

        let result = encrypt_gcm(plaintext, &key_material);
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyLength)),
            "Expected InvalidKeyLength for short key material during encryption, got {result:?}"
        );
    }

    #[test]
    fn test_decrypt_gcm_invalid_key_material() {
        let key_material_valid = generate_dek().unwrap();
        let plaintext = b"test data";
        let (ciphertext, nonce) = encrypt_gcm(plaintext, &key_material_valid).unwrap();

        let mut invalid_key_bytes = key_material_valid.expose_secret().clone();
        invalid_key_bytes.pop();
        let key_material_invalid = SecretBox::new(Box::new(invalid_key_bytes));

        let result = decrypt_gcm(&ciphertext, &nonce, &key_material_invalid);
        let is_match = matches!(result, Err(CryptoError::InvalidKeyLength));
        assert!(
            is_match,
            "Expected InvalidKeyLength for short key material during decryption, got {}",
            match &result {
                Ok(_) => "Ok(<secret data>)".to_string(), // Avoid exposing secret in logs
                Err(e) => format!("Err({e:?})"),
            }
        );
    }

    #[test]
    fn test_decrypt_gcm_invalid_nonce() {
        let key_material = generate_dek().unwrap();
        let plaintext = b"test data";
        // Encrypt once to get a valid ciphertext, though we won't use its nonce for decryption here
        let (ciphertext, _original_nonce) = encrypt_gcm(plaintext, &key_material).unwrap();

        let mut invalid_nonce_bytes = vec![0u8; NONCE_LEN - 1]; // Nonce too short
        OsRng.try_fill_bytes(&mut invalid_nonce_bytes).unwrap();

        let result = decrypt_gcm(&ciphertext, &invalid_nonce_bytes, &key_material);
        // Use `ref s` in the pattern to borrow s instead of moving it.
        let is_match =
            matches!(result, Err(CryptoError::RandError(ref s)) if s == "Invalid nonce length");
        assert!(
            is_match,
            // Updated assertion message to not print `result` directly, avoiding borrow issues.
            "Expected RandError(\"Invalid nonce length\") for invalid nonce during decryption, but a different error or Ok was returned."
        );
    }
}
