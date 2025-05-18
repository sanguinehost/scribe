use crate::crypto::encrypt_gcm;
use crate::errors::AppError;
use ring::aead;
use secrecy::{ExposeSecret, SecretBox};

const NONCE_LEN: usize = aead::NONCE_LEN;

pub struct EncryptionService;

impl EncryptionService {
    pub fn new() -> Self {
        Self
    }

    pub async fn encrypt(
        &self,
        plaintext: &str,
        key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        if key.len() != aead::AES_256_GCM.key_len() {
            return Err(AppError::EncryptionError(format!(
                "Invalid key length: expected {} bytes, got {}",
                aead::AES_256_GCM.key_len(),
                key.len()
            )));
        }
        let key_secret_box = SecretBox::new(Box::new(key.to_vec()));

        encrypt_gcm(plaintext.as_bytes(), &key_secret_box)
            .map_err(|e| AppError::EncryptionError(format!("Encryption failed: {}", e)))
    }

    pub async fn decrypt(
        &self,
        ciphertext_and_tag: &[u8],
        nonce_bytes: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        if key.len() != aead::AES_256_GCM.key_len() {
            return Err(AppError::DecryptionError(format!(
                "Invalid key length: expected {} bytes, got {}",
                aead::AES_256_GCM.key_len(),
                key.len()
            )));
        }

        if nonce_bytes.len() != NONCE_LEN {
            return Err(AppError::DecryptionError(format!(
                "Invalid nonce length: expected {} bytes, got {}",
                NONCE_LEN,
                nonce_bytes.len()
            )));
        }

        // Ciphertext_and_tag minimum length is TAG_LEN
        if ciphertext_and_tag.len() < aead::AES_256_GCM.tag_len() {
            return Err(AppError::DecryptionError(
                "Ciphertext too short to contain a tag".to_string(),
            ));
        }

        let key_secret_box = SecretBox::new(Box::new(key.to_vec()));

        match crate::crypto::decrypt_gcm(ciphertext_and_tag, nonce_bytes, &key_secret_box) {
            Ok(decrypted_secret_box_vec) => Ok(decrypted_secret_box_vec.expose_secret().to_vec()),
            Err(e) => {
                // Log the original error for debugging purposes if needed
                // tracing::error!("Decryption failed: {:?}", e);
                Err(AppError::DecryptionError(format!(
                    "Decryption failed: {}",
                    e
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::AppError;

    const TEST_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef"; // 32-byte key for AES-256

    #[tokio::test]
    async fn test_encrypt_decrypt_round_trip() {
        let service = EncryptionService::new();
        let plaintext = "This is a secret message.";

        let (encrypted_data, nonce) = service.encrypt(plaintext, TEST_KEY).await.unwrap();
        let decrypted_data_bytes = service
            .decrypt(&encrypted_data, &nonce, TEST_KEY)
            .await
            .unwrap();
        let decrypted_data = String::from_utf8(decrypted_data_bytes).unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[tokio::test]
    async fn test_decrypt_with_wrong_key_fails() {
        let service = EncryptionService::new();
        let plaintext = "Another secret.";
        let wrong_key = b"abcdef0123456789abcdef0123456789";

        let (encrypted_data, nonce) = service.encrypt(plaintext, TEST_KEY).await.unwrap();

        match service.decrypt(&encrypted_data, &nonce, wrong_key).await {
            Err(AppError::DecryptionError(_)) => { /* Expected */ }
            Ok(_) => panic!("Decryption should have failed with the wrong key."),
            Err(e) => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_encrypt_empty_string() {
        let service = EncryptionService::new();
        let plaintext = "";

        let (encrypted_data, nonce) = service.encrypt(plaintext, TEST_KEY).await.unwrap();
        let decrypted_data_bytes = service
            .decrypt(&encrypted_data, &nonce, TEST_KEY)
            .await
            .unwrap();
        let decrypted_data = String::from_utf8(decrypted_data_bytes).unwrap();

        assert_eq!(plaintext, decrypted_data);
        assert!(
            !encrypted_data.is_empty(),
            "Ciphertext (even for empty plaintext) should not be empty due to AEAD tag"
        );
        assert_eq!(nonce.len(), NONCE_LEN, "Nonce should have correct length");
    }

    // #[tokio::test]
    // async fn test_placeholder() {
    //     assert!(true);
    // }
}
