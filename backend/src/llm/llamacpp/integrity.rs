// backend/src/llm/llamacpp/integrity.rs
// Model file integrity verification and secure download management

use crate::llm::llamacpp::{SecurityAuditLogger, SecurityEventType};
use super::LocalLlmError;
use crate::errors::AppError;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, BufRead, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// Model integrity verification error types
#[derive(thiserror::Error, Debug)]
pub enum IntegrityError {
    #[error("Model file not found: {path}")]
    ModelNotFound { path: String },
    
    #[error("Checksum mismatch for {model_id}: expected {expected}, got {actual}")]
    ChecksumMismatch { model_id: String, expected: String, actual: String },
    
    #[error("Model signature verification failed: {reason}")]
    SignatureVerificationFailed { reason: String },
    
    #[error("Model metadata corruption: {reason}")]
    MetadataCorruption { reason: String },
    
    #[error("Untrusted model source: {0}")]
    UntrustedSource(String),
    
    #[error("Model file corruption detected: {details}")]
    FileCorruption { details: String },
    
    #[error("IO error during verification")]
    IoError(#[from] std::io::Error),
}

impl From<IntegrityError> for LocalLlmError {
    fn from(err: IntegrityError) -> Self {
        LocalLlmError::SecurityViolation(err.to_string())
    }
}

impl From<IntegrityError> for AppError {
    fn from(err: IntegrityError) -> Self {
        AppError::BadRequest(err.to_string())
    }
}

/// Model metadata and integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub model_id: String,
    pub name: String,
    pub version: String,
    pub file_path: String,
    pub file_size: u64,
    pub sha256_hash: String,
    pub download_url: String,
    pub trusted_source: bool,
    pub signature: Option<String>,
    pub verification_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub quarantine_status: QuarantineStatus,
    pub verification_history: Vec<VerificationRecord>,
}

/// Model quarantine status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuarantineStatus {
    Clean,      // Verified and safe
    Suspicious, // Requires additional verification
    Quarantined, // Isolated, not safe to use
    Unknown,    // Not yet verified
}

/// Verification record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub verification_type: VerificationType,
    pub result: VerificationResult,
    pub details: String,
    pub verifier_version: String,
}

/// Types of verification performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationType {
    ChecksumVerification,
    SignatureVerification,
    SourceVerification,
    FileStructureCheck,
    MalwareScanning,
    MetadataValidation,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationResult {
    Passed,
    Failed(String),
    Warning(String),
}

/// Trusted model sources configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedSources {
    pub domains: Vec<String>,
    pub checksums: HashMap<String, String>, // model_id -> expected_hash
    pub signatures: HashMap<String, String>, // model_id -> signature
}

impl Default for TrustedSources {
    fn default() -> Self {
        Self {
            domains: vec![
                "huggingface.co".to_string(),
                "github.com".to_string(),
                "releases.llama.cpp".to_string(),
            ],
            checksums: HashMap::new(),
            signatures: HashMap::new(),
        }
    }
}

/// Model integrity verifier
#[derive(Debug)]
pub struct ModelIntegrityVerifier {
    trusted_sources: TrustedSources,
    audit_logger: Option<SecurityAuditLogger>,
    strict_mode: bool,
}

impl ModelIntegrityVerifier {
    /// Create a new integrity verifier
    pub fn new(trusted_sources: Option<TrustedSources>) -> Self {
        Self {
            trusted_sources: trusted_sources.unwrap_or_default(),
            audit_logger: None,
            strict_mode: true,
        }
    }

    /// Create verifier with audit logging
    pub fn with_audit_logger(mut self, logger: SecurityAuditLogger) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Set strict mode (fail on any security concern)
    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Verify model file integrity
    pub async fn verify_model(&self, model_path: &Path, metadata: &mut ModelMetadata) -> Result<(), IntegrityError> {
        info!("Starting integrity verification for model: {}", metadata.model_id);
        
        let mut verification_record = VerificationRecord {
            timestamp: chrono::Utc::now(),
            verification_type: VerificationType::ChecksumVerification,
            result: VerificationResult::Passed,
            details: String::new(),
            verifier_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        // Verify file exists and is readable
        if !model_path.exists() {
            let error = IntegrityError::ModelNotFound { 
                path: model_path.display().to_string() 
            };
            self.log_security_event(&metadata.model_id, SecurityEventType::IntegrityCheckFailed, &error.to_string());
            return Err(error);
        }

        // Verify checksum
        match self.verify_checksum(model_path, metadata).await {
            Ok(_) => {
                info!("Checksum verification passed for model: {}", metadata.model_id);
            }
            Err(e) => {
                verification_record.result = VerificationResult::Failed(e.to_string());
                metadata.verification_history.push(verification_record);
                return Err(e);
            }
        }

        // Verify source trustworthiness
        if let Err(e) = self.verify_source_trust(metadata) {
            if self.strict_mode {
                verification_record.result = VerificationResult::Failed(e.to_string());
                metadata.verification_history.push(verification_record);
                return Err(e);
            } else {
                warn!("Source verification failed but continuing in non-strict mode: {}", e);
                verification_record.result = VerificationResult::Warning(e.to_string());
            }
        }

        // Verify file structure (basic GGUF format check)
        if let Err(e) = self.verify_file_structure(model_path, metadata) {
            if self.strict_mode {
                verification_record.result = VerificationResult::Failed(e.to_string());
                metadata.verification_history.push(verification_record);
                return Err(e);
            } else {
                warn!("File structure verification failed but continuing: {}", e);
                verification_record.result = VerificationResult::Warning(e.to_string());
            }
        }

        // Update metadata with verification results
        metadata.verification_timestamp = Some(chrono::Utc::now());
        metadata.quarantine_status = QuarantineStatus::Clean;
        
        verification_record.details = "Full integrity verification completed successfully".to_string();
        metadata.verification_history.push(verification_record);

        info!("Integrity verification completed successfully for model: {}", metadata.model_id);
        Ok(())
    }

    /// Verify file checksum
    async fn verify_checksum(&self, model_path: &Path, metadata: &ModelMetadata) -> Result<(), IntegrityError> {
        debug!("Computing SHA256 checksum for: {}", model_path.display());
        
        let mut file = File::open(model_path)
?;

        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192]; // 8KB buffer for streaming hash computation

        loop {
            let bytes_read = file.read(&mut buffer)
    ?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }

        let computed_hash = format!("{:x}", hasher.finalize());
        
        // Check against expected hash if available
        if !metadata.sha256_hash.is_empty() {
            if computed_hash != metadata.sha256_hash {
                let error = IntegrityError::ChecksumMismatch {
                    model_id: metadata.model_id.clone(),
                    expected: metadata.sha256_hash.clone(),
                    actual: computed_hash,
                };
                self.log_security_event(&metadata.model_id, SecurityEventType::IntegrityCheckFailed, &error.to_string());
                return Err(error);
            }
        }

        // Check against trusted sources registry
        if let Some(expected_hash) = self.trusted_sources.checksums.get(&metadata.model_id) {
            if &computed_hash != expected_hash {
                let error = IntegrityError::ChecksumMismatch {
                    model_id: metadata.model_id.clone(),
                    expected: expected_hash.clone(),
                    actual: computed_hash,
                };
                self.log_security_event(&metadata.model_id, SecurityEventType::IntegrityCheckFailed, &error.to_string());
                return Err(error);
            }
        }

        debug!("Checksum verification passed: {}", computed_hash);
        Ok(())
    }

    /// Verify source trustworthiness
    fn verify_source_trust(&self, metadata: &ModelMetadata) -> Result<(), IntegrityError> {
        // Parse URL to check domain
        if let Ok(url) = url::Url::parse(&metadata.download_url) {
            if let Some(host) = url.host_str() {
                let is_trusted = self.trusted_sources.domains.iter()
                    .any(|domain| host.contains(domain));
                
                if !is_trusted {
                    let error = IntegrityError::UntrustedSource(host.to_string());
                    self.log_security_event(&metadata.model_id, SecurityEventType::ModelTampering, &error.to_string());
                    return Err(error);
                }
            }
        }
        
        Ok(())
    }

    /// Verify GGUF file structure
    fn verify_file_structure(&self, model_path: &Path, metadata: &ModelMetadata) -> Result<(), IntegrityError> {
        let mut file = File::open(model_path)
?;

        // Check GGUF magic number (first 4 bytes should be "GGUF")
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)
            .map_err(|e| IntegrityError::FileCorruption { 
                details: format!("Could not read magic number: {}", e) 
            })?;

        if &magic != b"GGUF" {
            let error = IntegrityError::FileCorruption {
                details: "Invalid GGUF magic number".to_string(),
            };
            self.log_security_event(&metadata.model_id, SecurityEventType::ModelTampering, &error.to_string());
            return Err(error);
        }

        // Additional structure checks could be added here
        // For now, we just verify the magic number
        
        debug!("File structure verification passed for GGUF format");
        Ok(())
    }

    /// Log security event if logger is available
    fn log_security_event(&self, model_id: &str, event_type: SecurityEventType, details: &str) {
        if let Some(ref logger) = self.audit_logger {
            let event = super::SecurityEvent::new(
                event_type.clone(),
                event_type.default_severity(),
                "/api/llm/models".to_string(),
                "POST".to_string(),
                format!("Model integrity issue: {}", details),
            )
            .with_detail("model_id", model_id)
            .with_detail("details", details);
            
            logger.log_event(event);
        }
    }

    /// Quarantine a suspicious model
    pub fn quarantine_model(&self, metadata: &mut ModelMetadata, reason: &str) -> Result<(), IntegrityError> {
        warn!("Quarantining model {}: {}", metadata.model_id, reason);
        
        metadata.quarantine_status = QuarantineStatus::Quarantined;
        
        let verification_record = VerificationRecord {
            timestamp: chrono::Utc::now(),
            verification_type: VerificationType::MalwareScanning,
            result: VerificationResult::Failed(reason.to_string()),
            details: format!("Model quarantined: {}", reason),
            verifier_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        
        metadata.verification_history.push(verification_record);
        
        self.log_security_event(&metadata.model_id, SecurityEventType::ModelTampering, reason);
        
        Ok(())
    }

    /// Check if model is safe to use
    pub fn is_model_safe(&self, metadata: &ModelMetadata) -> bool {
        match metadata.quarantine_status {
            QuarantineStatus::Clean => true,
            QuarantineStatus::Suspicious => !self.strict_mode, // Allow in non-strict mode
            QuarantineStatus::Quarantined => false,
            QuarantineStatus::Unknown => false,
        }
    }
}

/// Model registry with integrity tracking
#[derive(Debug)]
pub struct SecureModelRegistry {
    models: HashMap<String, ModelMetadata>,
    verifier: ModelIntegrityVerifier,
    registry_path: PathBuf,
}

impl SecureModelRegistry {
    /// Create new secure model registry
    pub fn new<P: AsRef<Path>>(registry_path: P, verifier: ModelIntegrityVerifier) -> Self {
        Self {
            models: HashMap::new(),
            verifier,
            registry_path: registry_path.as_ref().to_path_buf(),
        }
    }

    /// Load registry from disk
    pub fn load(&mut self) -> Result<(), IntegrityError> {
        if self.registry_path.exists() {
            let file = File::open(&self.registry_path)
    ?;
            
            let reader = BufReader::new(file);
            self.models = serde_json::from_reader(reader)
                .map_err(|e| IntegrityError::MetadataCorruption { 
                    reason: format!("Failed to parse registry: {}", e) 
                })?;
            
            info!("Loaded {} models from registry", self.models.len());
        }
        Ok(())
    }

    /// Save registry to disk
    pub fn save(&self) -> Result<(), IntegrityError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.registry_path)
?;

        let json = serde_json::to_string_pretty(&self.models)
            .map_err(|e| IntegrityError::MetadataCorruption { 
                reason: format!("Failed to serialize registry: {}", e) 
            })?;

        file.write_all(json.as_bytes())
?;

        debug!("Saved model registry with {} entries", self.models.len());
        Ok(())
    }

    /// Register a new model
    pub async fn register_model(&mut self, mut metadata: ModelMetadata) -> Result<(), IntegrityError> {
        let model_path = Path::new(&metadata.file_path).to_owned();
        
        // Verify the model
        self.verifier.verify_model(&model_path, &mut metadata).await?;
        
        // Store in registry
        self.models.insert(metadata.model_id.clone(), metadata);
        
        // Save registry
        self.save()?;
        
        Ok(())
    }

    /// Get model metadata
    pub fn get_model(&self, model_id: &str) -> Option<&ModelMetadata> {
        self.models.get(model_id)
    }

    /// Get all safe models
    pub fn get_safe_models(&self) -> Vec<&ModelMetadata> {
        self.models
            .values()
            .filter(|metadata| self.verifier.is_model_safe(metadata))
            .collect()
    }

    /// Get quarantined models
    pub fn get_quarantined_models(&self) -> Vec<&ModelMetadata> {
        self.models
            .values()
            .filter(|metadata| metadata.quarantine_status == QuarantineStatus::Quarantined)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_checksum_verification() {
        let verifier = ModelIntegrityVerifier::new(None);
        
        // Create a temporary file with known content
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test content").unwrap();
        
        // Compute expected hash for "test content"
        let mut hasher = Sha256::new();
        hasher.update(b"test content");
        let expected_hash = format!("{:x}", hasher.finalize());
        
        let mut metadata = ModelMetadata {
            model_id: "test-model".to_string(),
            name: "Test Model".to_string(),
            version: "1.0".to_string(),
            file_path: temp_file.path().to_string_lossy().to_string(),
            file_size: 12,
            sha256_hash: expected_hash,
            download_url: "https://huggingface.co/test".to_string(),
            trusted_source: true,
            signature: None,
            verification_timestamp: None,
            quarantine_status: QuarantineStatus::Unknown,
            verification_history: Vec::new(),
        };
        
        // Should pass with correct hash
        assert!(verifier.verify_checksum(temp_file.path(), &metadata).await.is_ok());
        
        // Should fail with incorrect hash
        metadata.sha256_hash = "incorrect_hash".to_string();
        assert!(verifier.verify_checksum(temp_file.path(), &metadata).await.is_err());
    }

    #[test]
    fn test_source_trust_verification() {
        let verifier = ModelIntegrityVerifier::new(None);
        
        let trusted_metadata = ModelMetadata {
            model_id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0".to_string(),
            file_path: "".to_string(),
            file_size: 0,
            sha256_hash: "".to_string(),
            download_url: "https://huggingface.co/model".to_string(),
            trusted_source: true,
            signature: None,
            verification_timestamp: None,
            quarantine_status: QuarantineStatus::Unknown,
            verification_history: Vec::new(),
        };
        
        let untrusted_metadata = ModelMetadata {
            download_url: "https://suspicious-site.com/model".to_string(),
            ..trusted_metadata.clone()
        };
        
        assert!(verifier.verify_source_trust(&trusted_metadata).is_ok());
        assert!(verifier.verify_source_trust(&untrusted_metadata).is_err());
    }

    #[test]
    fn test_quarantine_status() {
        let verifier = ModelIntegrityVerifier::new(None).with_strict_mode(true);
        
        let clean_model = ModelMetadata {
            model_id: "clean".to_string(),
            name: "Clean Model".to_string(),
            version: "1.0".to_string(),
            file_path: "".to_string(),
            file_size: 0,
            sha256_hash: "".to_string(),
            download_url: "".to_string(),
            trusted_source: true,
            signature: None,
            verification_timestamp: None,
            quarantine_status: QuarantineStatus::Clean,
            verification_history: Vec::new(),
        };
        
        let quarantined_model = ModelMetadata {
            quarantine_status: QuarantineStatus::Quarantined,
            ..clean_model.clone()
        };
        
        assert!(verifier.is_model_safe(&clean_model));
        assert!(!verifier.is_model_safe(&quarantined_model));
    }
}