use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::DbId;
use crate::error::AppError;

/// JWT token claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: DbId,          // Subject (user ID)
    pub exp: i64,           // Expiration time (Unix timestamp)
    pub iat: i64,           // Issued at (Unix timestamp)
    pub token_type: String, // "access" or "refresh"
}

/// Token types for different purposes
#[derive(Debug, Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

impl TokenType {
    fn as_str(&self) -> &str {
        match self {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
        }
    }
}

/// Token pair returned on successful authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64, // seconds until access token expires
}

/// Service for managing JWT tokens
#[derive(Clone)]
pub struct TokenService {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    access_token_duration: Duration,
    refresh_token_duration: Duration,
}

impl TokenService {
    /// Create a new token service with the given secret
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: Arc::new(EncodingKey::from_secret(secret.as_bytes())),
            decoding_key: Arc::new(DecodingKey::from_secret(secret.as_bytes())),
            access_token_duration: Duration::minutes(15), // 15 minutes for access token
            refresh_token_duration: Duration::days(30),   // 30 days for refresh token
        }
    }

    /// Generate a new token pair for a user
    pub fn generate_token_pair(&self, user_id: DbId) -> Result<TokenPair, AppError> {
        let now = Utc::now();

        // Generate access token
        let access_claims = TokenClaims {
            sub: user_id,
            exp: (now + self.access_token_duration).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::Access.as_str().to_string(),
        };

        let access_token =
            encode(&Header::default(), &access_claims, &self.encoding_key).map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to generate access token: {}",
                    e
                ))
            })?;

        // Generate refresh token
        let refresh_claims = TokenClaims {
            sub: user_id,
            exp: (now + self.refresh_token_duration).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::Refresh.as_str().to_string(),
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to generate refresh token: {}",
                    e
                ))
            })?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_token_duration.num_seconds(),
        })
    }

    /// Validate a token and return its claims
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, AppError> {
        let validation = Validation::default();

        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::Unauthorized(format!("Invalid token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Refresh an access token using a refresh token
    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<String, AppError> {
        // Validate the refresh token
        let claims = self.validate_token(refresh_token)?;

        // Ensure it's a refresh token
        if claims.token_type != TokenType::Refresh.as_str() {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        // Generate new access token
        let now = Utc::now();
        let access_claims = TokenClaims {
            sub: claims.sub,
            exp: (now + self.access_token_duration).timestamp(),
            iat: now.timestamp(),
            token_type: TokenType::Access.as_str().to_string(),
        };

        let access_token =
            encode(&Header::default(), &access_claims, &self.encoding_key).map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to generate access token: {}",
                    e
                ))
            })?;

        Ok(access_token)
    }
}
