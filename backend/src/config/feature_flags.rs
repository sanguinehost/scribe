// backend/src/config/feature_flags.rs
//
// Feature flags for controlling the transition from manual to agentic narrative extraction.
// This allows for gradual rollout and A/B testing of the new agentic system.

use serde::{Deserialize, Serialize};

/// Feature flags for controlling narrative extraction behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeFeatureFlags {
    /// Whether to enable the new agentic narrative system
    pub enable_agentic_extraction: bool,
    
    /// Whether to fall back to manual extraction if agentic fails
    pub fallback_to_manual_on_error: bool,
    
    /// Whether to run both systems and compare results (for testing/validation)
    pub dual_extraction_mode: bool,
    
    /// Whether to log extraction performance metrics
    pub enable_extraction_metrics: bool,
    
    /// Percentage of users to enable agentic extraction for (0-100)
    pub agentic_rollout_percentage: u8,
    
    /// User IDs to force enable agentic extraction for (for testing)
    pub force_enable_users: Vec<String>,
    
    /// User IDs to force disable agentic extraction for (for testing)
    pub force_disable_users: Vec<String>,
    
    /// Whether to enable real-time extraction during chat
    pub enable_realtime_extraction: bool,
    
    /// Whether to enable automatic lorebook entry creation
    pub enable_auto_lorebook_creation: bool,
    
    /// Whether to enable automatic chronicle creation
    pub enable_auto_chronicle_creation: bool,
    
    /// Maximum number of AI calls per extraction session (cost control)
    pub max_ai_calls_per_extraction: u32,
    
    /// Timeout for agentic extraction in seconds
    pub agentic_extraction_timeout_secs: u64,
    
    // ECS System Feature Flags
    /// Whether to enable the ECS (Entity Component System) for world state management
    pub enable_ecs_system: bool,
    
    /// Whether to automatically update ECS state from chronicle events
    pub enable_chronicle_to_ecs_sync: bool,
    
    /// Whether to publish ECS state changes back to chronicle system
    pub enable_ecs_to_chronicle_sync: bool,
    
    /// Whether to enable ECS-enhanced RAG queries
    pub enable_ecs_enhanced_rag: bool,
    
    /// Whether to use ECS for entity relationship queries
    pub enable_ecs_relationship_queries: bool,
    
    /// Whether to enable ECS cache warming on system startup
    pub enable_ecs_cache_warming: bool,
    
    /// Percentage of users to enable ECS features for (0-100)
    pub ecs_rollout_percentage: u8,
    
    /// Whether to run in ECS compatibility mode (chronicle + ECS hybrid)
    pub enable_ecs_compatibility_mode: bool,
}

impl Default for NarrativeFeatureFlags {
    fn default() -> Self {
        Self {
            enable_agentic_extraction: false, // Conservative default
            fallback_to_manual_on_error: true,
            dual_extraction_mode: false,
            enable_extraction_metrics: true,
            agentic_rollout_percentage: 0, // Start with 0% rollout
            force_enable_users: vec![],
            force_disable_users: vec![],
            enable_realtime_extraction: false,
            enable_auto_lorebook_creation: false,
            enable_auto_chronicle_creation: false,
            max_ai_calls_per_extraction: 10,
            agentic_extraction_timeout_secs: 30,
            // ECS defaults - conservative
            enable_ecs_system: false,
            enable_chronicle_to_ecs_sync: false,
            enable_ecs_to_chronicle_sync: false,
            enable_ecs_enhanced_rag: false,
            enable_ecs_relationship_queries: false,
            enable_ecs_cache_warming: false,
            ecs_rollout_percentage: 0,
            enable_ecs_compatibility_mode: true, // Start in compatibility mode
        }
    }
}

impl NarrativeFeatureFlags {
    /// Create feature flags for development/testing with agentic features enabled
    pub fn development() -> Self {
        Self {
            enable_agentic_extraction: true,
            fallback_to_manual_on_error: true,
            dual_extraction_mode: true, // Compare both systems in dev
            enable_extraction_metrics: true,
            agentic_rollout_percentage: 100, // Full rollout in dev
            force_enable_users: vec![],
            force_disable_users: vec![],
            enable_realtime_extraction: true,
            enable_auto_lorebook_creation: true,
            enable_auto_chronicle_creation: true,
            max_ai_calls_per_extraction: 15, // More generous in dev
            agentic_extraction_timeout_secs: 60, // Longer timeout in dev
            // ECS fully enabled in development
            enable_ecs_system: true,
            enable_chronicle_to_ecs_sync: true,
            enable_ecs_to_chronicle_sync: true,
            enable_ecs_enhanced_rag: true,
            enable_ecs_relationship_queries: true,
            enable_ecs_cache_warming: true,
            ecs_rollout_percentage: 100,
            enable_ecs_compatibility_mode: true, // Hybrid mode for testing
        }
    }
    
    /// Create feature flags for safe production rollout (gradual)
    pub fn production_rollout(percentage: u8) -> Self {
        Self {
            enable_agentic_extraction: true,
            fallback_to_manual_on_error: true,
            dual_extraction_mode: false, // No dual mode in prod
            enable_extraction_metrics: true,
            agentic_rollout_percentage: percentage.min(100),
            force_enable_users: vec![],
            force_disable_users: vec![],
            enable_realtime_extraction: true,
            enable_auto_lorebook_creation: true,
            enable_auto_chronicle_creation: true,
            max_ai_calls_per_extraction: 8, // Conservative in prod
            agentic_extraction_timeout_secs: 25, // Shorter timeout in prod
            // ECS conservative rollout in production
            enable_ecs_system: true,
            enable_chronicle_to_ecs_sync: true,
            enable_ecs_to_chronicle_sync: false, // One-way sync initially
            enable_ecs_enhanced_rag: false, // Disabled until proven stable
            enable_ecs_relationship_queries: true,
            enable_ecs_cache_warming: true,
            ecs_rollout_percentage: percentage.min(100) / 2, // Half the narrative rollout
            enable_ecs_compatibility_mode: true, // Always hybrid in prod
        }
    }
    
    /// Determine if agentic extraction should be enabled for a specific user
    pub fn should_use_agentic_for_user(&self, user_id: &str) -> bool {
        // Check force enable/disable lists first
        if self.force_enable_users.contains(&user_id.to_string()) {
            return true;
        }
        
        if self.force_disable_users.contains(&user_id.to_string()) {
            return false;
        }
        
        // If agentic extraction is disabled globally, return false
        if !self.enable_agentic_extraction {
            return false;
        }
        
        // Use percentage-based rollout
        // Simple hash-based distribution to ensure consistent results for same user
        let user_hash = self.simple_hash(user_id) % 100;
        user_hash < self.agentic_rollout_percentage as u64
    }
    
    /// Simple hash function for consistent user bucketing
    fn simple_hash(&self, input: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Check if we should run dual extraction mode (both manual and agentic)
    pub fn should_run_dual_extraction(&self) -> bool {
        self.dual_extraction_mode && self.enable_agentic_extraction
    }
    
    /// Check if we should fall back to manual extraction on agentic failure
    pub fn should_fallback_to_manual(&self) -> bool {
        self.fallback_to_manual_on_error
    }
    
    /// Determine if ECS system should be enabled for a specific user
    pub fn should_use_ecs_for_user(&self, user_id: &str) -> bool {
        if !self.enable_ecs_system {
            return false;
        }
        
        // Use same hashing approach as agentic extraction for consistency
        let user_hash = self.simple_hash(&format!("ecs_{}", user_id)) % 100;
        user_hash < self.ecs_rollout_percentage as u64
    }
    
    /// Check if chronicle-to-ECS sync should be enabled for a user
    pub fn should_sync_chronicle_to_ecs(&self, user_id: &str) -> bool {
        self.enable_chronicle_to_ecs_sync && self.should_use_ecs_for_user(user_id)
    }
    
    /// Check if ECS-to-chronicle sync should be enabled for a user
    pub fn should_sync_ecs_to_chronicle(&self, user_id: &str) -> bool {
        self.enable_ecs_to_chronicle_sync && self.should_use_ecs_for_user(user_id)
    }
    
    /// Check if ECS-enhanced RAG should be used for a user
    pub fn should_use_ecs_enhanced_rag(&self, user_id: &str) -> bool {
        self.enable_ecs_enhanced_rag && self.should_use_ecs_for_user(user_id)
    }
    
    /// Check if the system is running in compatibility mode (chronicle + ECS hybrid)
    pub fn is_ecs_compatibility_mode(&self) -> bool {
        self.enable_ecs_compatibility_mode
    }
    
    /// Validate the feature flag configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.agentic_rollout_percentage > 100 {
            return Err("agentic_rollout_percentage must be between 0 and 100".to_string());
        }
        
        if self.max_ai_calls_per_extraction == 0 {
            return Err("max_ai_calls_per_extraction must be greater than 0".to_string());
        }
        
        if self.agentic_extraction_timeout_secs == 0 {
            return Err("agentic_extraction_timeout_secs must be greater than 0".to_string());
        }
        
        if self.dual_extraction_mode && !self.enable_agentic_extraction {
            return Err("Cannot enable dual_extraction_mode without enable_agentic_extraction".to_string());
        }
        
        // ECS validation
        if self.ecs_rollout_percentage > 100 {
            return Err("ecs_rollout_percentage must be between 0 and 100".to_string());
        }
        
        if self.enable_chronicle_to_ecs_sync && !self.enable_ecs_system {
            return Err("Cannot enable chronicle_to_ecs_sync without enable_ecs_system".to_string());
        }
        
        if self.enable_ecs_to_chronicle_sync && !self.enable_ecs_system {
            return Err("Cannot enable ecs_to_chronicle_sync without enable_ecs_system".to_string());
        }
        
        if self.enable_ecs_enhanced_rag && !self.enable_ecs_system {
            return Err("Cannot enable ecs_enhanced_rag without enable_ecs_system".to_string());
        }
        
        Ok(())
    }
}

/// Extraction mode to use for a specific operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionMode {
    /// Use only the old manual extraction system
    ManualOnly,
    /// Use only the new agentic extraction system
    AgenticOnly,
    /// Run both systems and compare results (for validation)
    DualMode,
}

/// Result of determining which extraction mode to use
#[derive(Debug, Clone)]
pub struct ExtractionModeDecision {
    pub mode: ExtractionMode,
    pub reason: String,
    pub should_log_metrics: bool,
}

impl NarrativeFeatureFlags {
    /// Determine which extraction mode to use for a given user and context
    pub fn determine_extraction_mode(&self, user_id: &str, context: &str) -> ExtractionModeDecision {
        // Check if user should get agentic extraction
        let user_should_get_agentic = self.should_use_agentic_for_user(user_id);
        
        if !self.enable_agentic_extraction {
            return ExtractionModeDecision {
                mode: ExtractionMode::ManualOnly,
                reason: "Agentic extraction disabled globally".to_string(),
                should_log_metrics: self.enable_extraction_metrics,
            };
        }
        
        if !user_should_get_agentic {
            return ExtractionModeDecision {
                mode: ExtractionMode::ManualOnly,
                reason: format!("User not in rollout ({}% rollout)", self.agentic_rollout_percentage),
                should_log_metrics: self.enable_extraction_metrics,
            };
        }
        
        if self.dual_extraction_mode {
            return ExtractionModeDecision {
                mode: ExtractionMode::DualMode,
                reason: "Dual extraction mode enabled for comparison".to_string(),
                should_log_metrics: self.enable_extraction_metrics,
            };
        }
        
        ExtractionModeDecision {
            mode: ExtractionMode::AgenticOnly,
            reason: "User enabled for agentic extraction".to_string(),
            should_log_metrics: self.enable_extraction_metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_feature_flags() {
        let flags = NarrativeFeatureFlags::default();
        assert!(!flags.enable_agentic_extraction);
        assert!(flags.fallback_to_manual_on_error);
        assert!(!flags.dual_extraction_mode);
        assert_eq!(flags.agentic_rollout_percentage, 0);
    }

    #[test]
    fn test_development_feature_flags() {
        let flags = NarrativeFeatureFlags::development();
        assert!(flags.enable_agentic_extraction);
        assert!(flags.enable_realtime_extraction);
        assert!(flags.enable_auto_lorebook_creation);
        assert_eq!(flags.agentic_rollout_percentage, 100);
    }

    #[test]
    fn test_production_rollout() {
        let flags = NarrativeFeatureFlags::production_rollout(25);
        assert!(flags.enable_agentic_extraction);
        assert_eq!(flags.agentic_rollout_percentage, 25);
        assert!(!flags.dual_extraction_mode);
        
        // Test clamping
        let flags_high = NarrativeFeatureFlags::production_rollout(150);
        assert_eq!(flags_high.agentic_rollout_percentage, 100);
    }

    #[test]
    fn test_user_agentic_determination() {
        let mut flags = NarrativeFeatureFlags::default();
        flags.enable_agentic_extraction = true;
        flags.agentic_rollout_percentage = 50;
        
        // Test force enable
        flags.force_enable_users = vec!["force_enable_user".to_string()];
        assert!(flags.should_use_agentic_for_user("force_enable_user"));
        
        // Test force disable
        flags.force_disable_users = vec!["force_disable_user".to_string()];
        assert!(!flags.should_use_agentic_for_user("force_disable_user"));
        
        // Test consistent hashing (same user should always get same result)
        let user_id = "test_user_123";
        let result1 = flags.should_use_agentic_for_user(user_id);
        let result2 = flags.should_use_agentic_for_user(user_id);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_validation() {
        let mut flags = NarrativeFeatureFlags::default();
        
        // Valid config should pass
        assert!(flags.validate().is_ok());
        
        // Invalid percentage should fail
        flags.agentic_rollout_percentage = 150;
        assert!(flags.validate().is_err());
        
        flags.agentic_rollout_percentage = 50;
        flags.max_ai_calls_per_extraction = 0;
        assert!(flags.validate().is_err());
        
        flags.max_ai_calls_per_extraction = 5;
        flags.agentic_extraction_timeout_secs = 0;
        assert!(flags.validate().is_err());
        
        // Dual mode without agentic enabled should fail
        flags.agentic_extraction_timeout_secs = 30;
        flags.enable_agentic_extraction = false;
        flags.dual_extraction_mode = true;
        assert!(flags.validate().is_err());
    }

    #[test]
    fn test_extraction_mode_determination() {
        let mut flags = NarrativeFeatureFlags::default();
        
        // Disabled globally
        let decision = flags.determine_extraction_mode("user123", "test");
        assert_eq!(decision.mode, ExtractionMode::ManualOnly);
        assert!(decision.reason.contains("disabled globally"));
        
        // Enabled but user not in rollout
        flags.enable_agentic_extraction = true;
        flags.agentic_rollout_percentage = 0;
        let decision = flags.determine_extraction_mode("user123", "test");
        assert_eq!(decision.mode, ExtractionMode::ManualOnly);
        assert!(decision.reason.contains("not in rollout"));
        
        // Dual mode enabled
        flags.agentic_rollout_percentage = 100;
        flags.dual_extraction_mode = true;
        let decision = flags.determine_extraction_mode("user123", "test");
        assert_eq!(decision.mode, ExtractionMode::DualMode);
        
        // Normal agentic mode
        flags.dual_extraction_mode = false;
        let decision = flags.determine_extraction_mode("user123", "test");
        assert_eq!(decision.mode, ExtractionMode::AgenticOnly);
    }
}