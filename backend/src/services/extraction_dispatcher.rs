// backend/src/services/extraction_dispatcher.rs
//
// Service responsible for dispatching extraction requests to either the manual
// or agentic extraction systems based on feature flags and user configuration.

use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn, error, instrument};
use uuid::Uuid;

use crate::{
    auth::session_dek::SessionDek,
    config::{NarrativeFeatureFlags, ExtractionMode},
    errors::AppError,
    models::chats::ChatMessage,
    services::{
        agentic::agent_runner::NarrativeAgentRunner,
    },
};

/// Result of an extraction operation
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub success: bool,
    pub mode_used: ExtractionMode,
    pub duration_ms: u64,
    pub events_extracted: usize,
    pub lorebook_entries_created: usize,
    pub chronicles_created: usize,
    pub error_message: Option<String>,
    pub ai_calls_made: u32,
}

/// Metrics for comparing extraction systems
#[derive(Debug, Clone)]
pub struct ExtractionComparisonMetrics {
    pub manual_result: Option<ExtractionResult>,
    pub agentic_result: Option<ExtractionResult>,
    pub agreement_score: Option<f64>, // 0.0 to 1.0, how similar the results were
    pub recommendation: String, // Which system performed better
}

/// Service for dispatching extraction operations based on feature flags
pub struct ExtractionDispatcher {
    feature_flags: Arc<NarrativeFeatureFlags>,
    agentic_runner: Option<Arc<NarrativeAgentRunner>>,
}

impl ExtractionDispatcher {
    pub fn new(
        feature_flags: Arc<NarrativeFeatureFlags>,
        agentic_runner: Option<Arc<NarrativeAgentRunner>>,
    ) -> Self {
        Self {
            feature_flags,
            agentic_runner,
        }
    }

    /// Extract events from chat messages using the appropriate system
    #[instrument(skip(self, messages, session_dek), fields(user_id = %user_id, num_messages = messages.len()))]
    pub async fn extract_events_from_chat(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
    ) -> Result<ExtractionResult, AppError> {
        let decision = self.feature_flags.determine_extraction_mode(
            &user_id.to_string(), 
            "event_extraction"
        );
        
        info!(
            user_id = %user_id,
            mode = ?decision.mode,
            reason = %decision.reason,
            "Determined extraction mode for event extraction"
        );

        match decision.mode {
            ExtractionMode::ManualOnly => {
                self.extract_events_manual(user_id, chat_session_id, chronicle_id, messages, session_dek).await
            }
            ExtractionMode::AgenticOnly => {
                self.extract_events_agentic(user_id, chat_session_id, chronicle_id, messages, session_dek).await
            }
            ExtractionMode::DualMode => {
                self.extract_events_dual_mode(user_id, chat_session_id, chronicle_id, messages, session_dek).await
            }
        }
    }

    /// Extract events using the manual system
    async fn extract_events_manual(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
    ) -> Result<ExtractionResult, AppError> {
        let start_time = Instant::now();
        
        debug!("Using manual event extraction");
        
        // For now, return a placeholder result since we're transitioning away from manual
        // In a real implementation, this would call the EventExtractionService
        let duration = start_time.elapsed();
        
        warn!("Manual event extraction called but not fully implemented in dispatcher");
        
        Ok(ExtractionResult {
            success: false,
            mode_used: ExtractionMode::ManualOnly,
            duration_ms: duration.as_millis() as u64,
            events_extracted: 0,
            lorebook_entries_created: 0,
            chronicles_created: 0,
            error_message: Some("Manual extraction not implemented in dispatcher".to_string()),
            ai_calls_made: 0,
        })
    }

    /// Extract events using the agentic system
    async fn extract_events_agentic(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
    ) -> Result<ExtractionResult, AppError> {
        let start_time = Instant::now();
        
        debug!("Using agentic event extraction");
        
        let Some(agentic_runner) = &self.agentic_runner else {
            return Err(AppError::InternalServerErrorGeneric(
                "Agentic runner not configured but agentic extraction requested".to_string()
            ));
        };

        // Apply timeout if configured
        let timeout_duration = std::time::Duration::from_secs(self.feature_flags.agentic_extraction_timeout_secs);
        
        // TODO: Retrieve user's persona context for extraction
        // For now, pass None - this will be implemented when persona retrieval is added
        let persona_context = None;
        
        let extraction_future = agentic_runner.process_narrative_event(
            user_id,
            chat_session_id,
            chronicle_id,
            messages,
            session_dek,
            persona_context,
        );

        let workflow_result = match tokio::time::timeout(timeout_duration, extraction_future).await {
            Ok(result) => result?,
            Err(_) => {
                error!("Agentic extraction timed out after {}s", self.feature_flags.agentic_extraction_timeout_secs);
                
                if self.feature_flags.should_fallback_to_manual() {
                    warn!("Falling back to manual extraction due to timeout");
                    return self.extract_events_manual(user_id, chat_session_id, chronicle_id, messages, session_dek).await;
                } else {
                    return Err(AppError::InternalServerErrorGeneric(
                        format!("Agentic extraction timed out after {}s", self.feature_flags.agentic_extraction_timeout_secs)
                    ));
                }
            }
        };

        let duration = start_time.elapsed();
        
        // Calculate metrics from workflow result (JSON value)
        let events_extracted = workflow_result
            .get("execution")
            .and_then(|e| e.get("events_created"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let chronicles_created = if chronicle_id.is_none() && events_extracted > 0 { 1 } else { 0 };
        let lorebook_entries_created = workflow_result
            .get("execution")
            .and_then(|e| e.get("lorebook_entries_created"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        info!(
            duration_ms = duration.as_millis(),
            events_extracted = events_extracted,
            chronicles_created = chronicles_created,
            lorebook_entries_created = lorebook_entries_created,
            "Agentic extraction completed"
        );

        Ok(ExtractionResult {
            success: true,
            mode_used: ExtractionMode::AgenticOnly,
            duration_ms: duration.as_millis() as u64,
            events_extracted,
            lorebook_entries_created,
            chronicles_created,
            error_message: None,
            ai_calls_made: 2, // Triage + planning calls (simplified)
        })
    }

    /// Run both manual and agentic extraction for comparison
    async fn extract_events_dual_mode(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
    ) -> Result<ExtractionResult, AppError> {
        debug!("Running dual-mode extraction for comparison");

        // Run both extractions concurrently
        let manual_future = self.extract_events_manual(user_id, chat_session_id, chronicle_id, messages, session_dek);
        let agentic_future = self.extract_events_agentic(user_id, chat_session_id, chronicle_id, messages, session_dek);

        let (manual_result, agentic_result) = tokio::join!(manual_future, agentic_future);

        let manual_result = manual_result.ok();
        let agentic_result = agentic_result.ok();

        // Log comparison metrics
        if let (Some(manual), Some(agentic)) = (&manual_result, &agentic_result) {
            let comparison = self.compare_extraction_results(manual, agentic);
            
            info!(
                comparison_metrics = ?comparison,
                "Dual-mode extraction comparison completed"
            );
            
            // In dual mode, we typically return the agentic result if it succeeded,
            // otherwise fall back to manual
            if agentic.success {
                return Ok(agentic.clone());
            } else if manual.success {
                return Ok(manual.clone());
            }
        }

        // If both failed or one is missing, return the agentic result (which should contain error info)
        agentic_result.unwrap_or_else(|| ExtractionResult {
            success: false,
            mode_used: ExtractionMode::DualMode,
            duration_ms: 0,
            events_extracted: 0,
            lorebook_entries_created: 0,
            chronicles_created: 0,
            error_message: Some("Both manual and agentic extraction failed".to_string()),
            ai_calls_made: 0,
        }).pipe(Ok)
    }

    /// Compare results from manual and agentic extraction
    fn compare_extraction_results(
        &self,
        manual: &ExtractionResult,
        agentic: &ExtractionResult,
    ) -> ExtractionComparisonMetrics {
        // Simple comparison logic - in a real implementation this would be more sophisticated
        let events_agreement = if manual.events_extracted == 0 && agentic.events_extracted == 0 {
            1.0 // Both found nothing - perfect agreement
        } else if manual.events_extracted == 0 || agentic.events_extracted == 0 {
            0.0 // One found something, other didn't - no agreement
        } else {
            // Both found events - compare counts (simple metric)
            let min = manual.events_extracted.min(agentic.events_extracted) as f64;
            let max = manual.events_extracted.max(agentic.events_extracted) as f64;
            min / max
        };

        let recommendation = if agentic.success && !manual.success {
            "Agentic extraction succeeded while manual failed".to_string()
        } else if manual.success && !agentic.success {
            "Manual extraction succeeded while agentic failed".to_string()
        } else if agentic.duration_ms < manual.duration_ms {
            "Agentic extraction was faster".to_string()
        } else if agentic.events_extracted > manual.events_extracted {
            "Agentic extraction found more events".to_string()
        } else {
            "Results are similar".to_string()
        };

        ExtractionComparisonMetrics {
            manual_result: Some(manual.clone()),
            agentic_result: Some(agentic.clone()),
            agreement_score: Some(events_agreement),
            recommendation,
        }
    }

    /// Check if realtime extraction is enabled for a user
    pub fn should_enable_realtime_extraction(&self, user_id: &str) -> bool {
        self.feature_flags.enable_realtime_extraction 
            && self.feature_flags.should_use_agentic_for_user(user_id)
    }

    /// Check if auto lorebook creation is enabled for a user
    pub fn should_enable_auto_lorebook_creation(&self, user_id: &str) -> bool {
        self.feature_flags.enable_auto_lorebook_creation 
            && self.feature_flags.should_use_agentic_for_user(user_id)
    }

    /// Check if auto chronicle creation is enabled for a user
    pub fn should_enable_auto_chronicle_creation(&self, user_id: &str) -> bool {
        self.feature_flags.enable_auto_chronicle_creation 
            && self.feature_flags.should_use_agentic_for_user(user_id)
    }
}

// Helper trait for pipe operations
trait Pipe<T> {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U;
}

impl<T> Pipe<T> for T {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U,
    {
        f(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NarrativeFeatureFlags;

    #[test]
    fn test_extraction_dispatcher_creation() {
        let flags = Arc::new(NarrativeFeatureFlags::default());
        let dispatcher = ExtractionDispatcher::new(flags, None);
        
        // Should be able to create dispatcher without services for testing
        assert!(dispatcher.agentic_runner.is_none());
    }

    #[test]
    fn test_realtime_extraction_check() {
        let mut flags = NarrativeFeatureFlags::default();
        flags.enable_realtime_extraction = true;
        flags.enable_agentic_extraction = true;
        flags.agentic_rollout_percentage = 100;
        
        let flags = Arc::new(flags);
        let dispatcher = ExtractionDispatcher::new(flags, None);
        
        assert!(dispatcher.should_enable_realtime_extraction("test_user"));
    }

    #[test]
    fn test_auto_features_check() {
        let mut flags = NarrativeFeatureFlags::default();
        flags.enable_auto_lorebook_creation = true;
        flags.enable_auto_chronicle_creation = true;
        flags.enable_agentic_extraction = true;
        flags.agentic_rollout_percentage = 100;
        
        let flags = Arc::new(flags);
        let dispatcher = ExtractionDispatcher::new(flags, None);
        
        assert!(dispatcher.should_enable_auto_lorebook_creation("test_user"));
        assert!(dispatcher.should_enable_auto_chronicle_creation("test_user"));
    }
}