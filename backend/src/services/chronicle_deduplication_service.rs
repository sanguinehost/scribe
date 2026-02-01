//! Chronicle Event Deduplication Service
//!
//! Implements structured query-based de-duplication using Ars Fabula narrative ontology.
//! This moves beyond simple semantic similarity to structured event reasoning.

use chrono::Duration;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
use tracing::{debug, info, instrument};

use crate::{
    auth::session_dek::SessionDek, errors::AppError, models::chronicle_event::ChronicleEvent,
    schema::chronicle_events::dsl as chronicle_events_dsl, state::DbPool,
};

/// Configuration for de-duplication behavior
#[derive(Debug, Clone)]
pub struct DeduplicationConfig {
    /// Time window in minutes for considering events as potential duplicates
    pub time_window_minutes: i64,
    /// Minimum content similarity to consider as duplicate (0.0-1.0)
    pub similarity_threshold: f32,
    /// Maximum number of events to check for duplicates per query
    pub max_events_to_check: i64,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            time_window_minutes: 3,     // 3 minute window (decreased from 5)
            similarity_threshold: 0.80, // 80% content similarity (Loose Pre-Filter)
            max_events_to_check: 50,
        }
    }
}

/// Result of duplicate detection
#[derive(Debug, Clone)]
pub struct DuplicateDetectionResult {
    /// Whether a duplicate was found
    pub is_duplicate: bool,
    /// The duplicate event ID if found
    pub duplicate_event_id: Option<crate::db::DbId>,
    /// Confidence score of the duplicate detection (0.0-1.0)
    pub confidence: f32,
    /// Reasoning for the duplicate detection
    pub reasoning: String,
}

use crate::llm::AiClient;
use std::sync::Arc;

/// Chronicle Event Deduplication Service
pub struct ChronicleDeduplicationService {
    db_pool: DbPool,
    ai_client: Arc<dyn AiClient>,
    config: DeduplicationConfig,
}

impl ChronicleDeduplicationService {
    /// Keywords that trigger the "Safety Valve" (bypass deduplication)
    const HIGH_INTENSITY_KEYWORDS: &'static [&'static str] = &[
        "death",
        "kill",
        "die",
        "murder",
        "blood",
        "betrayal",
        "secret",
        "reveal",
        "explosion",
        "attack",
        "ambush",
        "kiss",
        "intimacy",
        "sex",
        "love",
        "confession",
        "artifact",
        "relic",
        "god",
        "magic",
        "curse",
    ];

    fn is_high_intensity(&self, summary: &str) -> bool {
        let summary_lower = summary.to_lowercase();
        Self::HIGH_INTENSITY_KEYWORDS
            .iter()
            .any(|&kw| summary_lower.contains(kw))
    }
    /// Create a new deduplication service
    pub fn new(
        db_pool: DbPool,
        ai_client: Arc<dyn AiClient>,
        config: Option<DeduplicationConfig>,
    ) -> Self {
        Self {
            db_pool,
            ai_client,
            config: config.unwrap_or_default(),
        }
    }

    /// Check if a new event would be a duplicate of existing events
    #[instrument(skip(self), fields(event_id = %new_event.id))]
    pub async fn check_for_duplicates(
        &self,
        new_event: &ChronicleEvent,
        session_dek: Option<&SessionDek>,
    ) -> Result<DuplicateDetectionResult, AppError> {
        debug!(
            "Checking for duplicates of event: {} at timestamp: {:?}",
            new_event.id, new_event.timestamp_iso8601
        );

        // Safety Valve: High Intensity Keywords bypass deduplication
        if self.is_high_intensity(&new_event.summary) {
            info!(
                "Safety Valve triggered: high intensity keywords detected in event {}",
                new_event.id
            );
            return Ok(DuplicateDetectionResult {
                is_duplicate: false,
                duplicate_event_id: None,
                confidence: 1.0,
                reasoning: "Safety Valve: High intensity keywords detected".to_string(),
            });
        }

        // Get recent events from the same chronicle within the time window
        let candidate_events = self.get_candidate_events(new_event).await?;

        if candidate_events.is_empty() {
            debug!("No candidate events found in time window for deduplication");
            return Ok(DuplicateDetectionResult {
                is_duplicate: false,
                duplicate_event_id: None,
                confidence: 1.0,
                reasoning: "No recent events found in time window".to_string(),
            });
        }

        debug!("Found {} candidate events to check", candidate_events.len());

        // Check each candidate for duplication
        for candidate in &candidate_events {
            if let Some(result) = self
                .check_event_similarity(new_event, candidate, session_dek)
                .await?
            {
                if result.is_duplicate {
                    info!(
                        "Duplicate detected: {} is duplicate of {} (confidence: {:.2})",
                        new_event.id, candidate.id, result.confidence
                    );
                    return Ok(result);
                }
            }
        }

        Ok(DuplicateDetectionResult {
            is_duplicate: false,
            duplicate_event_id: None,
            confidence: 1.0,
            reasoning: "No duplicates found among candidate events".to_string(),
        })
    }

    /// Get candidate events that could potentially be duplicates
    async fn get_candidate_events(
        &self,
        new_event: &ChronicleEvent,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        // Calculate time window - look backward only for deduplication
        // We want to find events that happened BEFORE this one within the time window
        let event_timestamp = new_event.timestamp_iso8601;
        let time_window_start =
            event_timestamp - Duration::minutes(self.config.time_window_minutes);
        let time_window_end = event_timestamp;

        debug!(
            "Getting candidate events for timestamp {:?} with window {} minutes: {:?} to {:?}",
            new_event.timestamp_iso8601,
            self.config.time_window_minutes,
            time_window_start,
            time_window_end
        );

        // Copy values to move into closure
        let chronicle_id = new_event.chronicle_id;
        let user_id = new_event.user_id;
        let event_id = new_event.id;
        let max_events = self.config.max_events_to_check;

        // Query for events in the same chronicle within the time window
        let events = crate::db::with_conn(&self.db_pool, move |conn| {
            chronicle_events_dsl::chronicle_events
                .filter(chronicle_events_dsl::chronicle_id.eq(chronicle_id))
                .filter(chronicle_events_dsl::user_id.eq(user_id))
                .filter(chronicle_events_dsl::id.ne(event_id)) // Exclude the new event itself
                .filter(
                    chronicle_events_dsl::timestamp_iso8601
                        .between(time_window_start, time_window_end),
                )
                .order(chronicle_events_dsl::timestamp_iso8601.desc())
                .limit(max_events)
                .select(ChronicleEvent::as_select())
                .load::<ChronicleEvent>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

        Ok(events)
    }

    /// Check if two events are similar enough to be considered duplicates using LLM
    async fn check_event_similarity(
        &self,
        new_event: &ChronicleEvent,
        candidate: &ChronicleEvent,
        session_dek: Option<&SessionDek>,
    ) -> Result<Option<DuplicateDetectionResult>, AppError> {
        debug!(
            "Comparing events {} at {:?} and {} at {:?}",
            new_event.id, new_event.timestamp_iso8601, candidate.id, candidate.timestamp_iso8601
        );

        // Stage 0: Check message variant ID - distinct variants are never duplicates
        // REMOVED: We want to deduplicate across variants if the content is semantically identical.
        // if new_event.message_variant_id != candidate.message_variant_id {
        //     debug!(
        //         "Events belong to different message variants ({:?} vs {:?}), skipping similarity check",
        //         new_event.message_variant_id, candidate.message_variant_id
        //     );
        //     return Ok(None);
        // }

        // Stage 1: Quick temporal check - if events are outside the time window, skip detailed analysis
        let temporal_score = self.calculate_temporal_similarity(new_event, candidate);
        if temporal_score == 0.0 {
            debug!("Events are outside temporal window, skipping similarity check");
            return Ok(None);
        }

        // Stage 2: LLM Semantic Analysis
        self.check_duplicate_with_llm(new_event, candidate, session_dek)
            .await
    }

    /// Use LLM to check for semantic duplication
    async fn check_duplicate_with_llm(
        &self,
        new_event: &ChronicleEvent,
        candidate: &ChronicleEvent,
        session_dek: Option<&SessionDek>,
    ) -> Result<Option<DuplicateDetectionResult>, AppError> {
        let (candidate_summary, new_summary) = match session_dek {
            Some(dek) => (
                candidate.get_decrypted_summary(&dek.0)?,
                new_event.get_decrypted_summary(&dek.0)?,
            ),
            None => (candidate.summary.clone(), new_event.summary.clone()),
        };

        let prompt = format!(
            r#"Analyze these two narrative events and determine if they describe the SAME underlying story moment, even if the phrasing or level of detail differs.

            Event A (Existing): "{}"
            Event B (New): "{}"

            Context:
            - These are events from a roleplay chat log.
            - Users often regenerate responses or swipe for new options, creating multiple "versions" of the same story beat.
            - We want to keep only ONE event for a given moment.

            Criteria for DUPLICATE (return is_duplicate: true):
            1. Same Narrative Beat: Both events describe the same core action or conversation segment (e.g., "Solomon meets Elara").
            2. Summary vs. Detail: One event might be a brief summary ("Solomon talks to Elara") and the other detailed ("Solomon approaches Elara, asks about herbs..."). These ARE duplicates.
            3. Alternative Phrasing: Different words describing the same outcome (e.g., "He drank water" vs "Solomon quenched his thirst").

            Criteria for DISTINCT (return is_duplicate: false):
            1. Sequential Actions: Event B clearly happens AFTER Event A (e.g., "Solomon meets Elara" vs "Solomon and Elara leave the village").
            2. Different Topics: They describe completely different things happening.

            Respond with JSON:
            {{
                "is_duplicate": boolean,
                "confidence": number (0.0 to 1.0),
                "reasoning": string
            }}"#,
            candidate_summary, new_summary
        );

        let request = crate::llm::RigCompletionRequest {
            model_name: "gemini-2.5-flash-lite".to_string(),
            provider: "gemini".to_string(),
            prompt,
            preamble: None,
            history: vec![],
            temperature: Some(0.0),
            max_tokens: None,
            ..Default::default()
        };

        let response = self.ai_client.completion(request).await.map_err(|e| {
            AppError::GenerationError(format!("Failed to check duplicates with LLM: {}", e))
        })?;

        #[derive(serde::Deserialize)]
        struct LlmResponse {
            is_duplicate: bool,
            confidence: f32,
            reasoning: String,
        }

        // Parse JSON from the response content - strip markdown fences if present
        let content = &response.content;
        if content.is_empty() {
            return Err(AppError::GenerationError(
                "LLM returned empty response for deduplication check".to_string(),
            ));
        }

        let json_content = crate::llm::response_utils::strip_markdown_fences(content);
        let llm_result: LlmResponse = serde_json::from_str(json_content).map_err(|e| {
            AppError::GenerationError(format!("Failed to parse LLM deduplication response: {}", e))
        })?;

        if llm_result.is_duplicate && llm_result.confidence > 0.8 {
            Ok(Some(DuplicateDetectionResult {
                is_duplicate: true,
                duplicate_event_id: Some(candidate.id),
                confidence: llm_result.confidence,
                reasoning: llm_result.reasoning,
            }))
        } else {
            Ok(None)
        }
    }

    /// Calculate temporal similarity between two events
    fn calculate_temporal_similarity(
        &self,
        event1: &ChronicleEvent,
        event2: &ChronicleEvent,
    ) -> f32 {
        let t1 = event1.timestamp_iso8601;
        let t2 = event2.timestamp_iso8601;
        let time_diff = (t1 - t2).num_minutes().abs();
        let max_window = self.config.time_window_minutes;

        debug!(
            "Temporal similarity check: time_diff={} minutes, max_window={} minutes",
            time_diff, max_window
        );

        if time_diff >= max_window {
            debug!(
                "Events outside temporal window ({}>={}), returning 0.0",
                time_diff, max_window
            );
            0.0
        } else {
            // Linear decay: closer in time = higher similarity
            let similarity = 1.0 - (time_diff as f32 / max_window as f32);
            debug!("Events within temporal window, similarity: {}", similarity);
            similarity
        }
    }

    /// Find and mark duplicate events for cleanup
    #[instrument(skip(self))]
    pub async fn find_duplicate_events(
        &self,
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
        session_dek: Option<&SessionDek>,
    ) -> Result<Vec<(crate::db::DbId, crate::db::DbId)>, AppError> {
        debug!("Finding duplicate events for chronicle {}", chronicle_id);

        // Get all events for the chronicle
        let events = crate::db::with_conn(&self.db_pool, move |conn| {
            chronicle_events_dsl::chronicle_events
                .filter(chronicle_events_dsl::chronicle_id.eq(chronicle_id))
                .filter(chronicle_events_dsl::user_id.eq(user_id))
                .order(chronicle_events_dsl::timestamp_iso8601.asc())
                .select(ChronicleEvent::as_select())
                .load::<ChronicleEvent>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

        let mut duplicates = Vec::new();

        // Compare each event with subsequent events
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                let event1 = &events[i];
                let event2 = &events[j];

                // Check if they're within the time window
                let t1 = event1.timestamp_iso8601;
                let t2 = event2.timestamp_iso8601;
                let time_diff = (t2 - t1).num_minutes();
                if time_diff > self.config.time_window_minutes {
                    break; // No need to check further events for this base event
                }

                if let Some(result) = self
                    .check_event_similarity(event1, event2, session_dek)
                    .await?
                {
                    if result.is_duplicate {
                        // Keep the earlier event, mark the later one as duplicate
                        duplicates.push((event1.id, event2.id));
                        info!(
                            "Found duplicate pair: {} (original) -> {} (duplicate) with confidence {:.2}",
                            event1.id, event2.id, result.confidence
                        );
                    }
                }
            }
        }

        Ok(duplicates)
    }
}

#[cfg(all(test, feature = "postgres-backend"))]
mod tests {
    use super::*;
    use crate::db::DbId;

    use chrono::Utc;

    #[tokio::test]
    async fn test_deduplication_service_creation() {
        let test_app = crate::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();

        let mock_ai_client = std::sync::Arc::new(crate::test_helpers::MockAiClient::new());
        let service = ChronicleDeduplicationService::new(pool, mock_ai_client, None);
        assert_eq!(service.config.time_window_minutes, 3);
        assert_eq!(service.config.similarity_threshold, 0.80);
    }

    fn create_test_event(summary: &str) -> ChronicleEvent {
        ChronicleEvent {
            id: DbId::new(),
            chronicle_id: DbId::new(),
            user_id: DbId::new(),
            event_type: "TEST.EVENT".to_string(),
            summary: summary.to_string(),
            source: "AI_EXTRACTED".to_string(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: Utc::now().into(),
            keywords: Some(crate::db::unified_types::DbStringArray::empty()),
            keywords_encrypted: None,
            keywords_nonce: None,
            chat_session_id: None,
            message_variant_id: None,
        }
    }
}
