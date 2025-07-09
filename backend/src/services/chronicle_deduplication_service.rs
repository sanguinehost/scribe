//! Chronicle Event Deduplication Service
//! 
//! Implements structured query-based de-duplication using Ars Fabula narrative ontology.
//! This moves beyond simple semantic similarity to structured event reasoning.

use std::sync::Arc;
use std::collections::HashSet;
use tracing::{info, warn, debug, instrument};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods, PgTextExpressionMethods};

use crate::{
    errors::AppError,
    models::{
        chronicle_event::{ChronicleEvent, DeduplicationFilter},
        narrative_ontology::{EventActor, NarrativeAction},
    },
    schema::chronicle_events::dsl as chronicle_events_dsl,
    state::DbPool,
};

/// Configuration for de-duplication behavior
#[derive(Debug, Clone)]
pub struct DeduplicationConfig {
    /// Time window in minutes for considering events as potential duplicates
    pub time_window_minutes: i64,
    /// Minimum actor overlap ratio to consider as duplicate (0.0-1.0)
    pub actor_overlap_threshold: f32,
    /// Whether to check action similarity for non-exact matches
    pub enable_action_similarity: bool,
    /// Maximum number of events to check for duplicates per query
    pub max_events_to_check: i64,
    /// Confidence threshold for flagging duplicates
    pub duplicate_confidence_threshold: f32,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            time_window_minutes: 15, // Increased to 15 minutes for re-chronicling
            actor_overlap_threshold: 0.7, // Increased to 70% actor overlap
            enable_action_similarity: true,
            max_events_to_check: 100, // Increased to check more events
            duplicate_confidence_threshold: 0.8, // Lowered threshold for more aggressive deduplication
        }
    }
}

/// Result of duplicate detection
#[derive(Debug, Clone)]
pub struct DuplicateDetectionResult {
    /// Whether a duplicate was found
    pub is_duplicate: bool,
    /// The duplicate event ID if found
    pub duplicate_event_id: Option<Uuid>,
    /// Confidence score of the duplicate detection (0.0-1.0)
    pub confidence: f32,
    /// Reasoning for the duplicate detection
    pub reasoning: String,
}

/// Chronicle Event Deduplication Service
pub struct ChronicleDeduplicationService {
    db_pool: DbPool,
    config: DeduplicationConfig,
}

impl ChronicleDeduplicationService {
    /// Create a new deduplication service
    pub fn new(db_pool: DbPool, config: Option<DeduplicationConfig>) -> Self {
        Self {
            db_pool,
            config: config.unwrap_or_default(),
        }
    }

    /// Check if a new event would be a duplicate of existing events
    #[instrument(skip(self), fields(event_id = %new_event.id))]
    pub async fn check_for_duplicates(
        &self,
        new_event: &ChronicleEvent,
    ) -> Result<DuplicateDetectionResult, AppError> {
        debug!("Checking for duplicates of event: {} at timestamp: {}", new_event.id, new_event.timestamp_iso8601);

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
            if let Some(result) = self.check_event_similarity(new_event, candidate).await? {
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
        let connection = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(format!("Failed to get DB connection: {}", e)))?;

        // Calculate time window - look backward only for deduplication
        // We want to find events that happened BEFORE this one within the time window
        let time_window_start = new_event.timestamp_iso8601 - Duration::minutes(self.config.time_window_minutes);
        let time_window_end = new_event.timestamp_iso8601;
        
        debug!(
            "Getting candidate events for timestamp {} with window {} minutes: {} to {}",
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
        let events = connection
            .interact(move |conn| {
                chronicle_events_dsl::chronicle_events
                    .filter(chronicle_events_dsl::chronicle_id.eq(chronicle_id))
                    .filter(chronicle_events_dsl::user_id.eq(user_id))
                    .filter(chronicle_events_dsl::id.ne(event_id)) // Exclude the new event itself
                    .filter(chronicle_events_dsl::timestamp_iso8601.between(time_window_start, time_window_end))
                    .order(chronicle_events_dsl::timestamp_iso8601.desc())
                    .limit(max_events)
                    .load::<ChronicleEvent>(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Failed to interact with database: {}", e)))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(events)
    }

    /// Check if two events are similar enough to be considered duplicates
    async fn check_event_similarity(
        &self,
        new_event: &ChronicleEvent,
        candidate: &ChronicleEvent,
    ) -> Result<Option<DuplicateDetectionResult>, AppError> {
        debug!("Comparing events {} at {} and {} at {}", new_event.id, new_event.timestamp_iso8601, candidate.id, candidate.timestamp_iso8601);

        // Stage 0: Quick temporal check - if events are outside the time window, skip detailed analysis
        let temporal_score = self.calculate_temporal_similarity(new_event, candidate);
        if temporal_score == 0.0 {
            debug!("Events are outside temporal window, skipping similarity check");
            return Ok(None);
        }

        // Stage 1: Check for exact content match first (fastest check)
        let content_score = self.calculate_content_similarity(new_event, candidate);
        if content_score >= 0.95 {
            debug!("Events have very high content similarity: {:.2}", content_score);
            return Ok(Some(DuplicateDetectionResult {
                is_duplicate: true,
                duplicate_event_id: Some(candidate.id),
                confidence: content_score,
                reasoning: format!("Exact content match: {:.2}", content_score),
            }));
        }

        // Stage 2: Check action similarity
        let action_score = self.calculate_action_similarity(new_event, candidate);
        if action_score < 0.5 {
            debug!("Events have low action similarity: {:.2}", action_score);
            return Ok(None);
        }

        // Stage 3: Check actor overlap
        let actor_score = self.calculate_actor_overlap(new_event, candidate).await?;
        if actor_score < self.config.actor_overlap_threshold {
            debug!("Events have low actor overlap: {:.2}", actor_score);
            return Ok(None);
        }

        // Stage 4: Temporal score already calculated above

        // Calculate overall confidence with content similarity included
        let confidence = (content_score * 0.4 + action_score * 0.25 + actor_score * 0.25 + temporal_score * 0.1).min(1.0);

        // Consider it a duplicate if confidence is high enough
        let is_duplicate = confidence >= self.config.duplicate_confidence_threshold;

        let reasoning = format!(
            "Content similarity: {:.2}, Action similarity: {:.2}, Actor overlap: {:.2}, Temporal proximity: {:.2}, Overall confidence: {:.2}",
            content_score, action_score, actor_score, temporal_score, confidence
        );

        Ok(Some(DuplicateDetectionResult {
            is_duplicate,
            duplicate_event_id: if is_duplicate { Some(candidate.id) } else { None },
            confidence,
            reasoning,
        }))
    }

    /// Calculate content similarity between two events based on summary and event_data
    fn calculate_content_similarity(&self, event1: &ChronicleEvent, event2: &ChronicleEvent) -> f32 {
        // First check if summaries are identical
        if event1.summary == event2.summary {
            // If summaries are identical, check event_data as well
            match (&event1.event_data, &event2.event_data) {
                (Some(data1), Some(data2)) => {
                    if data1 == data2 {
                        1.0 // Perfect match
                    } else {
                        0.9 // Same summary but different structured data
                    }
                }
                (None, None) => 1.0, // Same summary, no event data
                _ => 0.85, // Same summary, one has event data
            }
        } else {
            // Calculate fuzzy similarity for summaries
            let summary_similarity = self.calculate_string_similarity(&event1.summary, &event2.summary);
            
            // If summaries are very similar, check event_data
            if summary_similarity > 0.8 {
                match (&event1.event_data, &event2.event_data) {
                    (Some(data1), Some(data2)) => {
                        if data1 == data2 {
                            summary_similarity * 0.9 // High similarity with same data
                        } else {
                            summary_similarity * 0.7 // Similar summary, different data
                        }
                    }
                    (None, None) => summary_similarity,
                    _ => summary_similarity * 0.8,
                }
            } else {
                summary_similarity
            }
        }
    }
    
    /// Calculate similarity between two strings using simple character-based comparison
    fn calculate_string_similarity(&self, str1: &str, str2: &str) -> f32 {
        if str1 == str2 {
            return 1.0;
        }
        
        let len1 = str1.len();
        let len2 = str2.len();
        
        if len1 == 0 || len2 == 0 {
            return 0.0;
        }
        
        // Simple character overlap calculation
        let chars1: std::collections::HashSet<char> = str1.chars().collect();
        let chars2: std::collections::HashSet<char> = str2.chars().collect();
        
        let intersection = chars1.intersection(&chars2).count();
        let union = chars1.union(&chars2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f32 / union as f32
        }
    }

    /// Calculate similarity between two actions
    fn calculate_action_similarity(&self, event1: &ChronicleEvent, event2: &ChronicleEvent) -> f32 {
        match (&event1.action, &event2.action) {
            (Some(action1), Some(action2)) => {
                if action1 == action2 {
                    1.0 // Exact match
                } else if self.config.enable_action_similarity {
                    // Check for semantically similar actions
                    self.calculate_semantic_action_similarity(action1, action2)
                } else {
                    0.0
                }
            }
            (None, None) => 0.5, // Both missing action
            _ => 0.0, // One has action, other doesn't
        }
    }

    /// Calculate semantic similarity between actions
    fn calculate_semantic_action_similarity(&self, action1: &str, action2: &str) -> f32 {
        // Define action similarity groups
        let discovery_actions = ["DISCOVERED", "FOUND", "UNCOVERED", "REVEALED"];
        let social_actions = ["MET", "BEFRIENDED", "MARRIED", "DIVORCED"];
        let conflict_actions = ["ATTACKED", "DEFENDED", "DEFEATED", "FLED"];
        let acquisition_actions = ["ACQUIRED", "GAVE", "LOST", "STOLE"];
        let transformation_actions = ["TRANSFORMED", "EVOLVED", "DIED", "RESURRECTED"];
        let communication_actions = ["TOLD", "ASKED", "LIED", "CONFESSED"];

        let action_groups = [
            &discovery_actions[..],
            &social_actions[..],
            &conflict_actions[..],
            &acquisition_actions[..],
            &transformation_actions[..],
            &communication_actions[..],
        ];

        // Check if both actions are in the same semantic group
        for group in &action_groups {
            if group.contains(&action1) && group.contains(&action2) {
                return 0.8; // High similarity for same group
            }
        }

        0.0 // No semantic similarity found
    }

    /// Calculate overlap between actors in two events
    async fn calculate_actor_overlap(&self, event1: &ChronicleEvent, event2: &ChronicleEvent) -> Result<f32, AppError> {
        let actors1 = event1.get_actors_with_fallback().map_err(|e| AppError::SerializationError(e.to_string()))?;
        let actors2 = event2.get_actors_with_fallback().map_err(|e| AppError::SerializationError(e.to_string()))?;

        if actors1.is_empty() && actors2.is_empty() {
            return Ok(0.5); // Both have no actors
        }

        if actors1.is_empty() || actors2.is_empty() {
            return Ok(0.0); // One has actors, other doesn't
        }

        // Extract entity IDs
        let entities1: HashSet<Uuid> = actors1.iter().map(|a| a.entity_id).collect();
        let entities2: HashSet<Uuid> = actors2.iter().map(|a| a.entity_id).collect();

        // Calculate Jaccard similarity (intersection / union)
        let intersection_count = entities1.intersection(&entities2).count();
        let union_count = entities1.union(&entities2).count();

        if union_count == 0 {
            Ok(0.0)
        } else {
            Ok(intersection_count as f32 / union_count as f32)
        }
    }

    /// Calculate temporal similarity between two events
    fn calculate_temporal_similarity(&self, event1: &ChronicleEvent, event2: &ChronicleEvent) -> f32 {
        let time_diff = (event1.timestamp_iso8601 - event2.timestamp_iso8601).num_minutes().abs();
        let max_window = self.config.time_window_minutes;

        debug!("Temporal similarity check: time_diff={} minutes, max_window={} minutes", time_diff, max_window);

        if time_diff >= max_window {
            debug!("Events outside temporal window ({}>={}), returning 0.0", time_diff, max_window);
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
        filter: &DeduplicationFilter,
    ) -> Result<Vec<(Uuid, Uuid)>, AppError> {
        debug!("Finding duplicate events with filter: {:?}", filter);

        let connection = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(format!("Failed to get DB connection: {}", e)))?;

        // Copy values to move into closure
        let chronicle_id = filter.chronicle_id;
        let user_id = filter.user_id;
        let action = filter.action.clone();

        // Get events matching the filter criteria
        let events = connection
            .interact(move |conn| {
                chronicle_events_dsl::chronicle_events
                    .filter(chronicle_events_dsl::chronicle_id.eq(chronicle_id))
                    .filter(chronicle_events_dsl::user_id.eq(user_id))
                    .filter(chronicle_events_dsl::action.eq(&action))
                    .order(chronicle_events_dsl::timestamp_iso8601.asc())
                    .load::<ChronicleEvent>(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Failed to interact with database: {}", e)))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        let mut duplicates = Vec::new();

        // Compare each event with subsequent events
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                let event1 = &events[i];
                let event2 = &events[j];

                // Check if they're within the time window
                let time_diff = (event2.timestamp_iso8601 - event1.timestamp_iso8601).num_minutes();
                if time_diff > filter.window_minutes {
                    break; // No need to check further events for this base event
                }

                if let Some(result) = self.check_event_similarity(event1, event2).await? {
                    if result.is_duplicate && result.confidence >= filter.similarity_threshold {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use chrono::Utc;
    use serde_json::json;

    #[tokio::test]
    async fn test_deduplication_service_creation() {
        let test_app = crate::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        
        let service = ChronicleDeduplicationService::new(pool, None);
        assert_eq!(service.config.time_window_minutes, 5);
        assert_eq!(service.config.actor_overlap_threshold, 0.6);
    }

    #[tokio::test]
    async fn test_action_similarity_calculation() {
        let test_app = crate::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let service = ChronicleDeduplicationService::new(pool, None);

        // Test exact match
        assert_eq!(service.calculate_action_similarity(&create_test_event("DISCOVERED"), &create_test_event("DISCOVERED")), 1.0);

        // Test semantic similarity (both discovery actions)
        assert_eq!(service.calculate_action_similarity(&create_test_event("DISCOVERED"), &create_test_event("FOUND")), 0.8);

        // Test no similarity
        assert_eq!(service.calculate_action_similarity(&create_test_event("DISCOVERED"), &create_test_event("ATTACKED")), 0.0);
    }

    #[tokio::test]
    async fn test_actor_overlap_calculation() {
        let test_app = crate::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let service = ChronicleDeduplicationService::new(pool, None);

        let event1 = create_test_event_with_actors("DISCOVERED", vec![
            (Uuid::new_v4(), "AGENT"),
            (Uuid::new_v4(), "PATIENT"),
        ]);
        
        let event2 = create_test_event_with_actors("DISCOVERED", vec![
            (event1.get_actors_with_fallback().unwrap()[0].entity_id, "AGENT"), // Same entity
            (Uuid::new_v4(), "WITNESS"), // Different entity
        ]);

        let overlap = service.calculate_actor_overlap(&event1, &event2).await.unwrap();
        assert!((overlap - 0.33).abs() < 0.1); // Should be around 1/3 (1 intersection, 3 union)
    }

    fn create_test_event(action: &str) -> ChronicleEvent {
        ChronicleEvent {
            id: Uuid::new_v4(),
            chronicle_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            event_type: "TEST.EVENT".to_string(),
            summary: "Test event".to_string(),
            source: "AI_EXTRACTED".to_string(),
            event_data: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: Utc::now(),
            actors: None,
            action: Some(action.to_string()),
            context_data: None,
            causality: None,
            valence: None,
            modality: Some("ACTUAL".to_string()),
            caused_by_event_id: None,
            causes_event_ids: None,
        }
    }

    fn create_test_event_with_actors(action: &str, actors: Vec<(Uuid, &str)>) -> ChronicleEvent {
        let actors_json = json!(actors.into_iter().map(|(entity_id, role)| {
            json!({
                "entity_id": entity_id,
                "role": role,
                "context": null
            })
        }).collect::<Vec<_>>());

        ChronicleEvent {
            id: Uuid::new_v4(),
            chronicle_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            event_type: "TEST.EVENT".to_string(),
            summary: "Test event".to_string(),
            source: "AI_EXTRACTED".to_string(),
            event_data: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: Utc::now(),
            actors: Some(actors_json),
            action: Some(action.to_string()),
            context_data: None,
            causality: None,
            valence: None,
            modality: Some("ACTUAL".to_string()),
            caused_by_event_id: None,
            causes_event_ids: None,
        }
    }
}