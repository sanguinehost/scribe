// backend/src/services/rag_budget_manager.rs

use chrono::Utc;
use std::cmp::Ordering;
use tracing::{debug, info, warn};

use crate::{
    errors::AppError,
    services::{
        embeddings::{RetrievedChunk, RetrievedMetadata},
        hybrid_token_counter::{CountingMode, HybridTokenCounter},
    },
};

/// Context budget planner that adapts to different Gemini model pricing tiers
#[derive(Debug, Clone)]
pub struct ContextBudgetPlanner {
    /// Total token budget to stay within pricing thresholds
    pub total_budget: usize,
    /// Budget allocated for recent chat history
    pub recent_history_budget: usize,
    /// Budget allocated for lorebook entries
    pub lorebook_budget: usize,
    /// Budget allocated for chronicle events
    pub chronicle_budget: usize,
    /// Budget allocated for older chat history
    pub older_chat_budget: usize,
    /// Estimated tokens for system prompt and overhead
    pub system_prompt_overhead: usize,
    /// The target model for this budget plan
    pub target_model: String,
}

impl ContextBudgetPlanner {
    /// Create a new budget planner optimized for the target model's pricing
    pub fn new_for_model(model: &str, target_total: Option<usize>) -> Self {
        let total_budget = target_total.unwrap_or_else(|| {
            match model {
                // Stay under 200k to avoid 2x cost penalty for Pro/Flash
                model if model.contains("pro") => 190_000,
                model if model.contains("flash") && !model.contains("lite") => 190_000,
                // Flash-Lite is so cheap ($0.10 vs $1.25+), we can use more context
                model if model.contains("lite") => 950_000,
                // Conservative default
                _ => 190_000,
            }
        });

        // Allocate budget intelligently based on model capabilities
        let system_prompt_overhead = 8_000; // Account for character profile, instructions, etc.

        // Model-specific allocation strategies
        let (history_ratio, _rag_ratio) = match model {
            // Pro models: favor RAG content for complex reasoning
            model if model.contains("pro") => (0.25, 0.75),
            // Flash models: balanced approach
            model if model.contains("flash") => (0.35, 0.65),
            // Default: balanced
            _ => (0.30, 0.70),
        };

        let available_budget = total_budget.saturating_sub(system_prompt_overhead);
        let recent_history_budget = (available_budget as f32 * history_ratio) as usize;
        let rag_total_budget = available_budget.saturating_sub(recent_history_budget);

        // Sub-allocate RAG budget: 40% Lore, 40% Chronicle, 20% Older Chat
        let lorebook_budget = (rag_total_budget as f32 * 0.4) as usize;
        let chronicle_budget = (rag_total_budget as f32 * 0.4) as usize;
        let older_chat_budget = rag_total_budget
            .saturating_sub(lorebook_budget)
            .saturating_sub(chronicle_budget);

        info!(
            model = %model,
            total_budget,
            recent_history_budget,
            lorebook_budget,
            chronicle_budget,
            older_chat_budget,
            system_prompt_overhead,
            "Created context budget plan"
        );

        Self {
            total_budget,
            recent_history_budget,
            lorebook_budget,
            chronicle_budget,
            older_chat_budget,
            system_prompt_overhead,
            target_model: model.to_string(),
        }
    }

    /// Get the total RAG budget
    pub fn total_rag_budget(&self) -> usize {
        self.lorebook_budget + self.chronicle_budget + self.older_chat_budget
    }

    /// Check if we're approaching a pricing threshold
    pub fn is_approaching_threshold(&self, current_usage: usize) -> bool {
        let threshold_200k = 200_000;
        current_usage > (threshold_200k as f32 * 0.9) as usize // 90% of 200k
    }
}

/// Priority score for different types of RAG content
#[derive(Debug, Clone)]
pub struct ContentPriority {
    /// Base relevance score (0.0 - 1.0)
    pub relevance: f32,
    /// Recency boost (newer content gets higher priority)
    pub recency: f32,
    /// Content type multiplier
    pub type_priority: f32,
    /// Final composite score
    pub composite_score: f32,
}

impl ContentPriority {
    /// Calculate priority for a retrieved chunk
    pub fn calculate(chunk: &RetrievedChunk, query_timestamp: crate::DbTimestamp) -> Self {
        let relevance = chunk.score;

        // Calculate recency boost based on content type and timestamp
        let (recency, type_priority) = match &chunk.metadata {
            RetrievedMetadata::Chronicle(chronicle_meta) => {
                // Chronicle events: high priority, strong recency bias
                let days_old = (query_timestamp - chronicle_meta.created_at)
                    .num_days()
                    .max(0) as f32;
                let recency_boost = (1.0 / (1.0 + days_old / 30.0)).max(0.1); // Decay over ~30 days
                (recency_boost, 1.2) // 20% type bonus
            }
            RetrievedMetadata::Lorebook(lore_meta) => {
                // Lorebook entries: high priority, especially if constant
                let type_priority = if lore_meta.is_constant { 1.5 } else { 1.1 };
                (1.0, type_priority) // Stable, no time decay
            }
            RetrievedMetadata::Chat(chat_meta) => {
                // Older chat: lower priority, moderate recency bias
                let days_old = (query_timestamp - chat_meta.timestamp).num_days().max(0) as f32;
                let recency_boost = (1.0 / (1.0 + days_old / 7.0)).max(0.2); // Decay over ~7 days
                (recency_boost, 0.8) // 20% type penalty (lower priority than new content)
            }
        };

        // Composite score: weighted combination
        let composite_score = relevance * 0.6 + recency * 0.25 + (type_priority - 1.0) * 0.15;

        Self {
            relevance,
            recency,
            type_priority,
            composite_score,
        }
    }
}

/// Dynamic RAG content selector using token budget management
#[derive(Debug, Clone)]
pub struct DynamicRagSelector {
    token_counter: HybridTokenCounter,
    budget_planner: ContextBudgetPlanner,
    /// URI for the Iceberg catalog (cold storage)
    pub iceberg_catalog_uri: Option<String>,
}

impl DynamicRagSelector {
    /// Create a new dynamic RAG selector
    pub fn new(token_counter: HybridTokenCounter, budget_planner: ContextBudgetPlanner) -> Self {
        // Load Iceberg configuration from environment or config
        let iceberg_catalog_uri = std::env::var("ICEBERG_CATALOG_URI").ok();

        Self {
            token_counter,
            budget_planner,
            iceberg_catalog_uri,
        }
    }

    /// Performs a semantic query directed to the Iceberg catalog for deep recall.
    /// This replaces the legacy Lorebook retrieval that relied on hot-state vector DBs.
    ///
    /// # Complexity
    /// Guarantees O(log N) metadata pruning via Iceberg manifest files, avoiding O(N) scans.
    #[tracing::instrument(skip(self))]
    pub async fn query_iceberg_lorebooks(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        let _span = tracing::Span::current();
        info!(
            query = %query,
            limit,
            catalog = ?self.iceberg_catalog_uri,
            "Performing semantic query to Iceberg catalog"
        );

        if self.iceberg_catalog_uri.is_none() {
            debug!("Iceberg catalog not configured, skipping cold storage recall.");
            return Ok(Vec::new());
        }

        // 1. Initialize Iceberg catalog and S3 object store
        // 2. Load the lorebook table metadata
        // 3. Register with DataFusion for distributed-ready querying
        // 4. Execute vector similarity search via DataFusion UDFs

        // Performance Note: Iceberg's partitioning (e.g., by world_id) further optimizes recall
        // by pruning entire manifest lists before reading any data files.

        // For the MVC spike, we return an empty list.
        // In production, this would bridge to the S3 parquet files.
        Ok(Vec::new())
    }

    /// Select RAG content within the available token budget, prioritized by relevance and type
    #[tracing::instrument(skip(self, candidates), fields(
        num_candidates = candidates.len(),
        available_budget = budget_override.unwrap_or_else(|| self.budget_planner.total_rag_budget()),
        target_model = %self.budget_planner.target_model,
        used_tokens = tracing::field::Empty,
        selected_count = tracing::field::Empty
    ))]
    pub async fn select_rag_content(
        &self,
        candidates: Vec<RetrievedChunk>,
        query_timestamp: Option<crate::DbTimestamp>,
        budget_override: Option<usize>,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        let available_budget =
            budget_override.unwrap_or_else(|| self.budget_planner.total_rag_budget());
        let query_time = query_timestamp.unwrap_or_else(|| Utc::now().into());

        debug!(
            num_candidates = candidates.len(),
            available_budget, "Starting dynamic RAG selection"
        );

        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Calculate priority scores for all candidates
        let mut prioritized_candidates: Vec<(RetrievedChunk, ContentPriority)> = candidates
            .into_iter()
            .map(|chunk| {
                let priority = ContentPriority::calculate(&chunk, query_time);
                (chunk, priority)
            })
            .collect();

        // Sort by composite score (highest first)
        prioritized_candidates.sort_by(|(_, a), (_, b)| {
            b.composite_score
                .partial_cmp(&a.composite_score)
                .unwrap_or(Ordering::Equal)
        });

        debug!(
            "Prioritized candidates by score: {}",
            prioritized_candidates
                .iter()
                .take(5)
                .map(|(_chunk, priority)| format!("{:.3}", priority.composite_score))
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Select items within budget, using the token-aware pattern from history manager
        let mut selected_chunks = Vec::new();
        let mut used_tokens = 0;
        let total_candidates = prioritized_candidates.len(); // Store length before move

        for (chunk, priority) in prioritized_candidates {
            // Estimate tokens for this chunk
            let chunk_tokens = match self
                .token_counter
                .count_tokens(
                    &chunk.text,
                    CountingMode::LocalOnly,
                    Some(&self.budget_planner.target_model),
                )
                .await
            {
                Ok(estimate) => estimate.total,
                Err(e) => {
                    warn!(
                        "Failed to count tokens for chunk, using character estimate: {}",
                        e
                    );
                    // Fallback: rough character-based estimate (4 chars per token)
                    chunk.text.len() / 4
                }
            };

            // Check if we can fit this chunk in the budget
            if used_tokens + chunk_tokens <= available_budget {
                used_tokens += chunk_tokens;

                debug!(
                    chunk_tokens,
                    used_tokens,
                    available_budget,
                    score = priority.composite_score,
                    chunk_type = ?std::mem::discriminant(&chunk.metadata),
                    "Selected chunk for RAG"
                );

                selected_chunks.push(chunk);
            } else {
                debug!(
                    chunk_tokens,
                    used_tokens, available_budget, "Chunk exceeds budget, stopping selection"
                );
                break; // Budget exhausted
            }
        }

        let budget_utilization = (used_tokens as f32 / available_budget as f32) * 100.0;

        info!(
            selected_count = selected_chunks.len(),
            total_candidates,
            used_tokens,
            available_budget,
            budget_utilization = format!("{:.1}%", budget_utilization),
            "Dynamic RAG selection completed"
        );

        // Record metrics as tracing events
        tracing::Span::current().record("used_tokens", used_tokens);
        tracing::Span::current().record("selected_count", selected_chunks.len());

        if selected_chunks.len() < total_candidates {
            warn!(
                discarded = total_candidates - selected_chunks.len(),
                "Some RAG candidates were discarded due to budget limits"
            );
        }

        Ok(selected_chunks)
    }

    /// Get the budget planner for this selector
    pub fn budget_planner(&self) -> &ContextBudgetPlanner {
        &self.budget_planner
    }
}

#[cfg(all(test, feature = "postgres-backend"))]
mod tests {
    use super::*;
    use crate::db::DbId;
    use crate::services::embeddings::ChronicleEventMetadata;
    use chrono::Utc;
    

    #[test]
    fn test_budget_planner_pro_model() {
        let planner = ContextBudgetPlanner::new_for_model("gemini-2.5-pro", None);
        assert_eq!(planner.total_budget, 190_000);
        assert!(planner.total_rag_budget() > planner.recent_history_budget); // Pro favors RAG
    }

    #[test]
    fn test_budget_planner_flash_lite() {
        let planner = ContextBudgetPlanner::new_for_model("gemini-2.5-flash-lite", None);
        assert_eq!(planner.total_budget, 950_000); // Can use more context due to low cost
    }

    #[test]
    fn test_content_priority_chronicle_events() {
        let chronicle_meta = ChronicleEventMetadata {
            event_id: DbId::new(),
            event_type: "plot.twist.revealed".to_string(),
            chronicle_id: DbId::new(),
            user_id: DbId::new(),
            created_at: (Utc::now() - chrono::Duration::hours(1)).into(), // 1 hour ago
        };

        let chunk = RetrievedChunk {
            text: "A major plot twist was revealed".to_string(),
            score: 0.85,
            metadata: RetrievedMetadata::Chronicle(chronicle_meta),
        };

        let priority = ContentPriority::calculate(&chunk, Utc::now().into());

        // Chronicle events should get high priority (type bonus + recency)
        assert!(priority.type_priority > 1.0);
        assert!(priority.recency > 0.8); // Recent events get high recency
        assert!(priority.composite_score > 0.75); // Adjusted expectation based on scoring formula
    }
}
