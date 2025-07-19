// backend/src/services/rag_budget_manager.rs

use std::cmp::Ordering;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};

use crate::{
    errors::AppError,
    services::{
        embeddings::{RetrievedChunk, RetrievedMetadata},
        hybrid_token_counter::{HybridTokenCounter, CountingMode},
    },
};

/// Context budget planner that adapts to different Gemini model pricing tiers
#[derive(Debug, Clone)]
pub struct ContextBudgetPlanner {
    /// Total token budget to stay within pricing thresholds
    pub total_budget: usize,
    /// Budget allocated for recent chat history
    pub recent_history_budget: usize,
    /// Budget allocated for RAG content (lorebooks, chronicles, etc.)
    pub rag_budget: usize,
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
        let rag_budget = available_budget.saturating_sub(recent_history_budget);
        
        info!(
            model = %model,
            total_budget,
            recent_history_budget,
            rag_budget,
            system_prompt_overhead,
            "Created context budget plan"
        );
        
        Self {
            total_budget,
            recent_history_budget,
            rag_budget,
            system_prompt_overhead,
            target_model: model.to_string(),
        }
    }
    
    /// Get the available RAG budget
    pub fn available_rag_budget(&self) -> usize {
        self.rag_budget
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
    pub fn calculate(chunk: &RetrievedChunk, query_timestamp: DateTime<Utc>) -> Self {
        let relevance = chunk.score;
        
        // Calculate recency boost based on content type and timestamp
        let (recency, type_priority) = match &chunk.metadata {
            RetrievedMetadata::Chronicle(chronicle_meta) => {
                // Chronicle events: high priority, strong recency bias
                let days_old = (query_timestamp - chronicle_meta.created_at).num_days().max(0) as f32;
                let recency_boost = (1.0 / (1.0 + days_old / 30.0)).max(0.1); // Decay over ~30 days
                (recency_boost, 1.2) // 20% type bonus
            },
            RetrievedMetadata::Lorebook(_) => {
                // Lorebook entries: medium priority, less time-sensitive
                (0.8, 1.0) // Stable, no time decay
            },
            RetrievedMetadata::Chat(chat_meta) => {
                // Older chat: lower priority, moderate recency bias
                let days_old = (query_timestamp - chat_meta.timestamp).num_days().max(0) as f32;
                let recency_boost = (1.0 / (1.0 + days_old / 7.0)).max(0.2); // Decay over ~7 days
                (recency_boost, 0.8) // 20% type penalty (lower priority than new content)
            },
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
}

impl DynamicRagSelector {
    /// Create a new dynamic RAG selector
    pub fn new(token_counter: HybridTokenCounter, budget_planner: ContextBudgetPlanner) -> Self {
        Self {
            token_counter,
            budget_planner,
        }
    }
    
    /// Select RAG content within the available token budget, prioritized by relevance and type
    pub async fn select_rag_content(
        &self,
        candidates: Vec<RetrievedChunk>,
        query_timestamp: Option<DateTime<Utc>>,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        let available_budget = self.budget_planner.available_rag_budget();
        let query_time = query_timestamp.unwrap_or_else(Utc::now);
        
        debug!(
            num_candidates = candidates.len(),
            available_budget,
            "Starting dynamic RAG selection"
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
            b.composite_score.partial_cmp(&a.composite_score).unwrap_or(Ordering::Equal)
        });
        
        debug!(
            "Prioritized candidates by score: {}",
            prioritized_candidates.iter()
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
            let chunk_tokens = match self.token_counter
                .count_tokens(&chunk.text, CountingMode::LocalOnly, Some(&self.budget_planner.target_model))
                .await
            {
                Ok(estimate) => estimate.total,
                Err(e) => {
                    warn!("Failed to count tokens for chunk, using character estimate: {}", e);
                    // Fallback: rough character-based estimate (4 chars per token)
                    chunk.text.len() / 4
                }
            };
            
            // Check if we can fit this chunk in the budget
            if selected_chunks.is_empty() || used_tokens + chunk_tokens <= available_budget {
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
                    used_tokens,
                    available_budget,
                    "Chunk exceeds budget, stopping selection"
                );
                break; // Budget exhausted
            }
        }
        
        info!(
            selected_count = selected_chunks.len(),
            total_candidates,
            used_tokens,
            available_budget,
            budget_utilization = format!("{:.1}%", (used_tokens as f32 / available_budget as f32) * 100.0),
            "Dynamic RAG selection completed"
        );
        
        Ok(selected_chunks)
    }
    
    /// Get the budget planner for this selector
    pub fn budget_planner(&self) -> &ContextBudgetPlanner {
        &self.budget_planner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::embeddings::ChronicleEventMetadata;
    use uuid::Uuid;
    
    #[test]
    fn test_budget_planner_pro_model() {
        let planner = ContextBudgetPlanner::new_for_model("gemini-2.5-pro", None);
        assert_eq!(planner.total_budget, 190_000);
        assert!(planner.rag_budget > planner.recent_history_budget); // Pro favors RAG
    }
    
    #[test]
    fn test_budget_planner_flash_lite() {
        let planner = ContextBudgetPlanner::new_for_model("gemini-2.5-flash-lite-preview-06-17", None);
        assert_eq!(planner.total_budget, 950_000); // Can use more context due to low cost
    }
    
    #[test]
    fn test_content_priority_chronicle_events() {
        let chronicle_meta = ChronicleEventMetadata {
            event_id: Uuid::new_v4(),
            event_type: "plot.twist.revealed".to_string(),
            chronicle_id: Uuid::new_v4(),
            created_at: Utc::now() - chrono::Duration::hours(1), // 1 hour ago
        };
        
        let chunk = RetrievedChunk {
            text: "A major plot twist was revealed".to_string(),
            score: 0.85,
            metadata: RetrievedMetadata::Chronicle(chronicle_meta),
        };
        
        let priority = ContentPriority::calculate(&chunk, Utc::now());
        
        // Chronicle events should get high priority (type bonus + recency)
        assert!(priority.type_priority > 1.0);
        assert!(priority.recency > 0.8); // Recent events get high recency
        assert!(priority.composite_score > 0.75); // Adjusted expectation based on scoring formula
    }
}