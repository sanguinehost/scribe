
#[derive(Debug, Clone, Default)]
pub struct RagBudget {
    pub total_limit: usize,
    pub recent_history_tokens: usize,
    pub available_rag_tokens: usize,
    pub lorebook_soft_cap: usize,
    pub chronicle_soft_cap: usize,
    pub older_chat_soft_cap: usize,
}

pub struct RagWaterfallManager {
    total_budget: usize,
}

impl RagWaterfallManager {
    pub fn new(total_budget: usize) -> Self {
        Self { total_budget }
    }

    /// Calculates the token budget for each RAG category based on the Waterfall strategy.
    pub fn calculate_budget(&self) -> RagBudget {
        let recent_history = (self.total_budget as f64 * 0.3) as usize;
        let available_rag = self.total_budget.saturating_sub(recent_history);
        
        let lorebook_cap = (available_rag as f64 * 0.4) as usize;
        let chronicle_cap = (available_rag as f64 * 0.4) as usize;
        let older_chat_cap = available_rag; // Flows from remaining

        RagBudget {
            total_limit: self.total_budget,
            recent_history_tokens: recent_history,
            available_rag_tokens: available_rag,
            lorebook_soft_cap: lorebook_cap,
            chronicle_soft_cap: chronicle_cap,
            older_chat_soft_cap: older_chat_cap,
        }
    }

    /// Enforces the waterfall logic: tokens not used by lorebooks flow to chronicles, etc.
    pub fn allocate_tokens(&self, used_lorebook: usize, used_chronicle: usize) -> RagBudget {
        let budget = self.calculate_budget();
        let remaining_after_lore = budget.available_rag_tokens.saturating_sub(used_lorebook);
        
        // Chronicles can use up to their cap OR remaining after lore
        let chronicle_max = budget.chronicle_soft_cap.max(remaining_after_lore);
        let used_chronicle_actual = used_chronicle.min(chronicle_max);
        
        let remaining_after_chronicle = remaining_after_lore.saturating_sub(used_chronicle_actual);
        
        RagBudget {
            total_limit: self.total_budget,
            recent_history_tokens: budget.recent_history_tokens,
            available_rag_tokens: budget.available_rag_tokens,
            lorebook_soft_cap: used_lorebook,
            chronicle_soft_cap: used_chronicle_actual,
            older_chat_soft_cap: remaining_after_chronicle,
        }
    }
}
