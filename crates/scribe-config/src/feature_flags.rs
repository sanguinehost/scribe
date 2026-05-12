use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NarrativeFeatureFlags {
    #[serde(default = "default_true")]
    pub agentic_narrative_processing: bool,
    #[serde(default = "default_false")]
    pub recursive_context_expansion: bool,
    #[serde(default = "default_false")]
    pub multi_agent_debate_mode: bool,
    #[serde(default = "default_true")]
    pub prompt_security_audit: bool,
}

fn default_true() -> bool { true }
fn default_false() -> bool { false }
