// backend/src/services/task_queue/mod.rs
//
// Task Queue Service for Epic 8: Orchestrator-Driven Intelligent Agent System
// Provides durable task queue with end-to-end encryption for background enrichment

pub mod types;
pub mod service;

pub use types::*;
pub use service::TaskQueueService;