//! Chronicle Event Listener Service
//!
//! This service implements Phase 4.1.1 of the ECS Architecture Plan:
//! - Subscribes to chronicle event creation/updates
//! - Processes events to derive ECS state changes
//! - Handles event reprocessing for state reconstruction
//! - Maintains chronicle system unchanged (no dual writes needed)
//!
//! Key Features:
//! - Toggle-able via feature flags
//! - Graceful degradation when ECS is disabled
//! - Backwards compatibility with chronicle-only mode
//! - User-scoped processing with privacy preservation

use std::sync::Arc;
use uuid::Uuid;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug, instrument};

use crate::{
    config::NarrativeFeatureFlags,
    errors::AppError,
    services::{
        chronicle_ecs_translator::{
            ChronicleEcsTranslator, 
            ComponentUpdate as TranslatorComponentUpdate, 
            ComponentOperation as TranslatorComponentOperation,
            RelationshipUpdate
        },
        ecs_entity_manager::{EcsEntityManager, ComponentUpdate, ComponentOperation},
        chronicle_service::ChronicleService,
    },
};

/// Event notification from chronicle system
#[derive(Debug, Clone)]
pub struct ChronicleEventNotification {
    pub event_id: Uuid,
    pub user_id: Uuid,
    pub chronicle_id: Uuid,
    pub event_type: String,
    pub notification_type: ChronicleNotificationType,
}

/// Type of chronicle event notification
#[derive(Debug, Clone, PartialEq)]
pub enum ChronicleNotificationType {
    /// New event was created
    Created,
    /// Existing event was updated
    Updated,
    /// Event was deleted
    Deleted,
    /// Chronicle was re-processed (bulk update)
    BulkUpdate { event_count: usize },
}

/// Result of processing a chronicle event notification
#[derive(Debug, Clone)]
pub struct ChronicleEventProcessingResult {
    pub notification_id: String,
    pub user_id: Uuid,
    pub entities_affected: Vec<Uuid>,
    pub components_updated: usize,
    pub processing_time_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub skipped_reason: Option<String>,
}

/// Configuration for the chronicle event listener
#[derive(Debug, Clone)]
pub struct ChronicleEventListenerConfig {
    /// Maximum number of events to process in parallel
    pub max_concurrent_events: usize,
    /// Buffer size for the event notification channel
    pub event_buffer_size: usize,
    /// Timeout for processing individual events (seconds)
    pub event_processing_timeout_secs: u64,
    /// Enable detailed metrics collection
    pub enable_metrics: bool,
    /// Batch size for bulk operations
    pub bulk_processing_batch_size: usize,
}

impl Default for ChronicleEventListenerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_events: 10,
            event_buffer_size: 1000,
            event_processing_timeout_secs: 30,
            enable_metrics: true,
            bulk_processing_batch_size: 50,
        }
    }
}

/// Chronicle Event Listener Service
///
/// This service bridges the chronicle system and ECS by listening for chronicle
/// events and updating ECS state accordingly. It respects feature flags and
/// provides graceful degradation.
pub struct ChronicleEventListener {
    /// Configuration
    config: ChronicleEventListenerConfig,
    /// Feature flags for toggle control
    feature_flags: Arc<NarrativeFeatureFlags>,
    /// Translation service for chronicle events to ECS
    translator: Arc<ChronicleEcsTranslator>,
    /// ECS entity manager for state updates
    entity_manager: Arc<EcsEntityManager>,
    /// Chronicle service for fetching events
    chronicle_service: Arc<ChronicleService>,
    /// Channel for receiving event notifications
    event_receiver: Option<mpsc::Receiver<ChronicleEventNotification>>,
    /// Channel sender for external systems to send notifications
    event_sender: mpsc::Sender<ChronicleEventNotification>,
    /// Processing metrics
    metrics: ChronicleEventListenerMetrics,
}

/// Metrics for the chronicle event listener
#[derive(Debug, Clone, Default)]
pub struct ChronicleEventListenerMetrics {
    pub events_processed: u64,
    pub events_skipped: u64,
    pub events_failed: u64,
    pub entities_created: u64,
    pub entities_updated: u64,
    pub components_modified: u64,
    pub avg_processing_time_ms: f64,
    pub total_processing_time_ms: u64,
}

impl ChronicleEventListener {
    /// Create a new chronicle event listener
    pub fn new(
        config: ChronicleEventListenerConfig,
        feature_flags: Arc<NarrativeFeatureFlags>,
        translator: Arc<ChronicleEcsTranslator>,
        entity_manager: Arc<EcsEntityManager>,
        chronicle_service: Arc<ChronicleService>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::channel(config.event_buffer_size);
        
        Self {
            config,
            feature_flags,
            translator,
            entity_manager,
            chronicle_service,
            event_receiver: Some(event_receiver),
            event_sender,
            metrics: ChronicleEventListenerMetrics::default(),
        }
    }
    
    /// Get a sender handle for external systems to send event notifications
    pub fn get_event_sender(&self) -> mpsc::Sender<ChronicleEventNotification> {
        self.event_sender.clone()
    }
    
    /// Start the event listener service
    ///
    /// This spawns a background task that processes chronicle event notifications.
    /// The service respects feature flags and will gracefully handle disabled states.
    #[instrument(skip(self), fields(service = "chronicle_event_listener"))]
    pub async fn start(&mut self) -> Result<(), AppError> {
        if !self.feature_flags.enable_ecs_system {
            info!("Chronicle event listener disabled - ECS system not enabled");
            return Ok(());
        }
        
        info!(
            max_concurrent = self.config.max_concurrent_events,
            buffer_size = self.config.event_buffer_size,
            "Starting chronicle event listener"
        );
        
        let receiver = self.event_receiver.take()
            .ok_or_else(|| AppError::ConfigError("Event receiver already taken".to_string()))?;
        
        let translator = Arc::clone(&self.translator);
        let entity_manager = Arc::clone(&self.entity_manager);
        let chronicle_service = Arc::clone(&self.chronicle_service);
        let feature_flags = Arc::clone(&self.feature_flags);
        let config = self.config.clone();
        
        // Spawn the main event processing loop
        tokio::spawn(async move {
            Self::event_processing_loop(
                receiver,
                translator,
                entity_manager,
                chronicle_service,
                feature_flags,
                config,
            ).await;
        });
        
        Ok(())
    }
    
    /// Main event processing loop
    async fn event_processing_loop(
        mut receiver: mpsc::Receiver<ChronicleEventNotification>,
        translator: Arc<ChronicleEcsTranslator>,
        entity_manager: Arc<EcsEntityManager>,
        chronicle_service: Arc<ChronicleService>,
        feature_flags: Arc<NarrativeFeatureFlags>,
        config: ChronicleEventListenerConfig,
    ) {
        info!("Chronicle event listener processing loop started");
        
        while let Some(notification) = receiver.recv().await {
            // Check if ECS sync is enabled for this user
            let user_id_str = notification.user_id.to_string();
            if !feature_flags.should_sync_chronicle_to_ecs(&user_id_str) {
                debug!(
                    user_id = %notification.user_id,
                    event_id = %notification.event_id,
                    "Skipping chronicle event - ECS sync not enabled for user"
                );
                continue;
            }
            
            // Process the event notification
            let result = Self::process_event_notification(
                notification,
                &translator,
                &entity_manager,
                &chronicle_service,
                &feature_flags,
                &config,
            ).await;
            
            // Log the result
            match result {
                Ok(processing_result) => {
                    if processing_result.success {
                        debug!(
                            event_id = %processing_result.notification_id,
                            user_id = %processing_result.user_id,
                            entities_affected = processing_result.entities_affected.len(),
                            components_updated = processing_result.components_updated,
                            processing_time_ms = processing_result.processing_time_ms,
                            "Chronicle event processed successfully"
                        );
                    } else {
                        warn!(
                            event_id = %processing_result.notification_id,
                            user_id = %processing_result.user_id,
                            error = processing_result.error_message.as_deref().unwrap_or("Unknown"),
                            "Chronicle event processing failed"
                        );
                    }
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to process chronicle event notification"
                    );
                }
            }
        }
        
        info!("Chronicle event listener processing loop stopped");
    }
    
    /// Process a single chronicle event notification
    #[instrument(skip(translator, entity_manager, chronicle_service, feature_flags, config))]
    async fn process_event_notification(
        notification: ChronicleEventNotification,
        translator: &ChronicleEcsTranslator,
        entity_manager: &EcsEntityManager,
        chronicle_service: &ChronicleService,
        feature_flags: &NarrativeFeatureFlags,
        config: &ChronicleEventListenerConfig,
    ) -> Result<ChronicleEventProcessingResult, AppError> {
        let start_time = std::time::Instant::now();
        let notification_id = format!("{}_{}", notification.event_id, notification.notification_type.as_str());
        
        // Handle different notification types
        match notification.notification_type {
            ChronicleNotificationType::Created | ChronicleNotificationType::Updated => {
                Self::process_single_event(
                    &notification,
                    translator,
                    entity_manager,
                    chronicle_service,
                    feature_flags,
                    config,
                    start_time,
                ).await
            }
            ChronicleNotificationType::Deleted => {
                Self::process_event_deletion(
                    &notification,
                    entity_manager,
                    start_time,
                ).await
            }
            ChronicleNotificationType::BulkUpdate { event_count } => {
                Self::process_bulk_update(
                    &notification,
                    translator,
                    entity_manager,
                    feature_flags,
                    config,
                    event_count,
                    start_time,
                ).await
            }
        }
    }
    
    /// Process a single chronicle event (created/updated)
    async fn process_single_event(
        notification: &ChronicleEventNotification,
        translator: &ChronicleEcsTranslator,
        entity_manager: &EcsEntityManager,
        chronicle_service: &ChronicleService,
        _feature_flags: &NarrativeFeatureFlags,
        _config: &ChronicleEventListenerConfig,
        start_time: std::time::Instant,
    ) -> Result<ChronicleEventProcessingResult, AppError> {
        debug!(
            event_id = %notification.event_id,
            user_id = %notification.user_id,
            chronicle_id = %notification.chronicle_id,
            "Processing single chronicle event for ECS state update"
        );
        
        // Fetch the chronicle event from the database
        let chronicle_event = match chronicle_service.get_event(notification.user_id, notification.event_id).await {
            Ok(event) => event,
            Err(e) => {
                error!(
                    event_id = %notification.event_id,
                    user_id = %notification.user_id,
                    error = %e,
                    "Failed to fetch chronicle event from database"
                );
                
                let processing_time_ms = start_time.elapsed().as_millis() as u64;
                return Ok(ChronicleEventProcessingResult {
                    notification_id: format!("{}_{}", notification.event_id, notification.notification_type.as_str()),
                    user_id: notification.user_id,
                    entities_affected: vec![],
                    components_updated: 0,
                    processing_time_ms,
                    success: false,
                    error_message: Some(format!("Failed to fetch event: {}", e)),
                    skipped_reason: None,
                });
            }
        };
        
        // Translate the chronicle event to ECS state changes
        let translation_result = match translator.translate_event(&chronicle_event, notification.user_id).await {
            Ok(result) => result,
            Err(e) => {
                error!(
                    event_id = %notification.event_id,
                    user_id = %notification.user_id,
                    error = %e,
                    "Failed to translate chronicle event to ECS changes"
                );
                
                let processing_time_ms = start_time.elapsed().as_millis() as u64;
                return Ok(ChronicleEventProcessingResult {
                    notification_id: format!("{}_{}", notification.event_id, notification.notification_type.as_str()),
                    user_id: notification.user_id,
                    entities_affected: vec![],
                    components_updated: 0,
                    processing_time_ms,
                    success: false,
                    error_message: Some(format!("Translation failed: {}", e)),
                    skipped_reason: None,
                });
            }
        };
        
        // Apply the ECS changes using the entity manager
        let mut entities_affected = Vec::new();
        let mut components_updated = 0;
        
        // Create/update entities
        for entity_id in &translation_result.entities_created {
            entities_affected.push(*entity_id);
        }
        
        // Convert translator component updates to entity manager component updates
        let mut component_updates_per_entity: std::collections::HashMap<Uuid, Vec<ComponentUpdate>> = std::collections::HashMap::new();
        
        for translator_update in &translation_result.component_updates {
            let entity_manager_update = ComponentUpdate {
                entity_id: translator_update.entity_id,
                component_type: translator_update.component_type.clone(),
                component_data: translator_update.component_data.clone(),
                operation: match translator_update.operation {
                    TranslatorComponentOperation::Create => ComponentOperation::Add,
                    TranslatorComponentOperation::Update => ComponentOperation::Update,
                    TranslatorComponentOperation::Delete => ComponentOperation::Remove,
                },
            };
            
            component_updates_per_entity
                .entry(translator_update.entity_id)
                .or_insert_with(Vec::new)
                .push(entity_manager_update);
        }
        
        // Apply component updates per entity
        for (entity_id, updates) in component_updates_per_entity {
            // First check if entity exists before updating components
            match entity_manager.get_entity(notification.user_id, entity_id).await {
                Ok(_) => {
                    // Entity exists, proceed with component updates
                    if let Err(e) = entity_manager.update_components(
                        notification.user_id,
                        entity_id,
                        updates.clone(),
                    ).await {
                        warn!(
                            entity_id = %entity_id,
                            updates_count = updates.len(),
                            error = %e,
                            "Failed to update components during chronicle event processing"
                        );
                    } else {
                        components_updated += updates.len();
                        if !entities_affected.contains(&entity_id) {
                            entities_affected.push(entity_id);
                        }
                    }
                }
                Err(AppError::NotFound(_)) => {
                    // Entity doesn't exist, create it first
                    debug!(
                        entity_id = %entity_id,
                        "Entity not found, creating entity before applying component updates"
                    );
                    
                    if let Err(e) = entity_manager.create_entity(
                        notification.user_id,
                        Some(entity_id),
                        "default".to_string(), // Default archetype signature
                        vec![], // Empty initial components
                    ).await {
                        warn!(
                            entity_id = %entity_id,
                            error = %e,
                            "Failed to create missing entity during chronicle event processing"
                        );
                        continue;
                    }
                    
                    // Now try component updates again
                    if let Err(e) = entity_manager.update_components(
                        notification.user_id,
                        entity_id,
                        updates.clone(),
                    ).await {
                        warn!(
                            entity_id = %entity_id,
                            updates_count = updates.len(),
                            error = %e,
                            "Failed to update components after creating entity"
                        );
                    } else {
                        components_updated += updates.len();
                        if !entities_affected.contains(&entity_id) {
                            entities_affected.push(entity_id);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        entity_id = %entity_id,
                        error = %e,
                        "Failed to check entity existence during chronicle event processing"
                    );
                }
            }
        }
        
        // Apply relationship updates
        for relationship_update in &translation_result.relationship_updates {
            // Note: We'd need to add relationship update methods to entity manager
            debug!(
                from_entity = %relationship_update.from_entity_id,
                to_entity = %relationship_update.to_entity_id,
                relationship_type = %relationship_update.relationship_type,
                "Applying relationship update (placeholder implementation)"
            );
            // For now, just track the entities involved
            if !entities_affected.contains(&relationship_update.from_entity_id) {
                entities_affected.push(relationship_update.from_entity_id);
            }
            if !entities_affected.contains(&relationship_update.to_entity_id) {
                entities_affected.push(relationship_update.to_entity_id);
            }
        }
        
        let processing_time_ms = start_time.elapsed().as_millis() as u64;
        
        info!(
            event_id = %notification.event_id,
            user_id = %notification.user_id,
            entities_affected = entities_affected.len(),
            components_updated = components_updated,
            processing_time_ms = processing_time_ms,
            "Successfully processed chronicle event for ECS state update"
        );
        
        Ok(ChronicleEventProcessingResult {
            notification_id: format!("{}_{}", notification.event_id, notification.notification_type.as_str()),
            user_id: notification.user_id,
            entities_affected,
            components_updated,
            processing_time_ms,
            success: true,
            error_message: None,
            skipped_reason: None,
        })
    }
    
    /// Process a chronicle event deletion
    async fn process_event_deletion(
        notification: &ChronicleEventNotification,
        _entity_manager: &EcsEntityManager,
        start_time: std::time::Instant,
    ) -> Result<ChronicleEventProcessingResult, AppError> {
        let processing_time_ms = start_time.elapsed().as_millis() as u64;
        
        // Event deletions might require removing derived ECS state
        // For now, we log and skip actual processing
        warn!(
            event_id = %notification.event_id,
            user_id = %notification.user_id,
            "Chronicle event deletion detected - ECS state cleanup may be needed"
        );
        
        Ok(ChronicleEventProcessingResult {
            notification_id: format!("{}_{}", notification.event_id, notification.notification_type.as_str()),
            user_id: notification.user_id,
            entities_affected: vec![],
            components_updated: 0,
            processing_time_ms,
            success: true,
            error_message: None,
            skipped_reason: Some("Event deletion handling not implemented".to_string()),
        })
    }
    
    /// Process a bulk chronicle update
    async fn process_bulk_update(
        notification: &ChronicleEventNotification,
        _translator: &ChronicleEcsTranslator,
        _entity_manager: &EcsEntityManager,
        _feature_flags: &NarrativeFeatureFlags,
        _config: &ChronicleEventListenerConfig,
        event_count: usize,
        start_time: std::time::Instant,
    ) -> Result<ChronicleEventProcessingResult, AppError> {
        let processing_time_ms = start_time.elapsed().as_millis() as u64;
        
        info!(
            chronicle_id = %notification.chronicle_id,
            user_id = %notification.user_id,
            event_count = event_count,
            "Processing bulk chronicle update"
        );
        
        // Bulk updates would require reprocessing multiple events
        // This is typically used for re-chronicling operations
        
        Ok(ChronicleEventProcessingResult {
            notification_id: format!("bulk_{}_{}", notification.chronicle_id, notification.notification_type.as_str()),
            user_id: notification.user_id,
            entities_affected: vec![],
            components_updated: 0,
            processing_time_ms,
            success: true,
            error_message: None,
            skipped_reason: Some("Bulk update processing not implemented".to_string()),
        })
    }
    
    /// Get current processing metrics
    pub fn get_metrics(&self) -> ChronicleEventListenerMetrics {
        self.metrics.clone()
    }
    
    /// Send a chronicle event notification to be processed
    ///
    /// This is used by external systems (like the chronicle service) to notify
    /// the listener of new/updated events.
    pub async fn notify_chronicle_event(&self, notification: ChronicleEventNotification) -> Result<(), AppError> {
        self.event_sender.send(notification).await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to send chronicle event notification: {}", e)))
    }
}

impl ChronicleNotificationType {
    fn as_str(&self) -> &'static str {
        match self {
            ChronicleNotificationType::Created => "created",
            ChronicleNotificationType::Updated => "updated", 
            ChronicleNotificationType::Deleted => "deleted",
            ChronicleNotificationType::BulkUpdate { .. } => "bulk_update",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NarrativeFeatureFlags;
    
    #[test]
    fn test_feature_flag_ecs_user_determination() {
        let mut flags = NarrativeFeatureFlags::default();
        flags.enable_ecs_system = true;
        flags.ecs_rollout_percentage = 50;
        
        // Test consistent results for same user
        let user_id = "test_user_123";
        let result1 = flags.should_use_ecs_for_user(user_id);
        let result2 = flags.should_use_ecs_for_user(user_id);
        assert_eq!(result1, result2);
        
        // Test disabled system
        flags.enable_ecs_system = false;
        assert!(!flags.should_use_ecs_for_user(user_id));
    }
    
    #[test]
    fn test_chronicle_to_ecs_sync_flags() {
        let mut flags = NarrativeFeatureFlags::default();
        flags.enable_ecs_system = true;
        flags.enable_chronicle_to_ecs_sync = true;
        flags.ecs_rollout_percentage = 100;
        
        let user_id = "test_user";
        assert!(flags.should_sync_chronicle_to_ecs(user_id));
        
        flags.enable_chronicle_to_ecs_sync = false;
        assert!(!flags.should_sync_chronicle_to_ecs(user_id));
    }
    
    #[test] 
    fn test_chronicle_notification_type_string_conversion() {
        assert_eq!(ChronicleNotificationType::Created.as_str(), "created");
        assert_eq!(ChronicleNotificationType::Updated.as_str(), "updated");
        assert_eq!(ChronicleNotificationType::Deleted.as_str(), "deleted");
        assert_eq!(ChronicleNotificationType::BulkUpdate { event_count: 10 }.as_str(), "bulk_update");
    }
}