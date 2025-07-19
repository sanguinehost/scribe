//! Dynamic Query Registry System
//! 
//! This module provides a self-registering system for query types and strategies.
//! Each query implementation registers itself automatically at startup.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    errors::AppError,
    services::query_strategy_planner::PlannedQuery,
};

/// Global query registry instance
static QUERY_REGISTRY: Lazy<Arc<RwLock<QueryRegistry>>> = Lazy::new(|| {
    Arc::new(RwLock::new(QueryRegistry::new()))
});

/// Trait that all query types must implement
#[async_trait]
pub trait QueryType: Send + Sync {
    /// Unique name for this query type
    fn name(&self) -> &'static str;
    
    /// Human-readable description
    fn description(&self) -> &'static str;
    
    /// When to use this query
    fn usage_guidance(&self) -> &'static str;
    
    /// What this query returns
    fn returns_description(&self) -> &'static str;
    
    /// Get parameter metadata
    fn parameters(&self) -> QueryParameters;
    
    /// Dependencies on other queries
    fn dependencies(&self) -> Vec<&'static str> {
        vec![]
    }
    
    /// Typical token usage
    fn typical_tokens(&self) -> u32 {
        500
    }
    
    /// Execute the query with the given parameters
    async fn execute(
        &self,
        params: HashMap<String, JsonValue>,
        context: QueryContext,
    ) -> Result<JsonValue, AppError>;
    
    /// Validate parameters before execution
    fn validate_params(&self, params: &HashMap<String, JsonValue>) -> Result<(), AppError> {
        let param_meta = self.parameters();
        
        // Check required parameters
        for required in &param_meta.required {
            if !params.contains_key(required.name) {
                return Err(AppError::InvalidInput(
                    format!("Missing required parameter: {}", required.name)
                ));
            }
        }
        
        Ok(())
    }
}

/// Trait for query strategies
pub trait QueryStrategy: Send + Sync {
    /// Unique name for this strategy
    fn name(&self) -> &'static str;
    
    /// Human-readable description
    fn description(&self) -> &'static str;
    
    /// When to use this strategy
    fn usage_guidance(&self) -> &'static str;
    
    /// Query types commonly used with this strategy
    fn common_queries(&self) -> Vec<&'static str>;
    
    /// Example scenario
    fn example_scenario(&self) -> &'static str;
}

/// Parameter metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParameters {
    pub required: Vec<ParameterMetadata>,
    pub optional: Vec<ParameterMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterMetadata {
    pub name: &'static str,
    pub type_name: &'static str,
    pub description: &'static str,
    pub example: JsonValue,
}

/// Context passed to query execution
pub struct QueryContext {
    pub user_id: Uuid,
    pub session_id: Option<Uuid>,
    pub db_pool: Arc<crate::PgPool>,
    pub ai_client: Arc<dyn crate::llm::AiClient>,
    pub encryption_service: Arc<crate::services::EncryptionService>,
    pub user_dek: Option<Arc<secrecy::SecretBox<Vec<u8>>>>,
}

/// Dynamic query registry
pub struct QueryRegistry {
    query_types: HashMap<String, Arc<dyn QueryType>>,
    strategies: HashMap<String, Arc<dyn QueryStrategy>>,
}

impl QueryRegistry {
    fn new() -> Self {
        Self {
            query_types: HashMap::new(),
            strategies: HashMap::new(),
        }
    }
    
    /// Register a query type
    pub fn register_query_type(query_type: Arc<dyn QueryType>) -> Result<(), AppError> {
        let mut registry = QUERY_REGISTRY.write().map_err(|_| {
            AppError::InternalError("Failed to acquire registry write lock".to_string())
        })?;
        
        let name = query_type.name().to_string();
        if registry.query_types.contains_key(&name) {
            return Err(AppError::InvalidInput(
                format!("Query type '{}' already registered", name)
            ));
        }
        
        registry.query_types.insert(name, query_type);
        Ok(())
    }
    
    /// Register a strategy
    pub fn register_strategy(strategy: Arc<dyn QueryStrategy>) -> Result<(), AppError> {
        let mut registry = QUERY_REGISTRY.write().map_err(|_| {
            AppError::InternalError("Failed to acquire registry write lock".to_string())
        })?;
        
        let name = strategy.name().to_string();
        if registry.strategies.contains_key(&name) {
            return Err(AppError::InvalidInput(
                format!("Strategy '{}' already registered", name)
            ));
        }
        
        registry.strategies.insert(name, strategy);
        Ok(())
    }
    
    /// Get a query type by name
    pub fn get_query_type(name: &str) -> Option<Arc<dyn QueryType>> {
        let registry = QUERY_REGISTRY.read().ok()?;
        registry.query_types.get(name).cloned()
    }
    
    /// Execute a planned query
    pub async fn execute_query(
        planned_query: &PlannedQuery,
        context: QueryContext,
    ) -> Result<JsonValue, AppError> {
        let query_type_name = format!("{:?}", planned_query.query_type);
        
        let query_type = Self::get_query_type(&query_type_name)
            .ok_or_else(|| AppError::InvalidInput(
                format!("Unknown query type: {}", query_type_name)
            ))?;
        
        // Validate parameters
        query_type.validate_params(&planned_query.parameters)?;
        
        // Execute the query
        query_type.execute(planned_query.parameters.clone(), context).await
    }
    
    /// Get all registered query type names
    pub fn get_query_type_names() -> Vec<String> {
        let registry = QUERY_REGISTRY.read().unwrap();
        registry.query_types.keys().cloned().collect()
    }
    
    /// Get all registered strategy names
    pub fn get_strategy_names() -> Vec<String> {
        let registry = QUERY_REGISTRY.read().unwrap();
        registry.strategies.keys().cloned().collect()
    }
    
    /// Generate documentation for all query types
    pub fn generate_query_type_documentation() -> String {
        let registry = QUERY_REGISTRY.read().unwrap();
        let mut doc = String::from("AVAILABLE QUERY TYPES - Dynamic Registry:\n\n");
        
        for (name, query_type) in &registry.query_types {
            doc.push_str(&format!("{}:\n", name));
            doc.push_str(&format!("  Description: {}\n", query_type.description()));
            doc.push_str(&format!("  When to use: {}\n", query_type.usage_guidance()));
            doc.push_str(&format!("  Returns: {}\n", query_type.returns_description()));
            
            let params = query_type.parameters();
            if !params.required.is_empty() {
                doc.push_str("  Required parameters:\n");
                for param in &params.required {
                    doc.push_str(&format!("    - {} ({}): {}\n", 
                        param.name, param.type_name, param.description));
                }
            }
            
            if !params.optional.is_empty() {
                doc.push_str("  Optional parameters:\n");
                for param in &params.optional {
                    doc.push_str(&format!("    - {} ({}): {}\n", 
                        param.name, param.type_name, param.description));
                }
            }
            
            doc.push_str(&format!("  Typical tokens: {}\n\n", query_type.typical_tokens()));
        }
        
        doc
    }
    
    /// Generate documentation for all strategies
    pub fn generate_strategy_documentation() -> String {
        let registry = QUERY_REGISTRY.read().unwrap();
        let mut doc = String::from("\nAVAILABLE STRATEGIES - Dynamic Registry:\n\n");
        
        for (name, strategy) in &registry.strategies {
            doc.push_str(&format!("{}:\n", name));
            doc.push_str(&format!("  Description: {}\n", strategy.description()));
            doc.push_str(&format!("  When to use: {}\n", strategy.usage_guidance()));
            doc.push_str(&format!("  Common queries: {}\n", strategy.common_queries().join(", ")));
            doc.push_str(&format!("  Example: {}\n\n", strategy.example_scenario()));
        }
        
        doc
    }
}

// Macro to simplify query type registration
#[macro_export]
macro_rules! register_query_type {
    ($type:ty) => {
        {
            let query_type = Arc::new(<$type>::new());
            QueryRegistry::register_query_type(query_type)
                .expect(&format!("Failed to register query type: {}", stringify!($type)));
        }
    };
}

// Example implementation for EntityEvents query type
pub struct EntityEventsQuery;

impl EntityEventsQuery {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl QueryType for EntityEventsQuery {
    fn name(&self) -> &'static str {
        "EntityEvents"
    }
    
    fn description(&self) -> &'static str {
        "Retrieve all events involving specific entities"
    }
    
    fn usage_guidance(&self) -> &'static str {
        "Use when you need to understand what happened to or was done by specific characters/entities"
    }
    
    fn returns_description(&self) -> &'static str {
        "List of events with timestamps, descriptions, and involved entities"
    }
    
    fn parameters(&self) -> QueryParameters {
        QueryParameters {
            required: vec![
                ParameterMetadata {
                    name: "entity_names",
                    type_name: "Vec<String>",
                    description: "List of entity names to query events for",
                    example: serde_json::json!(["Alice", "Bob"]),
                },
            ],
            optional: vec![
                ParameterMetadata {
                    name: "time_scope",
                    type_name: "String",
                    description: "Time range to search: 'recent', 'all', or specific date range",
                    example: serde_json::json!("recent"),
                },
                ParameterMetadata {
                    name: "max_results",
                    type_name: "u32",
                    description: "Maximum number of events to return",
                    example: serde_json::json!(20),
                },
            ],
        }
    }
    
    fn typical_tokens(&self) -> u32 {
        500
    }
    
    async fn execute(
        &self,
        params: HashMap<String, JsonValue>,
        context: QueryContext,
    ) -> Result<JsonValue, AppError> {
        // Implementation would go here - this would call the actual
        // entity event query logic using the context's database pool, etc.
        
        // For now, return a placeholder
        Ok(serde_json::json!({
            "entities": params.get("entity_names").cloned().unwrap_or_default(),
            "events": [],
            "time_scope": params.get("time_scope").cloned().unwrap_or(serde_json::json!("all"))
        }))
    }
}

// Function to register all query types - called at startup
pub fn register_all_query_types() -> Result<(), AppError> {
    // Each query type implementation would register itself
    register_query_type!(EntityEventsQuery);
    // register_query_type!(EntityCurrentStateQuery);
    // register_query_type!(CausalChainQuery);
    // ... etc
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dynamic_registration() {
        // Clear registry for test
        {
            let mut registry = QUERY_REGISTRY.write().unwrap();
            registry.query_types.clear();
        }
        
        // Register a query type
        let query = Arc::new(EntityEventsQuery::new());
        QueryRegistry::register_query_type(query).unwrap();
        
        // Verify it's registered
        let names = QueryRegistry::get_query_type_names();
        assert!(names.contains(&"EntityEvents".to_string()));
        
        // Get and use the query type
        let query_type = QueryRegistry::get_query_type("EntityEvents").unwrap();
        assert_eq!(query_type.name(), "EntityEvents");
    }
}