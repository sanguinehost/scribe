use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for Entity Dependency Analysis
/// Ensures AI generates valid dependency analysis with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDependencyOutput {
    pub explicit_dependencies: Vec<EntityDependency>, // Entities explicitly mentioned in plan steps
    pub implicit_dependencies: Vec<EntityDependency>, // Entities implied but not directly stated
    pub contextual_dependencies: Vec<EntityDependency>, // Entities needed for context/environment
    pub dependency_graph: Vec<DependencyRelation>, // Relationships between dependencies
    pub confidence_score: f32, // Overall confidence in the analysis (0.0-1.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDependency {
    pub entity_name: String,
    pub dependency_type: String, // "required", "optional", "contextual", "environmental"
    pub reason: String, // Why this entity is a dependency
    pub confidence: f32, // Confidence in this specific dependency (0.0-1.0)
    pub source_steps: Vec<usize>, // Which plan steps reference this entity (0-indexed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRelation {
    pub from_entity: String,
    pub to_entity: String,
    pub relation_type: String, // "depends_on", "provides_context_for", "interacts_with"
    pub strength: f32, // Strength of the dependency (0.0-1.0)
}

/// Helper function to create the JSON schema for entity dependency analysis
pub fn get_entity_dependency_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "explicit_dependencies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the entity that is a dependency"
                        },
                        "dependency_type": {
                            "type": "string",
                            "enum": ["required", "optional", "contextual", "environmental"],
                            "description": "Type of dependency"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Explanation of why this entity is a dependency"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this dependency (0.0-1.0)"
                        },
                        "source_steps": {
                            "type": "array",
                            "items": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "description": "Plan step indices that reference this entity"
                        }
                    },
                    "required": ["entity_name", "dependency_type", "reason", "confidence", "source_steps"]
                },
                "description": "Entities explicitly mentioned in the plan steps"
            },
            "implicit_dependencies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the implicitly required entity"
                        },
                        "dependency_type": {
                            "type": "string",
                            "enum": ["required", "optional", "contextual", "environmental"],
                            "description": "Type of dependency"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why this entity is implicitly needed"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this implicit dependency"
                        },
                        "source_steps": {
                            "type": "array",
                            "items": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "description": "Plan steps that imply this dependency"
                        }
                    },
                    "required": ["entity_name", "dependency_type", "reason", "confidence", "source_steps"]
                },
                "description": "Entities implied but not directly stated in the plan"
            },
            "contextual_dependencies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the contextual entity"
                        },
                        "dependency_type": {
                            "type": "string",
                            "enum": ["required", "optional", "contextual", "environmental"],
                            "description": "Type of dependency"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why this entity provides necessary context"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this contextual dependency"
                        },
                        "source_steps": {
                            "type": "array",
                            "items": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "description": "Plan steps that benefit from this context"
                        }
                    },
                    "required": ["entity_name", "dependency_type", "reason", "confidence", "source_steps"]
                },
                "description": "Entities needed for context or environment"
            },
            "dependency_graph": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "from_entity": {
                            "type": "string",
                            "description": "Source entity in the dependency relationship"
                        },
                        "to_entity": {
                            "type": "string",
                            "description": "Target entity in the dependency relationship"
                        },
                        "relation_type": {
                            "type": "string",
                            "enum": ["depends_on", "provides_context_for", "interacts_with", "requires_presence_of"],
                            "description": "Type of relationship between entities"
                        },
                        "strength": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Strength of the dependency relationship"
                        }
                    },
                    "required": ["from_entity", "to_entity", "relation_type", "strength"]
                },
                "description": "Relationships between the identified dependencies"
            },
            "confidence_score": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the dependency analysis"
            }
        },
        "required": [
            "explicit_dependencies",
            "implicit_dependencies",
            "contextual_dependencies",
            "dependency_graph",
            "confidence_score"
        ]
    })
}

/// Validation for structured output
impl EntityDependencyOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence score
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err(AppError::InvalidInput(
                "Overall confidence score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate explicit dependencies
        for dep in &self.explicit_dependencies {
            if dep.entity_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Entity name cannot be empty".to_string()
                ));
            }
            if dep.confidence < 0.0 || dep.confidence > 1.0 {
                return Err(AppError::InvalidInput(
                    "Dependency confidence must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate implicit dependencies
        for dep in &self.implicit_dependencies {
            if dep.entity_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Implicit entity name cannot be empty".to_string()
                ));
            }
            if dep.confidence < 0.0 || dep.confidence > 1.0 {
                return Err(AppError::InvalidInput(
                    "Implicit dependency confidence must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate dependency graph
        for relation in &self.dependency_graph {
            if relation.from_entity.trim().is_empty() || relation.to_entity.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Dependency relation entities cannot be empty".to_string()
                ));
            }
            if relation.strength < 0.0 || relation.strength > 1.0 {
                return Err(AppError::InvalidInput(
                    "Relation strength must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Convert to a simple list of all entity names for backward compatibility
    pub fn to_entity_list(&self) -> Vec<String> {
        let mut entities = Vec::new();
        let mut seen = std::collections::HashSet::new();
        
        // Add explicit dependencies
        for dep in &self.explicit_dependencies {
            if seen.insert(dep.entity_name.clone()) {
                entities.push(dep.entity_name.clone());
            }
        }
        
        // Add implicit dependencies with high confidence
        for dep in &self.implicit_dependencies {
            if dep.confidence >= 0.7 && seen.insert(dep.entity_name.clone()) {
                entities.push(dep.entity_name.clone());
            }
        }
        
        // Add contextual dependencies marked as required
        for dep in &self.contextual_dependencies {
            if dep.dependency_type == "required" && seen.insert(dep.entity_name.clone()) {
                entities.push(dep.entity_name.clone());
            }
        }
        
        entities
    }
}