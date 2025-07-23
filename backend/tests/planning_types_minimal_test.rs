// Minimal test to verify planning types work
use scribe_backend::services::planning::types::*;

#[test]
fn test_planning_types_compile() {
    // Test ActionName serialization
    let action = ActionName::FindEntity;
    let serialized = serde_json::to_string(&action).unwrap();
    assert_eq!(serialized, "\"find_entity\"");
    
    // Test Plan structure
    let plan = Plan {
        goal: "Test goal".to_string(),
        actions: vec![],
        metadata: PlanMetadata {
            estimated_duration: Some(100),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    assert_eq!(plan.goal, "Test goal");
    assert_eq!(plan.metadata.confidence, 0.9);
    
    println!("Planning types compile and work correctly!");
}