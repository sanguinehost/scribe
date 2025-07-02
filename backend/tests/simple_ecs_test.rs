#![cfg(test)]

#[test]
fn test_can_import_ecs_types() {
    // Just try to import the types
    use scribe_backend::models::ecs::Entity;
    use scribe_backend::models::ecs::Component;
    use scribe_backend::models::ecs::ComponentRegistry;
    
    // If this compiles, the imports work
    assert!(true);
}