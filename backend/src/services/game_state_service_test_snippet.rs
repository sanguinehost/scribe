
    #[test]
    fn test_last_turn_changes_persistence() {
        let current = GameState::default();
        let mut new = GameState::default();
        
        // Add an item in the new state
        new.inventory.push(InventoryItem {
            id: "gold_coin".to_string(),
            name: "Gold Coin".to_string(),
            quantity: 50,
            description: None,
            category: Some("Currency".to_string()),
            equipped: false,
            properties: HashMap::new(),
            staleness_count: 0,
        });

        let result = reconcile_pure(&current, &new, "Found some gold");
        
        // Verify changes were applied
        assert_eq!(result.applied_changes.len(), 1);
        
        // Verify custom_data contains the summary
        assert!(result.final_state.custom_data.contains_key("last_turn_changes"));
        let summary = result.final_state.custom_data.get("last_turn_changes").unwrap().as_str().unwrap();
        
        assert!(summary.contains("Added item: Gold Coin (x50)"));
    }
