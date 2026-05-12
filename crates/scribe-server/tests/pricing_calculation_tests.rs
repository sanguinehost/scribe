#![cfg(feature = "postgres-backend")]
/// Tests for token pricing calculations to ensure correct per-1M pricing with markup
///
/// This test suite verifies:
/// - Credit calculations use industry-standard per-1M token pricing
/// - 20% markup is correctly applied to API costs
/// - Pricing matches real-world usage examples
/// - Edge cases are handled correctly
use serde_json;
use std::fs;

/// Test that the config file has the correct per-1M pricing structure
#[test]
fn test_config_has_per_million_pricing_structure() {
    let config_path = "config/subscription_tiers.json";
    let config_content =
        fs::read_to_string(config_path).expect("Failed to read subscription_tiers.json");

    let config: serde_json::Value =
        serde_json::from_str(&config_content).expect("Failed to parse subscription_tiers.json");

    // Verify the new structure exists
    let token_pricing = &config["credit_system"]["token_pricing"];
    assert!(
        !token_pricing.is_null(),
        "token_pricing section should exist"
    );

    // Check for markup_percentage
    let markup_percentage = token_pricing["markup_percentage"].as_f64();
    assert_eq!(
        markup_percentage,
        Some(20.0),
        "Markup percentage should be 20%"
    );

    // Check for base_api_costs structure
    let base_costs = &token_pricing["base_api_costs"];
    assert!(!base_costs.is_null(), "base_api_costs section should exist");

    // Verify Flash pricing (most common model)
    let flash_pricing = &base_costs["gemini-2.5-flash"];
    assert!(
        !flash_pricing.is_null(),
        "gemini-2.5-flash pricing should exist"
    );

    // Verify rates are per-million and match Google's API pricing
    let input_per_million = flash_pricing["input_per_million"].as_f64();
    let output_per_million = flash_pricing["output_per_million"].as_f64();

    assert_eq!(
        input_per_million,
        Some(0.30),
        "Flash input should be $0.30 per 1M tokens"
    );
    assert_eq!(
        output_per_million,
        Some(2.50),
        "Flash output should be $2.50 per 1M tokens"
    );
}

/// Calculate credits with markup for testing
/// 1 credit = $0.02 (based on Paddle pricing: 250 credits = $5)
fn calculate_credits_with_markup(
    tokens: i32,
    rate_per_million_dollars: f64,
    markup_percentage: f64,
) -> i32 {
    let base_cost_dollars = (tokens as f64 / 1_000_000.0) * rate_per_million_dollars;
    let markup_multiplier = 1.0 + (markup_percentage / 100.0);
    let customer_cost_dollars = base_cost_dollars * markup_multiplier;
    let credits = (customer_cost_dollars / 0.02).ceil() as i32; // 1 credit = $0.02
    credits
}

#[test]
fn test_credit_calculation_with_markup() {
    // Test gemini-2.5-flash pricing with 20% markup
    // Base API cost: $0.30/1M input, $2.50/1M output
    // With 20% markup: $0.36/1M input, $3.00/1M output
    // 1 credit = $0.02

    // Test 1M input tokens: $0.36 / $0.02 = 18 credits
    let input_credits = calculate_credits_with_markup(1_000_000, 0.30, 20.0);
    assert_eq!(
        input_credits, 18,
        "1M input tokens should cost 18 credits ($0.36)"
    );

    // Test 1M output tokens: $3.00 / $0.02 = 150 credits
    let output_credits = calculate_credits_with_markup(1_000_000, 2.50, 20.0);
    assert_eq!(
        output_credits, 150,
        "1M output tokens should cost 150 credits ($3.00)"
    );
}

#[test]
fn test_real_world_usage_example() {
    // From user's actual usage: 5,047,176 input + 160,294 output tokens
    // Expected cost: ~$1.91 base, ~$2.29 with 20% markup
    // 1 credit = $0.02, so ~$2.29 / $0.02 = ~115 credits

    let input_tokens = 5_047_176;
    let output_tokens = 160_294;

    // Calculate with 20% markup
    let input_credits = calculate_credits_with_markup(input_tokens, 0.30, 20.0);
    let output_credits = calculate_credits_with_markup(output_tokens, 2.50, 20.0);
    let total_credits = input_credits + output_credits;

    // Expected:
    // Input: 5,047,176 / 1M * $0.36 / $0.02 = 1.817 / 0.02 = 90.85 → 91 credits
    // Output: 160,294 / 1M * $3.00 / $0.02 = 0.481 / 0.02 = 24.05 → 25 credits
    // Total: 116 credits = $2.32

    assert_eq!(input_credits, 91, "Input credits should be 91");
    assert_eq!(output_credits, 25, "Output credits should be 25");
    assert_eq!(total_credits, 116, "Total should be 116 credits ($2.32)");

    // Verify this is a reasonable charge (~$2.32 for 5M tokens)
    assert!(
        total_credits >= 110 && total_credits <= 120,
        "Should charge approximately 115 credits for 5M tokens"
    );
}

#[test]
fn test_small_token_amounts() {
    // Test small amounts to verify ceiling behavior
    // Even 1 token should round up to at least 1 credit

    let one_token_credits = calculate_credits_with_markup(1, 0.30, 20.0);
    assert_eq!(
        one_token_credits, 1,
        "Even 1 token should cost at least 1 credit due to ceiling"
    );

    // 100 tokens: 0.0001M * $0.36 / $0.02 = 0.0018 → 1 credit
    let hundred_tokens = calculate_credits_with_markup(100, 0.30, 20.0);
    assert_eq!(hundred_tokens, 1, "100 tokens should cost 1 credit");

    // 10,000 tokens (0.01M): 0.01M * $0.36 / $0.02 = 0.18 → 1 credit
    let ten_k_tokens = calculate_credits_with_markup(10_000, 0.30, 20.0);
    assert_eq!(ten_k_tokens, 1, "10k tokens should cost 1 credit");
}

#[test]
fn test_zero_tokens() {
    let zero_credits = calculate_credits_with_markup(0, 0.30, 20.0);
    assert_eq!(zero_credits, 0, "Zero tokens should cost zero credits");
}

#[test]
fn test_large_token_amounts() {
    // Test very large amounts (100M tokens)
    let large_amount = 100_000_000;
    let large_credits = calculate_credits_with_markup(large_amount, 0.30, 20.0);

    // 100M tokens * $0.36/1M / $0.02 = $36 / $0.02 = 1,800 credits
    assert_eq!(
        large_credits, 1_800,
        "100M tokens should cost 1,800 credits ($36)"
    );
}

#[test]
fn test_pro_model_pricing() {
    // Test gemini-2.5-pro pricing
    // Base: $1.25/1M input, $10.00/1M output
    // With 20% markup: $1.50/1M input, $12.00/1M output
    // 1 credit = $0.02

    let pro_input = calculate_credits_with_markup(1_000_000, 1.25, 20.0);
    let pro_output = calculate_credits_with_markup(1_000_000, 10.0, 20.0);

    assert_eq!(
        pro_input, 75,
        "Pro input should be 75 credits per 1M ($1.50)"
    );
    assert_eq!(
        pro_output, 600,
        "Pro output should be 600 credits per 1M ($12.00)"
    );
}

#[test]
fn test_flash_lite_pricing() {
    // Test gemini-2.5-flash-lite pricing (correct pricing from Google)
    // Base: $0.10/1M input, $0.40/1M output
    // With 20% markup: $0.12/1M input, $0.48/1M output
    // 1 credit = $0.02

    let lite_input = calculate_credits_with_markup(1_000_000, 0.10, 20.0);
    let lite_output = calculate_credits_with_markup(1_000_000, 0.40, 20.0);

    assert_eq!(
        lite_input, 6,
        "Lite input should be 6 credits per 1M ($0.12)"
    );
    assert_eq!(
        lite_output, 24,
        "Lite output should be 24 credits per 1M ($0.48)"
    );
}

#[test]
fn test_markup_application() {
    // Verify that markup is correctly applied
    // Base: $0.30, Markup: 20%, Customer pays: $0.36
    // 1 credit = $0.02, so $0.36 / $0.02 = 18 credits

    let base_cost = 0.30;
    let markup_percentage = 20.0;
    let markup_multiplier = 1.0 + (markup_percentage / 100.0);
    let customer_cost = base_cost * markup_multiplier;

    assert_eq!(customer_cost, 0.36, "20% markup on $0.30 should be $0.36");

    // Verify in credits
    let credits = calculate_credits_with_markup(1_000_000, 0.30, 20.0);
    assert_eq!(
        credits, 18,
        "Should match customer cost of $0.36 / $0.02 = 18 credits"
    );
}

/// Integration test: Verify per-1k and per-1M approaches are equivalent
#[test]
fn test_per_1k_vs_per_1m_equivalence() {
    // The old per-1k config had:
    // "prompt_credits_per_1k": 0.018
    // "completion_credits_per_1k": 0.15
    //
    // These values represent credits directly (not dollars), where 1 credit = $0.02
    // So 0.018 credits/1k = 18 credits/1M
    // And 0.15 credits/1k = 150 credits/1M
    //
    // The new per-1M config has:
    // API cost: $0.30/1M input, $2.50/1M output
    // With 20% markup: $0.36/1M, $3.00/1M
    // In credits (÷ $0.02): 18 credits/1M, 150 credits/1M
    //
    // Both approaches should give the same result!

    let input_tokens = 5_047_176;
    let output_tokens = 160_294;

    // Old per-1k approach (credits directly)
    let old_input_credits = ((input_tokens as f64 / 1000.0) * 0.018).ceil() as i32;
    let old_output_credits = ((output_tokens as f64 / 1000.0) * 0.15).ceil() as i32;
    let old_total = old_input_credits + old_output_credits;

    // New per-1M approach (dollars → credits)
    let new_input_credits = calculate_credits_with_markup(input_tokens, 0.30, 20.0);
    let new_output_credits = calculate_credits_with_markup(output_tokens, 2.50, 20.0);
    let new_total = new_input_credits + new_output_credits;

    // Both should give approximately the same result (~115-116 credits)
    assert!(
        (old_total - new_total).abs() <= 1,
        "Per-1k and per-1M approaches should be equivalent. Old: {}, New: {}",
        old_total,
        new_total
    );

    // Verify both are in the expected range (~$2.30)
    assert!(
        old_total >= 110 && old_total <= 120,
        "Should charge approximately 115 credits for 5M tokens (old approach: {})",
        old_total
    );
    assert!(
        new_total >= 110 && new_total <= 120,
        "Should charge approximately 115 credits for 5M tokens (new approach: {})",
        new_total
    );
}
