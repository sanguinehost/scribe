// @generated automatically by Diesel CLI.

pub mod sql_types_unified {
    #[cfg(feature = "postgres-backend")]
    pub use diesel::sql_types::Uuid as DbIdType;
    #[cfg(feature = "sqlite-backend")]
    pub use diesel::sql_types::Text as DbIdType;

    #[cfg(feature = "postgres-backend")]
    pub use diesel::sql_types::Timestamptz as DbTimestampType;
    #[cfg(feature = "sqlite-backend")]
    pub use diesel::sql_types::Timestamp as DbTimestampType;

    #[cfg(feature = "postgres-backend")]
    pub use diesel::sql_types::Jsonb as DbJsonType;
    #[cfg(feature = "sqlite-backend")]
    pub use diesel::sql_types::Text as DbJsonType;

    #[cfg(feature = "postgres-backend")]
    pub use diesel::sql_types::Numeric as DbNumericType;
    #[cfg(feature = "sqlite-backend")]
    pub use diesel::sql_types::Double as DbNumericType;
}


diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    agent_context_analysis (id) {
        id -> DbIdType,
        chat_session_id -> DbIdType,
        user_id -> DbIdType,
        analysis_type -> Text,
        agent_reasoning -> Nullable<Text>,
        agent_reasoning_nonce -> Nullable<Binary>,
        planned_searches -> Nullable<DbJsonType>,
        execution_log -> Nullable<DbJsonType>,
        execution_log_nonce -> Nullable<Binary>,
        retrieved_context -> Nullable<Text>,
        retrieved_context_nonce -> Nullable<Binary>,
        analysis_summary -> Nullable<Text>,
        analysis_summary_nonce -> Nullable<Binary>,
        total_tokens_used -> Nullable<Integer>,
        execution_time_ms -> Nullable<Integer>,
        model_used -> Nullable<Text>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
        message_id -> DbIdType,
        assistant_message_id -> Nullable<DbIdType>,
        status -> Text,
        error_message -> Nullable<Text>,
        retry_count -> Integer,
        superseded_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    #[cfg(feature = "postgres-backend")]
    use diesel::sql_types::Int4 as AssetIdType;
    #[cfg(feature = "sqlite-backend")]
    use diesel::sql_types::Text as AssetIdType;

    character_assets (id) {
        id -> AssetIdType,
        character_id -> DbIdType,
        asset_type -> Text,
        uri -> Nullable<Text>,
        name -> Text,
        ext -> Text,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        data -> Nullable<Binary>,
        content_type -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    character_lorebooks (character_id, lorebook_id) {
        character_id -> DbIdType,
        lorebook_id -> DbIdType,
        user_id -> DbIdType,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    characters (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        spec -> Text,
        spec_version -> Text,
        name -> Text,
        description -> Nullable<Binary>,
        personality -> Nullable<Binary>,
        scenario -> Nullable<Binary>,
        first_mes -> Nullable<Binary>,
        mes_example -> Nullable<Binary>,
        creator_notes -> Nullable<Binary>,
        system_prompt -> Nullable<Binary>,
        post_history_instructions -> Nullable<Binary>,
        tags -> Nullable<Array<Nullable<Text>>>,
        creator -> Nullable<Text>,
        character_version -> Nullable<Text>,
        alternate_greetings -> Nullable<Array<Nullable<Text>>>,
        nickname -> Nullable<Text>,
        creator_notes_multilingual -> Nullable<DbJsonType>,
        source -> Nullable<Array<Nullable<Text>>>,
        group_only_greetings -> Nullable<Array<Nullable<Text>>>,
        creation_date -> Nullable<DbTimestampType>,
        modification_date -> Nullable<DbTimestampType>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        persona -> Nullable<Binary>,
        world_scenario -> Nullable<Binary>,
        avatar -> Nullable<Text>,
        chat -> Nullable<Text>,
        greeting -> Nullable<Binary>,
        definition -> Nullable<Binary>,
        default_voice -> Nullable<Text>,
        extensions -> Nullable<DbJsonType>,
        data_id -> Nullable<Integer>,
        category -> Nullable<Text>,
        definition_visibility -> Nullable<Text>,
        depth -> Nullable<Integer>,
        example_dialogue -> Nullable<Binary>,
        favorite -> Nullable<Bool>,
        first_message_visibility -> Nullable<Text>,
        height -> Nullable<DbNumericType>,
        last_activity -> Nullable<DbTimestampType>,
        migrated_from -> Nullable<Text>,
        model_prompt -> Nullable<Binary>,
        model_prompt_visibility -> Nullable<Text>,
        model_temperature -> Nullable<DbNumericType>,
        num_interactions -> Nullable<Integer>,
        permanence -> Nullable<DbNumericType>,
        persona_visibility -> Nullable<Text>,
        revision -> Nullable<Integer>,
        sharing_visibility -> Nullable<Text>,
        status -> Nullable<Text>,
        system_prompt_visibility -> Nullable<Text>,
        system_tags -> Nullable<Array<Nullable<Text>>>,
        token_budget -> Nullable<Integer>,
        usage_hints -> Nullable<DbJsonType>,
        user_persona -> Nullable<Binary>,
        user_persona_visibility -> Nullable<Text>,
        visibility -> Nullable<Text>,
        weight -> Nullable<DbNumericType>,
        world_scenario_visibility -> Nullable<Text>,
        description_nonce -> Nullable<Binary>,
        personality_nonce -> Nullable<Binary>,
        scenario_nonce -> Nullable<Binary>,
        first_mes_nonce -> Nullable<Binary>,
        mes_example_nonce -> Nullable<Binary>,
        creator_notes_nonce -> Nullable<Binary>,
        system_prompt_nonce -> Nullable<Binary>,
        persona_nonce -> Nullable<Binary>,
        world_scenario_nonce -> Nullable<Binary>,
        greeting_nonce -> Nullable<Binary>,
        definition_nonce -> Nullable<Binary>,
        example_dialogue_nonce -> Nullable<Binary>,
        model_prompt_nonce -> Nullable<Binary>,
        user_persona_nonce -> Nullable<Binary>,
        post_history_instructions_nonce -> Nullable<Binary>,
        fav -> Nullable<Bool>,
        world -> Nullable<Text>,
        creator_comment -> Nullable<Binary>,
        creator_comment_nonce -> Nullable<Binary>,
        depth_prompt -> Nullable<Binary>,
        depth_prompt_depth -> Nullable<Integer>,
        depth_prompt_role -> Nullable<Text>,
        talkativeness -> Nullable<DbNumericType>,
        depth_prompt_ciphertext -> Nullable<Binary>,
        depth_prompt_nonce -> Nullable<Binary>,
        world_ciphertext -> Nullable<Binary>,
        world_nonce -> Nullable<Binary>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    chat_character_lorebook_overrides (id) {
        id -> Nullable<DbIdType>,
        chat_session_id -> DbIdType,
        lorebook_id -> DbIdType,
        user_id -> DbIdType,
        action -> Text,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    chat_character_overrides (id) {
        id -> Nullable<DbIdType>,
        chat_session_id -> DbIdType,
        original_character_id -> DbIdType,
        field_name -> Text,
        overridden_value -> Binary,
        overridden_value_nonce -> Binary,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    chat_messages (id) {
        id -> DbIdType,
        session_id -> DbIdType,
        message_type -> Text,
        content -> Binary,
        rag_embedding_id -> Nullable<Text>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        user_id -> DbIdType,
        content_nonce -> Nullable<Binary>,
        role -> Nullable<Text>,
        parts -> Nullable<DbJsonType>,
        attachments -> Nullable<DbJsonType>,
        prompt_tokens -> Nullable<Integer>,
        completion_tokens -> Nullable<Integer>,
        raw_prompt_ciphertext -> Nullable<Binary>,
        raw_prompt_nonce -> Nullable<Binary>,
        model_name -> Text,
        status -> Text,
        error_message -> Nullable<Text>,
        superseded_at -> Nullable<DbTimestampType>,
        variant_count -> Integer,
        current_variant_index -> Integer,
        credits_charged -> Integer,
        credits_cost -> Integer,
        actual_cost -> DbNumericType,
        modified_cost -> DbNumericType,
        credit_cost -> Integer,
        actual_charge -> DbNumericType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    chat_session_lorebooks (chat_session_id, lorebook_id) {
        chat_session_id -> DbIdType,
        lorebook_id -> DbIdType,
        user_id -> DbIdType,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    chat_sessions (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        character_id -> Nullable<DbIdType>,
        temperature -> Nullable<DbNumericType>,
        max_output_tokens -> Nullable<Integer>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        frequency_penalty -> Nullable<DbNumericType>,
        presence_penalty -> Nullable<DbNumericType>,
        top_k -> Nullable<Integer>,
        top_p -> Nullable<DbNumericType>,
        repetition_penalty -> Nullable<DbNumericType>,
        min_p -> Nullable<DbNumericType>,
        top_a -> Nullable<DbNumericType>,
        seed -> Nullable<Integer>,
        logit_bias -> Nullable<DbJsonType>,
        history_management_strategy -> Text,
        history_management_limit -> Integer,
        model_name -> Text,
        gemini_thinking_budget -> Nullable<Integer>,
        gemini_enable_code_execution -> Nullable<Bool>,
        visibility -> Nullable<Text>,
        active_custom_persona_id -> Nullable<DbIdType>,
        active_impersonated_character_id -> Nullable<DbIdType>,
        system_prompt_ciphertext -> Nullable<Binary>,
        system_prompt_nonce -> Nullable<Binary>,
        title_ciphertext -> Nullable<Binary>,
        title_nonce -> Nullable<Binary>,
        stop_sequences -> Nullable<Array<Nullable<Text>>>,
        chat_mode -> Text,
        player_chronicle_id -> Nullable<DbIdType>,
        agent_mode -> Nullable<Text>,
        model_provider -> Nullable<Text>,
        total_prompt_tokens -> Integer,
        total_completion_tokens -> Integer,
        estimated_cost_cents -> Integer,
        tokens_counted_at -> DbTimestampType,
        prompt_template_id -> Text,
        total_credits_used -> Integer,
        narrative_style_override_ciphertext -> Nullable<Binary>,
        narrative_style_override_nonce -> Nullable<Binary>,
        total_actual_cost -> DbNumericType,
        total_modified_cost -> DbNumericType,
        total_credit_cost -> Integer,
        total_actual_charge -> DbNumericType,
        game_state -> Nullable<DbJsonType>,
        game_master_mode_enabled -> Bool,
        gemini_thinking_level -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    chronicle_events (id) {
        id -> DbIdType,
        chronicle_id -> DbIdType,
        user_id -> DbIdType,
        event_type -> Text,
        summary -> Text,
        source -> Text,
        event_data -> Nullable<DbJsonType>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        summary_encrypted -> Nullable<Binary>,
        summary_nonce -> Nullable<Binary>,
        timestamp_iso8601 -> Nullable<DbTimestampType>,
        keywords -> Nullable<Array<Nullable<Text>>>,
        keywords_encrypted -> Nullable<Binary>,
        keywords_nonce -> Nullable<Binary>,
        chat_session_id -> Nullable<DbIdType>,
        message_variant_id -> Nullable<DbIdType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    credit_packages (id) {
        id -> DbIdType,
        package_id -> Text,
        name -> Text,
        credits -> Integer,
        price_cents -> Integer,
        bonus_percentage -> Nullable<Integer>,
        paddle_price_id -> Nullable<Text>,
        active -> Nullable<Bool>,
        display_order -> Nullable<Integer>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    credit_transactions (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        amount -> Integer,
        balance_after -> Integer,
        transaction_type -> Text,
        description_encrypted -> Binary,
        description_nonce -> Binary,
        metadata_encrypted -> Nullable<Binary>,
        metadata_nonce -> Nullable<Binary>,
        reference_id -> Nullable<Text>,
        created_at -> Nullable<DbTimestampType>,
        expires_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    daily_usage_tracking (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        date -> Date,
        message_count -> Integer,
        token_count -> Integer,
        model_breakdown -> Nullable<Text>,
        soft_limit_triggered_at -> Nullable<Integer>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    email_verification_tokens (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        token -> Text,
        expires_at -> DbTimestampType,
        created_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    lorebook_entries (id) {
        id -> DbIdType,
        lorebook_id -> DbIdType,
        user_id -> DbIdType,
        original_sillytavern_uid -> Nullable<Integer>,
        entry_title_ciphertext -> Binary,
        entry_title_nonce -> Binary,
        keys_text_ciphertext -> Binary,
        keys_text_nonce -> Binary,
        content_ciphertext -> Binary,
        content_nonce -> Binary,
        comment_ciphertext -> Nullable<Binary>,
        comment_nonce -> Nullable<Binary>,
        is_enabled -> Bool,
        is_constant -> Bool,
        insertion_order -> Integer,
        placement_hint -> Nullable<Text>,
        sillytavern_metadata_ciphertext -> Nullable<Binary>,
        sillytavern_metadata_nonce -> Nullable<Binary>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        name -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    lorebooks (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        name -> Text,
        description -> Nullable<Text>,
        source_format -> Text,
        is_public -> Bool,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    message_variants (id) {
        id -> DbIdType,
        parent_message_id -> DbIdType,
        variant_index -> Integer,
        content -> Binary,
        content_nonce -> Nullable<Binary>,
        user_id -> DbIdType,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        prompt_tokens -> Nullable<Integer>,
        completion_tokens -> Nullable<Integer>,
        model_name -> Nullable<Text>,
        raw_prompt_ciphertext -> Nullable<Binary>,
        raw_prompt_nonce -> Nullable<Binary>,
        game_state -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    old_documents (id, created_at) {
        id -> DbIdType,
        created_at -> DbTimestampType,
        title -> Text,
        content -> Nullable<Text>,
        kind -> Text,
        user_id -> DbIdType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    old_suggestions (id) {
        id -> Text,
        document_id -> Text,
        document_created_at -> Timestamp,
        original_text -> Text,
        suggested_text -> Text,
        description -> Nullable<Text>,
        is_resolved -> Bool,
        user_id -> Text,
        created_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    old_votes (chat_id, message_id) {
        chat_id -> Text,
        message_id -> Text,
        is_upvoted -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    payment_audit_logs (id) {
        id -> Nullable<Text>,
        user_id_hash -> Text,
        event_type -> Text,
        amount -> Nullable<Integer>,
        event_category -> Text,
        success -> Bool,
        error_code -> Nullable<Text>,
        external_reference_hash -> Nullable<Text>,
        created_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    payment_transactions (id) {
        id -> Nullable<Text>,
        paddle_transaction_id -> Text,
        user_id -> Text,
        status -> Text,
        collection_mode -> Nullable<Text>,
        total_cents -> Integer,
        tax_cents -> Nullable<Integer>,
        discount_cents -> Nullable<Integer>,
        currency_code -> Nullable<Text>,
        paddle_customer_id -> Nullable<Text>,
        customer_data_encrypted -> Nullable<Binary>,
        customer_data_nonce -> Nullable<Binary>,
        items -> Text,
        checkout_id -> Nullable<Text>,
        billed_at -> Nullable<Timestamp>,
        completed_at -> Nullable<Timestamp>,
        paddle_data_encrypted -> Nullable<Binary>,
        paddle_data_nonce -> Nullable<Binary>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    payment_usage_tracking (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        subscription_id -> Nullable<Text>,
        tokens_used -> Integer,
        tokens_limit -> Nullable<Integer>,
        period_start -> Timestamp,
        period_end -> DbTimestampType,
        metadata_encrypted -> Nullable<Binary>,
        metadata_nonce -> Nullable<Binary>,
        created_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    payments (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        subscription_id -> Nullable<DbIdType>,
        paddle_transaction_id -> Nullable<Text>,
        amount_cents -> Integer,
        currency -> Nullable<Text>,
        status -> Text,
        failure_reason_encrypted -> Nullable<Binary>,
        failure_reason_nonce -> Nullable<Binary>,
        paddle_receipt_url -> Nullable<Text>,
        created_at -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    plan_features (plan_type) {
        plan_type -> Nullable<Text>,
        monthly_token_limit -> Nullable<Integer>,
        characters_limit -> Nullable<Integer>,
        lorebooks_limit -> Nullable<Integer>,
        price_cents -> Nullable<Integer>,
        paddle_price_id -> Nullable<Text>,
        features -> Nullable<Text>,
        display_name -> Text,
        description -> Nullable<Text>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
        paddle_price_id_yearly -> Nullable<Text>,
        max_context_tokens -> Nullable<Integer>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    player_chronicles (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        name -> Text,
        description -> Nullable<Text>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    sessions (id) {
        id -> Text,
        expires -> Nullable<DbTimestampType>,
        session -> Text,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    subscriptions (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        paddle_customer_id -> Nullable<Text>,
        paddle_subscription_id -> Nullable<Text>,
        plan_type -> Text,
        status -> Text,
        current_period_start -> DbTimestampType,
        current_period_end -> DbTimestampType,
        cancel_at_period_end -> Nullable<Bool>,
        trial_end -> Nullable<DbTimestampType>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
        credits_allocated_this_period -> Nullable<Bool>,
        soft_limit_override -> Nullable<Integer>,
        last_credit_grant -> Nullable<DbTimestampType>,
        paddle_sync_attempted -> Bool,
        first_payment_date -> Nullable<DbTimestampType>,
        has_ever_paid -> Nullable<Bool>,
        cancellation_date -> Nullable<DbTimestampType>,
        trial_start_date -> Nullable<DbTimestampType>,
        last_payment_date -> Nullable<DbTimestampType>,
        grace_period_end -> Nullable<DbTimestampType>,
        previous_subscription_id -> Nullable<DbIdType>,
        cancellation_reason_encrypted -> Nullable<Binary>,
        cancellation_reason_nonce -> Nullable<Binary>,
        paddle_trial_end -> Nullable<DbTimestampType>,
        first_billed_at -> Nullable<DbTimestampType>,
        next_billed_at -> Nullable<DbTimestampType>,
        canceled_at -> Nullable<DbTimestampType>,
        paused_at -> Nullable<DbTimestampType>,
        trial_starts_at -> Nullable<DbTimestampType>,
        trial_ends_at -> Nullable<DbTimestampType>,
        scheduled_change -> Nullable<Text>,
        management_urls -> Nullable<Text>,
        discount -> Nullable<Text>,
        collection_mode -> Nullable<Text>,
        billing_details -> Nullable<Text>,
        scheduled_plan_change -> Nullable<Text>,
        scheduled_change_date -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    template_preferences (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        character_id -> Nullable<DbIdType>,
        template_id -> Nullable<Text>,
        tense -> Text,
        narration -> Text,
        perspective -> Text,
        length -> Text,
        enable_info_box -> Bool,
        enable_stats_tracker -> Bool,
        enable_thinking -> Bool,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    usage_tracking (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        period_start -> DbTimestampType,
        period_end -> DbTimestampType,
        prompt_tokens_used -> Integer,
        completion_tokens_used -> Integer,
        estimated_cost_cents -> Integer,
        model_breakdown -> Nullable<Text>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    user_assets (id) {
        id -> Nullable<Integer>,
        user_id -> DbIdType,
        persona_id -> Nullable<DbIdType>,
        asset_type -> Text,
        uri -> Nullable<Text>,
        name -> Text,
        ext -> Text,
        data -> Nullable<Binary>,
        content_type -> Nullable<Text>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    user_credits (user_id) {
        user_id -> DbIdType,
        balance -> Integer,
        lifetime_earned -> Integer,
        lifetime_spent -> Integer,
        last_monthly_grant -> Nullable<DbTimestampType>,
        created_at -> Nullable<DbTimestampType>,
        updated_at -> Nullable<DbTimestampType>,
        version -> Integer,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    user_personas (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        name -> Text,
        description -> Binary,
        spec -> Nullable<Text>,
        spec_version -> Nullable<Text>,
        personality -> Nullable<Binary>,
        scenario -> Nullable<Binary>,
        first_mes -> Nullable<Binary>,
        mes_example -> Nullable<Binary>,
        system_prompt -> Nullable<Binary>,
        post_history_instructions -> Nullable<Binary>,
        tags -> Nullable<Text>,
        avatar -> Nullable<Text>,
        description_nonce -> Nullable<Binary>,
        personality_nonce -> Nullable<Binary>,
        scenario_nonce -> Nullable<Binary>,
        first_mes_nonce -> Nullable<Binary>,
        mes_example_nonce -> Nullable<Binary>,
        system_prompt_nonce -> Nullable<Binary>,
        post_history_instructions_nonce -> Nullable<Binary>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    user_settings (id) {
        id -> DbIdType,
        user_id -> DbIdType,
        default_model_name -> Nullable<Text>,
        default_temperature -> Nullable<Double>,
        default_max_output_tokens -> Nullable<Integer>,
        default_frequency_penalty -> Nullable<Double>,
        default_presence_penalty -> Nullable<Double>,
        default_top_p -> Nullable<Double>,
        default_top_k -> Nullable<Integer>,
        default_seed -> Nullable<Integer>,
        default_gemini_thinking_budget -> Nullable<Integer>,
        default_gemini_enable_code_execution -> Nullable<Bool>,
        default_context_total_token_limit -> Nullable<Integer>,
        default_context_recent_history_budget -> Nullable<Integer>,
        default_context_rag_budget -> Nullable<Integer>,
        auto_save_chats -> Nullable<Bool>,
        theme -> Nullable<Text>,
        notifications_enabled -> Nullable<Bool>,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        typing_speed -> Nullable<Integer>,
        preferred_local_model -> Nullable<Text>,
        local_llm_enabled -> Nullable<Bool>,
        local_model_preferences -> Nullable<Text>,
        default_gemini_thinking_level -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    users (id) {
        id -> DbIdType,
        username -> Text,
        password_hash -> Text,
        created_at -> DbTimestampType,
        updated_at -> DbTimestampType,
        email -> Nullable<Text>,
        kek_salt -> Text,
        encrypted_dek -> Binary,
        encrypted_dek_by_recovery -> Nullable<Binary>,
        recovery_kek_salt -> Nullable<Text>,
        dek_nonce -> Binary,
        recovery_dek_nonce -> Nullable<Binary>,
        role -> Text,
        account_status -> Text,
        default_persona_id -> Nullable<DbIdType>,
        total_prompt_tokens -> Integer,
        total_completion_tokens -> Integer,
        total_token_cost_cents -> Integer,
        tokens_last_reset_at -> Nullable<DbTimestampType>,
        token_usage_updated_at -> DbTimestampType,
        cached_credit_balance -> Nullable<Integer>,
        cached_subscription_tier -> Nullable<Text>,
        last_daily_usage_reset -> Nullable<DbTimestampType>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types_unified::*;

    webhook_events (id) {
        id -> DbIdType,
        event_id -> Text,
        event_type -> Text,
        paddle_signature -> Text,
        payload_hash -> Text,
        processed_at -> DbTimestampType,
        processing_status -> Text,
        created_at -> DbTimestampType,
    }
}

diesel::joinable!(agent_context_analysis -> chat_sessions (chat_session_id));
diesel::joinable!(agent_context_analysis -> users (user_id));
diesel::joinable!(character_assets -> characters (character_id));
diesel::joinable!(character_lorebooks -> characters (character_id));
diesel::joinable!(character_lorebooks -> lorebooks (lorebook_id));
diesel::joinable!(character_lorebooks -> users (user_id));
diesel::joinable!(characters -> users (user_id));
diesel::joinable!(chat_character_lorebook_overrides -> chat_sessions (chat_session_id));
diesel::joinable!(chat_character_lorebook_overrides -> lorebooks (lorebook_id));
diesel::joinable!(chat_character_lorebook_overrides -> users (user_id));
diesel::joinable!(chat_character_overrides -> characters (original_character_id));
diesel::joinable!(chat_character_overrides -> chat_sessions (chat_session_id));
diesel::joinable!(chat_session_lorebooks -> chat_sessions (chat_session_id));
diesel::joinable!(chat_session_lorebooks -> lorebooks (lorebook_id));
diesel::joinable!(chat_session_lorebooks -> users (user_id));
diesel::joinable!(chronicle_events -> chat_sessions (chat_session_id));
diesel::joinable!(chronicle_events -> message_variants (message_variant_id));
diesel::joinable!(chronicle_events -> player_chronicles (chronicle_id));
diesel::joinable!(chronicle_events -> users (user_id));
diesel::joinable!(credit_transactions -> users (user_id));
diesel::joinable!(daily_usage_tracking -> users (user_id));
diesel::joinable!(email_verification_tokens -> users (user_id));
diesel::joinable!(message_variants -> chat_messages (parent_message_id));
diesel::joinable!(message_variants -> users (user_id));
diesel::joinable!(old_documents -> users (user_id));
diesel::joinable!(old_suggestions -> users (user_id));
diesel::joinable!(old_votes -> chat_messages (message_id));
diesel::joinable!(old_votes -> chat_sessions (chat_id));
diesel::joinable!(payment_transactions -> users (user_id));
diesel::joinable!(payment_usage_tracking -> subscriptions (subscription_id));
diesel::joinable!(payment_usage_tracking -> users (user_id));
diesel::joinable!(payments -> subscriptions (subscription_id));
diesel::joinable!(payments -> users (user_id));
diesel::joinable!(player_chronicles -> users (user_id));
diesel::joinable!(subscriptions -> plan_features (plan_type));
diesel::joinable!(subscriptions -> users (user_id));
diesel::joinable!(template_preferences -> characters (character_id));
diesel::joinable!(template_preferences -> users (user_id));
diesel::joinable!(usage_tracking -> users (user_id));
diesel::joinable!(user_assets -> user_personas (persona_id));
diesel::joinable!(user_assets -> users (user_id));
diesel::joinable!(user_credits -> users (user_id));
diesel::joinable!(user_personas -> users (user_id));
diesel::joinable!(user_settings -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    agent_context_analysis,
    character_assets,
    character_lorebooks,
    characters,
    chat_character_lorebook_overrides,
    chat_character_overrides,
    chat_messages,
    chat_session_lorebooks,
    chat_sessions,
    chronicle_events,
    credit_packages,
    credit_transactions,
    daily_usage_tracking,
    email_verification_tokens,
    lorebook_entries,
    lorebooks,
    message_variants,
    old_documents,
    old_suggestions,
    old_votes,
    payment_audit_logs,
    payment_transactions,
    payment_usage_tracking,
    payments,
    plan_features,
    player_chronicles,
    sessions,
    subscriptions,
    template_preferences,
    usage_tracking,
    user_assets,
    user_credits,
    user_personas,
    user_settings,
    users,
    webhook_events,
);
