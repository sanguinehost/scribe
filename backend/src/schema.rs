// @generated automatically by Diesel CLI.

diesel::table! {
    agent_context_analysis (id) {
        id -> Text,
        chat_session_id -> Text,
        user_id -> Text,
        analysis_type -> Text,
        agent_reasoning -> Nullable<Text>,
        agent_reasoning_nonce -> Nullable<Binary>,
        planned_searches -> Nullable<Text>,
        execution_log -> Nullable<Text>,
        execution_log_nonce -> Nullable<Binary>,
        retrieved_context -> Nullable<Text>,
        retrieved_context_nonce -> Nullable<Binary>,
        analysis_summary -> Nullable<Text>,
        analysis_summary_nonce -> Nullable<Binary>,
        total_tokens_used -> Nullable<Integer>,
        execution_time_ms -> Nullable<Integer>,
        model_used -> Nullable<Text>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        message_id -> Text,
        assistant_message_id -> Text,
        status -> Text,
        error_message -> Nullable<Text>,
        retry_count -> Integer,
        superseded_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    character_assets (id) {
        id -> Text,
        character_id -> Text,
        asset_type -> Text,
        uri -> Nullable<Text>,
        name -> Text,
        ext -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        data -> Nullable<Binary>,
        content_type -> Nullable<Text>,
    }
}

diesel::table! {
    character_lorebooks (character_id, lorebook_id) {
        character_id -> Text,
        lorebook_id -> Text,
        user_id -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    characters (id) {
        id -> Text,
        user_id -> Text,
        spec -> Text,
        spec_version -> Text,
        name -> Text,
        description -> Nullable<Text>,
        personality -> Nullable<Text>,
        scenario -> Nullable<Text>,
        first_mes -> Nullable<Text>,
        mes_example -> Nullable<Text>,
        creator_notes -> Nullable<Text>,
        system_prompt -> Nullable<Text>,
        post_history_instructions -> Nullable<Text>,
        tags -> Nullable<Text>,
        creator -> Nullable<Text>,
        character_version -> Nullable<Text>,
        alternate_greetings -> Nullable<Text>,
        nickname -> Nullable<Text>,
        creator_notes_multilingual -> Nullable<Text>,
        source -> Nullable<Text>,
        group_only_greetings -> Nullable<Text>,
        creation_date -> Nullable<Timestamp>,
        modification_date -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        persona -> Nullable<Text>,
        world_scenario -> Nullable<Text>,
        avatar -> Nullable<Text>,
        chat -> Nullable<Text>,
        greeting -> Nullable<Text>,
        definition -> Nullable<Text>,
        default_voice -> Nullable<Text>,
        extensions -> Nullable<Text>,
        data_id -> Nullable<Integer>,
        category -> Nullable<Text>,
        definition_visibility -> Nullable<Text>,
        depth -> Nullable<Integer>,
        example_dialogue -> Nullable<Text>,
        favorite -> Nullable<Bool>,
        first_message_visibility -> Nullable<Text>,
        height -> Nullable<Double>,
        last_activity -> Nullable<Timestamp>,
        migrated_from -> Nullable<Text>,
        model_prompt -> Nullable<Text>,
        model_prompt_visibility -> Nullable<Text>,
        model_temperature -> Nullable<Double>,
        num_interactions -> Nullable<Integer>,
        permanence -> Nullable<Double>,
        persona_visibility -> Nullable<Text>,
        revision -> Nullable<Integer>,
        sharing_visibility -> Nullable<Text>,
        status -> Nullable<Text>,
        system_prompt_visibility -> Nullable<Text>,
        system_tags -> Nullable<Text>,
        token_budget -> Nullable<Integer>,
        usage_hints -> Nullable<Text>,
        user_persona -> Nullable<Text>,
        user_persona_visibility -> Nullable<Text>,
        visibility -> Nullable<Text>,
        weight -> Nullable<Double>,
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
        talkativeness -> Nullable<Double>,
        depth_prompt_ciphertext -> Nullable<Binary>,
        depth_prompt_nonce -> Nullable<Binary>,
        world_ciphertext -> Nullable<Binary>,
        world_nonce -> Nullable<Binary>,
    }
}

diesel::table! {
    chat_character_lorebook_overrides (id) {
        id -> Nullable<Text>,
        chat_session_id -> Text,
        lorebook_id -> Text,
        user_id -> Text,
        action -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    chat_character_overrides (id) {
        id -> Nullable<Text>,
        chat_session_id -> Text,
        original_character_id -> Text,
        field_name -> Text,
        overridden_value -> Binary,
        overridden_value_nonce -> Binary,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    chat_messages (id) {
        id -> Text,
        session_id -> Text,
        message_type -> Text,
        content -> Text,
        rag_embedding_id -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_id -> Text,
        content_nonce -> Nullable<Binary>,
        role -> Nullable<Text>,
        parts -> Nullable<Text>,
        attachments -> Nullable<Text>,
        prompt_tokens -> Nullable<Integer>,
        completion_tokens -> Nullable<Integer>,
        raw_prompt_ciphertext -> Nullable<Binary>,
        raw_prompt_nonce -> Nullable<Binary>,
        model_name -> Nullable<Text>,
        status -> Text,
        error_message -> Nullable<Text>,
        superseded_at -> Nullable<Timestamp>,
        variant_count -> Integer,
        current_variant_index -> Integer,
        credits_charged -> Integer,
        credits_cost -> Integer,
        actual_cost -> Double,
        modified_cost -> Double,
        credit_cost -> Integer,
        actual_charge -> Double,
    }
}

diesel::table! {
    chat_session_lorebooks (chat_session_id, lorebook_id) {
        chat_session_id -> Text,
        lorebook_id -> Text,
        user_id -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    chat_sessions (id) {
        id -> Text,
        user_id -> Text,
        character_id -> Text,
        temperature -> Nullable<Double>,
        max_output_tokens -> Nullable<Integer>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        frequency_penalty -> Nullable<Double>,
        presence_penalty -> Nullable<Double>,
        top_k -> Nullable<Integer>,
        top_p -> Nullable<Double>,
        repetition_penalty -> Nullable<Double>,
        min_p -> Nullable<Double>,
        top_a -> Nullable<Double>,
        seed -> Nullable<Integer>,
        logit_bias -> Nullable<Text>,
        history_management_strategy -> Text,
        history_management_limit -> Integer,
        model_name -> Text,
        gemini_thinking_budget -> Nullable<Integer>,
        gemini_enable_code_execution -> Nullable<Bool>,
        visibility -> Nullable<Text>,
        active_custom_persona_id -> Text,
        active_impersonated_character_id -> Text,
        system_prompt_ciphertext -> Nullable<Binary>,
        system_prompt_nonce -> Nullable<Binary>,
        title_ciphertext -> Nullable<Binary>,
        title_nonce -> Nullable<Binary>,
        stop_sequences -> Nullable<Text>,
        chat_mode -> Text,
        player_chronicle_id -> Text,
        agent_mode -> Nullable<Text>,
        model_provider -> Nullable<Text>,
        total_prompt_tokens -> Integer,
        total_completion_tokens -> Integer,
        estimated_cost_cents -> Integer,
        tokens_counted_at -> Timestamp,
        prompt_template_id -> Text,
        total_credits_used -> Integer,
        narrative_style_override_ciphertext -> Nullable<Binary>,
        narrative_style_override_nonce -> Nullable<Binary>,
        total_actual_cost -> Double,
        total_modified_cost -> Double,
        total_credit_cost -> Integer,
        total_actual_charge -> Double,
    }
}

diesel::table! {
    chronicle_events (id) {
        id -> Nullable<Text>,
        chronicle_id -> Text,
        user_id -> Text,
        event_type -> Text,
        summary -> Text,
        source -> Text,
        event_data -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        summary_encrypted -> Nullable<Binary>,
        summary_nonce -> Nullable<Binary>,
        timestamp_iso8601 -> Nullable<Timestamp>,
        keywords -> Nullable<Text>,
        keywords_encrypted -> Nullable<Binary>,
        keywords_nonce -> Nullable<Binary>,
        chat_session_id -> Nullable<Text>,
    }
}

diesel::table! {
    credit_packages (id) {
        id -> Nullable<Text>,
        package_id -> Text,
        name -> Text,
        credits -> Integer,
        price_cents -> Integer,
        bonus_percentage -> Nullable<Integer>,
        paddle_price_id -> Nullable<Text>,
        active -> Nullable<Bool>,
        display_order -> Nullable<Integer>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    credit_transactions (id) {
        id -> Text,
        user_id -> Text,
        amount -> Integer,
        balance_after -> Integer,
        transaction_type -> Text,
        description_encrypted -> Binary,
        description_nonce -> Binary,
        metadata_encrypted -> Nullable<Binary>,
        metadata_nonce -> Nullable<Binary>,
        reference_id -> Text,
        created_at -> Nullable<Timestamp>,
        expires_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    daily_usage_tracking (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        date -> Date,
        message_count -> Integer,
        token_count -> Integer,
        model_breakdown -> Nullable<Text>,
        soft_limit_triggered_at -> Nullable<Integer>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    email_verification_tokens (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        token -> Text,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    lorebook_entries (id) {
        id -> Text,
        lorebook_id -> Text,
        user_id -> Text,
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
        created_at -> Timestamp,
        updated_at -> Timestamp,
        name -> Nullable<Text>,
    }
}

diesel::table! {
    lorebooks (id) {
        id -> Text,
        user_id -> Text,
        name -> Text,
        description -> Nullable<Text>,
        source_format -> Text,
        is_public -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    message_variants (id) {
        id -> Nullable<Text>,
        parent_message_id -> Text,
        variant_index -> Integer,
        content -> Binary,
        content_nonce -> Nullable<Binary>,
        user_id -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    old_documents (id, created_at) {
        id -> Text,
        created_at -> Timestamp,
        title -> Text,
        content -> Nullable<Text>,
        kind -> Text,
        user_id -> Text,
    }
}

diesel::table! {
    old_suggestions (id) {
        id -> Text,
        document_id -> Text,
        document_created_at -> Timestamp,
        original_text -> Text,
        suggested_text -> Text,
        description -> Nullable<Text>,
        is_resolved -> Bool,
        user_id -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    old_votes (chat_id, message_id) {
        chat_id -> Text,
        message_id -> Text,
        is_upvoted -> Bool,
    }
}

diesel::table! {
    payment_audit_logs (id) {
        id -> Nullable<Text>,
        user_id_hash -> Text,
        event_type -> Text,
        amount -> Nullable<Integer>,
        event_category -> Text,
        success -> Bool,
        error_code -> Nullable<Text>,
        external_reference_hash -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    payment_transactions (id) {
        id -> Text,
        paddle_transaction_id -> Text,
        user_id -> Text,
        status -> Text,
        collection_mode -> Nullable<Text>,
        total_cents -> Integer,
        tax_cents -> Nullable<Integer>,
        discount_cents -> Nullable<Integer>,
        currency_code -> Nullable<Text>,
        paddle_customer_id -> Text,
        customer_data_encrypted -> Nullable<Binary>,
        customer_data_nonce -> Nullable<Binary>,
        items -> Text,
        checkout_id -> Text,
        billed_at -> Nullable<Timestamp>,
        completed_at -> Nullable<Timestamp>,
        paddle_data_encrypted -> Nullable<Binary>,
        paddle_data_nonce -> Nullable<Binary>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    payment_usage_tracking (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        subscription_id -> Nullable<Text>,
        tokens_used -> Integer,
        tokens_limit -> Nullable<Integer>,
        period_start -> Timestamp,
        period_end -> Timestamp,
        metadata_encrypted -> Nullable<Binary>,
        metadata_nonce -> Nullable<Binary>,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    payments (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        subscription_id -> Nullable<Text>,
        paddle_transaction_id -> Nullable<Text>,
        amount_cents -> Integer,
        currency -> Nullable<Text>,
        status -> Text,
        failure_reason_encrypted -> Nullable<Binary>,
        failure_reason_nonce -> Nullable<Binary>,
        paddle_receipt_url -> Nullable<Text>,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
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
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        paddle_price_id_yearly -> Nullable<Text>,
        max_context_tokens -> Nullable<Integer>,
    }
}

diesel::table! {
    player_chronicles (id) {
        id -> Text,
        user_id -> Text,
        name -> Text,
        description -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    sessions (id) {
        id -> Text,
        expires -> Nullable<Timestamp>,
        session -> Text,
    }
}

diesel::table! {
    subscriptions (id) {
        id -> Text,
        user_id -> Text,
        paddle_customer_id -> Text,
        paddle_subscription_id -> Text,
        plan_type -> Text,
        status -> Text,
        current_period_start -> Timestamp,
        current_period_end -> Timestamp,
        cancel_at_period_end -> Nullable<Bool>,
        trial_end -> Nullable<Timestamp>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        credits_allocated_this_period -> Nullable<Bool>,
        soft_limit_override -> Nullable<Integer>,
        last_credit_grant -> Nullable<Timestamp>,
        paddle_sync_attempted -> Bool,
        first_payment_date -> Nullable<Timestamp>,
        has_ever_paid -> Nullable<Bool>,
        cancellation_date -> Nullable<Timestamp>,
        trial_start_date -> Nullable<Timestamp>,
        last_payment_date -> Nullable<Timestamp>,
        grace_period_end -> Nullable<Timestamp>,
        previous_subscription_id -> Text,
        cancellation_reason_encrypted -> Nullable<Binary>,
        cancellation_reason_nonce -> Nullable<Binary>,
        paddle_trial_end -> Nullable<Timestamp>,
        first_billed_at -> Nullable<Timestamp>,
        next_billed_at -> Nullable<Timestamp>,
        canceled_at -> Nullable<Timestamp>,
        paused_at -> Nullable<Timestamp>,
        trial_starts_at -> Nullable<Timestamp>,
        trial_ends_at -> Nullable<Timestamp>,
        scheduled_change -> Nullable<Text>,
        management_urls -> Nullable<Text>,
        discount -> Nullable<Text>,
        collection_mode -> Nullable<Text>,
        billing_details -> Nullable<Text>,
        scheduled_plan_change -> Nullable<Text>,
        scheduled_change_date -> Nullable<Timestamp>,
    }
}

diesel::table! {
    template_preferences (id) {
        id -> Text,
        user_id -> Text,
        character_id -> Text,
        template_id -> Text,
        tense -> Text,
        narration -> Text,
        perspective -> Text,
        length -> Text,
        enable_info_box -> Bool,
        enable_stats_tracker -> Bool,
        enable_thinking -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    usage_tracking (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        period_start -> Timestamp,
        period_end -> Timestamp,
        prompt_tokens_used -> Integer,
        completion_tokens_used -> Integer,
        estimated_cost_cents -> Integer,
        model_breakdown -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    user_assets (id) {
        id -> Text,
        user_id -> Text,
        persona_id -> Text,
        asset_type -> Text,
        uri -> Nullable<Text>,
        name -> Text,
        ext -> Text,
        data -> Nullable<Binary>,
        content_type -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    user_credits (user_id) {
        user_id -> Nullable<Text>,
        balance -> Integer,
        lifetime_earned -> Integer,
        lifetime_spent -> Integer,
        last_monthly_grant -> Nullable<Timestamp>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        version -> Integer,
    }
}

diesel::table! {
    user_personas (id) {
        id -> Text,
        user_id -> Text,
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
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    user_settings (id) {
        id -> Text,
        user_id -> Text,
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
        created_at -> Timestamp,
        updated_at -> Timestamp,
        typing_speed -> Nullable<Integer>,
        preferred_local_model -> Nullable<Text>,
        local_llm_enabled -> Nullable<Bool>,
        local_model_preferences -> Nullable<Text>,
    }
}

diesel::table! {
    users (id) {
        id -> Text,
        username -> Text,
        password_hash -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        email -> Nullable<Text>,
        kek_salt -> Text,
        encrypted_dek -> Binary,
        encrypted_dek_by_recovery -> Nullable<Binary>,
        recovery_kek_salt -> Nullable<Text>,
        dek_nonce -> Binary,
        recovery_dek_nonce -> Nullable<Binary>,
        role -> Text,
        account_status -> Text,
        default_persona_id -> Text,
        total_prompt_tokens -> Integer,
        total_completion_tokens -> Integer,
        total_token_cost_cents -> Integer,
        tokens_last_reset_at -> Nullable<Timestamp>,
        token_usage_updated_at -> Timestamp,
        cached_credit_balance -> Nullable<Integer>,
        cached_subscription_tier -> Nullable<Text>,
        last_daily_usage_reset -> Nullable<Timestamp>,
    }
}

diesel::table! {
    webhook_events (id) {
        id -> Nullable<Text>,
        event_id -> Text,
        event_type -> Text,
        paddle_signature -> Text,
        payload_hash -> Text,
        processed_at -> Timestamp,
        processing_status -> Text,
        created_at -> Timestamp,
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
diesel::joinable!(chat_messages -> chat_sessions (session_id));
diesel::joinable!(chat_session_lorebooks -> chat_sessions (chat_session_id));
diesel::joinable!(chat_session_lorebooks -> lorebooks (lorebook_id));
diesel::joinable!(chat_session_lorebooks -> users (user_id));
diesel::joinable!(chat_sessions -> player_chronicles (player_chronicle_id));
diesel::joinable!(chat_sessions -> user_personas (active_custom_persona_id));
diesel::joinable!(chat_sessions -> users (user_id));
diesel::joinable!(chronicle_events -> chat_sessions (chat_session_id));
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
