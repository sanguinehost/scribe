// @generated automatically by Diesel CLI.

pub mod backend_sql_types {
    #[cfg(feature = "postgres-backend")]
    pub use diesel::pg::sql_types::*;
    #[cfg(feature = "postgres-backend")]
    pub use diesel::sql_types::*;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::*;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Timestamp as Timestamptz;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Text as Uuid;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Text as Jsonb;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Binary as Bytea;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Text as Varchar;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Float as Float4;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Double as Float8;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::BigInt as Int8;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Integer as Int4;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::SmallInt as Int2;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Bool as Bool;
    #[cfg(feature = "postgres-backend")]
    pub type DbArrayNullableText = diesel::sql_types::Array<diesel::sql_types::Nullable<diesel::sql_types::Text>>;
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub type DbArrayNullableText = diesel::sql_types::Text;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub use diesel::sql_types::Numeric as Numeric;
}

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "account_status"))]
    pub struct AccountStatus;

    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "message_type"))]
    pub struct MessageType;

    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "user_role"))]
    pub struct UserRole;
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    agent_context_analysis (id) {
        id -> Uuid,
        chat_session_id -> Uuid,
        user_id -> Uuid,
        #[max_length = 50]
        analysis_type -> Varchar,
        agent_reasoning -> Nullable<Text>,
        agent_reasoning_nonce -> Nullable<Bytea>,
        planned_searches -> Nullable<Jsonb>,
        execution_log -> Nullable<Jsonb>,
        execution_log_nonce -> Nullable<Bytea>,
        retrieved_context -> Nullable<Text>,
        retrieved_context_nonce -> Nullable<Bytea>,
        analysis_summary -> Nullable<Text>,
        analysis_summary_nonce -> Nullable<Bytea>,
        total_tokens_used -> Nullable<Int4>,
        execution_time_ms -> Nullable<Int4>,
        #[max_length = 100]
        model_used -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
        message_id -> Uuid,
        assistant_message_id -> Nullable<Uuid>,
        #[max_length = 20]
        status -> Varchar,
        error_message -> Nullable<Text>,
        retry_count -> Int4,
        superseded_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    character_assets (id) {
        id -> Int4,
        character_id -> Uuid,
        #[max_length = 50]
        asset_type -> Varchar,
        uri -> Nullable<Text>,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 50]
        ext -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        data -> Nullable<Bytea>,
        #[max_length = 100]
        content_type -> Nullable<Varchar>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    character_lorebooks (character_id, lorebook_id) {
        character_id -> Uuid,
        lorebook_id -> Uuid,
        user_id -> Uuid,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    character_opinions (id) {
        id -> Uuid,
        user_id -> Uuid,
        chronicle_id -> Uuid,
        perspective_hash -> Text,
        perspective_encrypted -> Bytea,
        perspective_nonce -> Bytea,
        opinion_encrypted -> Bytea,
        opinion_nonce -> Bytea,
        confidence -> Float4,
        significance -> Float4,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        message_variant_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    characters (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        spec -> Varchar,
        #[max_length = 50]
        spec_version -> Varchar,
        #[max_length = 255]
        name -> Varchar,
        description -> Nullable<Bytea>,
        personality -> Nullable<Bytea>,
        scenario -> Nullable<Bytea>,
        first_mes -> Nullable<Bytea>,
        mes_example -> Nullable<Bytea>,
        creator_notes -> Nullable<Bytea>,
        system_prompt -> Nullable<Bytea>,
        post_history_instructions -> Nullable<Bytea>,
        tags -> Nullable<DbArrayNullableText>,
        #[max_length = 255]
        creator -> Nullable<Varchar>,
        #[max_length = 255]
        character_version -> Nullable<Varchar>,
        alternate_greetings -> Nullable<DbArrayNullableText>,
        #[max_length = 255]
        nickname -> Nullable<Varchar>,
        creator_notes_multilingual -> Nullable<Jsonb>,
        source -> Nullable<DbArrayNullableText>,
        group_only_greetings -> Nullable<DbArrayNullableText>,
        creation_date -> Nullable<Timestamptz>,
        modification_date -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        persona -> Nullable<Bytea>,
        world_scenario -> Nullable<Bytea>,
        avatar -> Nullable<Text>,
        chat -> Nullable<Text>,
        greeting -> Nullable<Bytea>,
        definition -> Nullable<Bytea>,
        default_voice -> Nullable<Text>,
        extensions -> Nullable<Jsonb>,
        data_id -> Nullable<Int4>,
        #[max_length = 255]
        category -> Nullable<Varchar>,
        #[max_length = 50]
        definition_visibility -> Nullable<Varchar>,
        depth -> Nullable<Int4>,
        example_dialogue -> Nullable<Bytea>,
        favorite -> Nullable<Bool>,
        #[max_length = 50]
        first_message_visibility -> Nullable<Varchar>,
        height -> Nullable<Numeric>,
        last_activity -> Nullable<Timestamptz>,
        #[max_length = 255]
        migrated_from -> Nullable<Varchar>,
        model_prompt -> Nullable<Bytea>,
        #[max_length = 50]
        model_prompt_visibility -> Nullable<Varchar>,
        model_temperature -> Nullable<Numeric>,
        num_interactions -> Nullable<Int8>,
        permanence -> Nullable<Numeric>,
        #[max_length = 50]
        persona_visibility -> Nullable<Varchar>,
        revision -> Nullable<Int4>,
        #[max_length = 50]
        sharing_visibility -> Nullable<Varchar>,
        #[max_length = 50]
        status -> Nullable<Varchar>,
        #[max_length = 50]
        system_prompt_visibility -> Nullable<Varchar>,
        system_tags -> Nullable<DbArrayNullableText>,
        token_budget -> Nullable<Int4>,
        usage_hints -> Nullable<Jsonb>,
        user_persona -> Nullable<Bytea>,
        #[max_length = 50]
        user_persona_visibility -> Nullable<Varchar>,
        #[max_length = 50]
        visibility -> Nullable<Varchar>,
        weight -> Nullable<Numeric>,
        #[max_length = 50]
        world_scenario_visibility -> Nullable<Varchar>,
        description_nonce -> Nullable<Bytea>,
        personality_nonce -> Nullable<Bytea>,
        scenario_nonce -> Nullable<Bytea>,
        first_mes_nonce -> Nullable<Bytea>,
        mes_example_nonce -> Nullable<Bytea>,
        creator_notes_nonce -> Nullable<Bytea>,
        system_prompt_nonce -> Nullable<Bytea>,
        persona_nonce -> Nullable<Bytea>,
        world_scenario_nonce -> Nullable<Bytea>,
        greeting_nonce -> Nullable<Bytea>,
        definition_nonce -> Nullable<Bytea>,
        example_dialogue_nonce -> Nullable<Bytea>,
        model_prompt_nonce -> Nullable<Bytea>,
        user_persona_nonce -> Nullable<Bytea>,
        post_history_instructions_nonce -> Nullable<Bytea>,
        fav -> Nullable<Bool>,
        world -> Nullable<Text>,
        creator_comment -> Nullable<Bytea>,
        creator_comment_nonce -> Nullable<Bytea>,
        depth_prompt -> Nullable<Bytea>,
        depth_prompt_depth -> Nullable<Int4>,
        #[max_length = 255]
        depth_prompt_role -> Nullable<Varchar>,
        talkativeness -> Nullable<Numeric>,
        depth_prompt_ciphertext -> Nullable<Bytea>,
        depth_prompt_nonce -> Nullable<Bytea>,
        world_ciphertext -> Nullable<Bytea>,
        world_nonce -> Nullable<Bytea>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    chat_character_lorebook_overrides (id) {
        id -> Uuid,
        chat_session_id -> Uuid,
        lorebook_id -> Uuid,
        user_id -> Uuid,
        #[max_length = 20]
        action -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    chat_character_overrides (id) {
        id -> Uuid,
        chat_session_id -> Uuid,
        original_character_id -> Uuid,
        #[max_length = 255]
        field_name -> Varchar,
        overridden_value -> Bytea,
        overridden_value_nonce -> Bytea,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types::MessageType;

    chat_messages (id) {
        id -> Uuid,
        session_id -> Uuid,
        message_type -> MessageType,
        content -> Bytea,
        rag_embedding_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        user_id -> Uuid,
        content_nonce -> Nullable<Bytea>,
        #[max_length = 50]
        role -> Nullable<Varchar>,
        parts -> Nullable<Jsonb>,
        attachments -> Nullable<Jsonb>,
        prompt_tokens -> Nullable<Int8>,
        completion_tokens -> Nullable<Int8>,
        raw_prompt_ciphertext -> Nullable<Bytea>,
        raw_prompt_nonce -> Nullable<Bytea>,
        #[max_length = 255]
        model_name -> Varchar,
        #[max_length = 20]
        status -> Varchar,
        error_message -> Nullable<Text>,
        superseded_at -> Nullable<Timestamptz>,
        variant_count -> Int4,
        current_variant_index -> Int4,
        credits_charged -> Int4,
        credits_cost -> Numeric,
        actual_cost -> Numeric,
        modified_cost -> Numeric,
        credit_cost -> Int4,
        actual_charge -> Numeric,
        game_time -> Nullable<Jsonb>,
        reasoning_content -> Nullable<Bytea>,
        reasoning_content_nonce -> Nullable<Bytea>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    chat_session_lorebooks (chat_session_id, lorebook_id) {
        chat_session_id -> Uuid,
        lorebook_id -> Uuid,
        user_id -> Uuid,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    chat_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        character_id -> Nullable<Uuid>,
        temperature -> Nullable<Numeric>,
        max_output_tokens -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        frequency_penalty -> Nullable<Numeric>,
        presence_penalty -> Nullable<Numeric>,
        top_k -> Nullable<Int4>,
        top_p -> Nullable<Numeric>,
        repetition_penalty -> Nullable<Numeric>,
        min_p -> Nullable<Numeric>,
        top_a -> Nullable<Numeric>,
        seed -> Nullable<Int4>,
        logit_bias -> Nullable<Jsonb>,
        history_management_strategy -> Text,
        history_management_limit -> Int4,
        #[max_length = 100]
        model_name -> Varchar,
        thinking_budget -> Nullable<Int4>,
        enable_code_execution -> Nullable<Bool>,
        #[max_length = 50]
        visibility -> Nullable<Varchar>,
        active_custom_persona_id -> Nullable<Uuid>,
        active_impersonated_character_id -> Nullable<Uuid>,
        system_prompt_ciphertext -> Nullable<Bytea>,
        system_prompt_nonce -> Nullable<Bytea>,
        title_ciphertext -> Nullable<Bytea>,
        title_nonce -> Nullable<Bytea>,
        stop_sequences -> Nullable<DbArrayNullableText>,
        chat_mode -> Varchar,
        player_chronicle_id -> Nullable<Uuid>,
        #[max_length = 20]
        agent_mode -> Nullable<Varchar>,
        #[max_length = 50]
        model_provider -> Nullable<Varchar>,
        total_prompt_tokens -> Int8,
        total_completion_tokens -> Int8,
        estimated_cost_cents -> Int4,
        tokens_counted_at -> Timestamptz,
        #[max_length = 50]
        prompt_template_id -> Varchar,
        total_credits_used -> Numeric,
        total_actual_cost -> Numeric,
        total_modified_cost -> Numeric,
        total_credit_cost -> Int4,
        total_actual_charge -> Numeric,
        narrative_style_override_ciphertext -> Nullable<Bytea>,
        narrative_style_override_nonce -> Nullable<Bytea>,
        game_state -> Nullable<Jsonb>,
        game_master_mode_enabled -> Bool,
        thinking_level -> Nullable<Text>,
        rag_chronicles_limit -> Nullable<Int4>,
        rag_lorebooks_limit -> Nullable<Int4>,
        rag_older_chat_limit -> Nullable<Int4>,
        rag_cognitive_context_limit -> Nullable<Int4>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    chronicle_events (id) {
        id -> Uuid,
        chronicle_id -> Uuid,
        user_id -> Uuid,
        #[max_length = 100]
        event_type -> Varchar,
        summary -> Text,
        #[max_length = 50]
        source -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        summary_encrypted -> Nullable<Bytea>,
        summary_nonce -> Nullable<Bytea>,
        timestamp_iso8601 -> Timestamptz,
        keywords -> Nullable<DbArrayNullableText>,
        keywords_encrypted -> Nullable<Bytea>,
        keywords_nonce -> Nullable<Bytea>,
        chat_session_id -> Nullable<Uuid>,
        message_variant_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    cognitive_core_memory (id) {
        id -> Uuid,
        user_id -> Uuid,
        chronicle_id -> Uuid,
        memory_state_encrypted -> Bytea,
        memory_state_nonce -> Bytea,
        version -> Int4,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    cognitive_facts (id) {
        id -> Uuid,
        user_id -> Uuid,
        chronicle_id -> Uuid,
        who_encrypted -> Bytea,
        who_nonce -> Bytea,
        what_encrypted -> Bytea,
        what_nonce -> Bytea,
        where_encrypted -> Bytea,
        where_nonce -> Bytea,
        when_encrypted -> Bytea,
        when_nonce -> Bytea,
        why_encrypted -> Bytea,
        why_nonce -> Bytea,
        fact_type -> Text,
        confidence -> Float4,
        significance -> Float4,
        created_at -> Timestamptz,
        message_variant_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    credit_packages (id) {
        id -> Uuid,
        #[max_length = 50]
        package_id -> Varchar,
        #[max_length = 100]
        name -> Varchar,
        credits -> Int4,
        price_cents -> Int4,
        bonus_percentage -> Nullable<Int4>,
        #[max_length = 255]
        paddle_price_id -> Nullable<Varchar>,
        active -> Nullable<Bool>,
        display_order -> Nullable<Int4>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    credit_transactions (id) {
        id -> Uuid,
        user_id -> Uuid,
        amount -> Int4,
        balance_after -> Int4,
        #[max_length = 50]
        transaction_type -> Varchar,
        description_encrypted -> Bytea,
        description_nonce -> Bytea,
        metadata_encrypted -> Nullable<Bytea>,
        metadata_nonce -> Nullable<Bytea>,
        #[max_length = 255]
        reference_id -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    daily_usage_tracking (id) {
        id -> Uuid,
        user_id -> Uuid,
        date -> Date,
        message_count -> Int4,
        token_count -> Int8,
        model_breakdown -> Nullable<Jsonb>,
        soft_limit_triggered_at -> Nullable<Int4>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    email_verification_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        token -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    entity_observations (id) {
        id -> Uuid,
        user_id -> Uuid,
        chronicle_id -> Uuid,
        entity_name_hash -> Text,
        entity_name_encrypted -> Bytea,
        entity_name_nonce -> Bytea,
        observation_encrypted -> Bytea,
        observation_nonce -> Bytea,
        confidence -> Float4,
        significance -> Float4,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        message_variant_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    lorebook_entries (id) {
        is_enabled -> Bool,
        insertion_order -> Int4,
        #[max_length = 255]
        name -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        id -> Uuid,
        lorebook_id -> Uuid,
        user_id -> Uuid,
        original_sillytavern_uid -> Nullable<Int4>,
        entry_title_ciphertext -> Bytea,
        entry_title_nonce -> Bytea,
        keys_text_ciphertext -> Bytea,
        keys_text_nonce -> Bytea,
        content_ciphertext -> Bytea,
        content_nonce -> Bytea,
        comment_ciphertext -> Nullable<Bytea>,
        comment_nonce -> Nullable<Bytea>,
        is_constant -> Bool,
        #[max_length = 255]
        placement_hint -> Nullable<Varchar>,
        sillytavern_metadata_ciphertext -> Nullable<Bytea>,
        sillytavern_metadata_nonce -> Nullable<Bytea>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    lorebooks (id) {
        #[max_length = 255]
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        source_format -> Varchar,
        is_public -> Bool,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    message_variants (id) {
        id -> Uuid,
        parent_message_id -> Uuid,
        variant_index -> Int4,
        content -> Bytea,
        content_nonce -> Nullable<Bytea>,
        user_id -> Uuid,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        raw_prompt_ciphertext -> Nullable<Bytea>,
        raw_prompt_nonce -> Nullable<Bytea>,
        game_state -> Nullable<Jsonb>,
        prompt_tokens -> Nullable<Int8>,
        completion_tokens -> Nullable<Int8>,
        model_name -> Nullable<Text>,
        reasoning_content -> Nullable<Bytea>,
        reasoning_content_nonce -> Nullable<Bytea>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    narrative_tasks (id) {
        id -> Uuid,
        user_id -> Uuid,
        session_id -> Uuid,
        workflow_type -> Text,
        current_state -> Bytea,
        status -> Text,
        worker_id -> Nullable<Text>,
        trace_context -> Nullable<Text>,
        expires_at -> Timestamptz,
        last_step_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    old_documents (id, created_at) {
        id -> Uuid,
        created_at -> Timestamptz,
        title -> Text,
        content -> Nullable<Text>,
        kind -> Varchar,
        user_id -> Uuid,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    old_suggestions (id) {
        id -> Uuid,
        document_id -> Uuid,
        document_created_at -> Timestamptz,
        original_text -> Text,
        suggested_text -> Text,
        description -> Nullable<Text>,
        is_resolved -> Bool,
        user_id -> Uuid,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    old_votes (chat_id, message_id) {
        chat_id -> Uuid,
        message_id -> Uuid,
        is_upvoted -> Bool,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    payment_audit_logs (id) {
        id -> Uuid,
        #[max_length = 64]
        user_id_hash -> Varchar,
        #[max_length = 50]
        event_type -> Varchar,
        amount -> Nullable<Int4>,
        #[max_length = 30]
        event_category -> Varchar,
        success -> Bool,
        #[max_length = 50]
        error_code -> Nullable<Varchar>,
        #[max_length = 64]
        external_reference_hash -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    payment_transactions (id) {
        id -> Uuid,
        #[max_length = 255]
        paddle_transaction_id -> Varchar,
        user_id -> Uuid,
        #[max_length = 50]
        status -> Varchar,
        #[max_length = 50]
        collection_mode -> Nullable<Varchar>,
        total_cents -> Int4,
        tax_cents -> Nullable<Int4>,
        discount_cents -> Nullable<Int4>,
        #[max_length = 3]
        currency_code -> Nullable<Varchar>,
        #[max_length = 255]
        paddle_customer_id -> Nullable<Varchar>,
        customer_data_encrypted -> Nullable<Bytea>,
        customer_data_nonce -> Nullable<Bytea>,
        items -> Jsonb,
        #[max_length = 255]
        checkout_id -> Nullable<Varchar>,
        billed_at -> Nullable<Timestamptz>,
        completed_at -> Nullable<Timestamptz>,
        paddle_data_encrypted -> Nullable<Bytea>,
        paddle_data_nonce -> Nullable<Bytea>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    payment_usage_tracking (id) {
        id -> Uuid,
        user_id -> Uuid,
        subscription_id -> Nullable<Uuid>,
        tokens_used -> Int4,
        tokens_limit -> Nullable<Int4>,
        period_start -> Timestamptz,
        period_end -> Timestamptz,
        metadata_encrypted -> Nullable<Bytea>,
        metadata_nonce -> Nullable<Bytea>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    payments (id) {
        id -> Uuid,
        user_id -> Uuid,
        subscription_id -> Nullable<Uuid>,
        #[max_length = 255]
        paddle_transaction_id -> Nullable<Varchar>,
        amount_cents -> Int4,
        #[max_length = 3]
        currency -> Nullable<Varchar>,
        #[max_length = 50]
        status -> Varchar,
        failure_reason_encrypted -> Nullable<Bytea>,
        failure_reason_nonce -> Nullable<Bytea>,
        #[max_length = 512]
        paddle_receipt_url -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    plan_features (plan_type) {
        #[max_length = 50]
        plan_type -> Varchar,
        monthly_token_limit -> Nullable<Int4>,
        characters_limit -> Nullable<Int4>,
        lorebooks_limit -> Nullable<Int4>,
        price_cents -> Nullable<Int4>,
        #[max_length = 255]
        paddle_price_id -> Nullable<Varchar>,
        features -> Nullable<Jsonb>,
        #[max_length = 100]
        display_name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
        #[max_length = 255]
        paddle_price_id_yearly -> Nullable<Varchar>,
        max_context_tokens -> Nullable<Int4>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    player_chronicles (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    sessions (id) {
        id -> Text,
        expires -> Nullable<Timestamptz>,
        session -> Text,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    subscriptions (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        paddle_customer_id -> Nullable<Varchar>,
        #[max_length = 255]
        paddle_subscription_id -> Nullable<Varchar>,
        #[max_length = 50]
        plan_type -> Varchar,
        #[max_length = 50]
        status -> Varchar,
        current_period_start -> Timestamptz,
        current_period_end -> Timestamptz,
        cancel_at_period_end -> Nullable<Bool>,
        trial_end -> Nullable<Timestamptz>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
        credits_allocated_this_period -> Nullable<Bool>,
        soft_limit_override -> Nullable<Int4>,
        last_credit_grant -> Nullable<Timestamptz>,
        paddle_sync_attempted -> Bool,
        first_payment_date -> Nullable<Timestamptz>,
        has_ever_paid -> Nullable<Bool>,
        cancellation_date -> Nullable<Timestamptz>,
        trial_start_date -> Nullable<Timestamptz>,
        last_payment_date -> Nullable<Timestamptz>,
        grace_period_end -> Nullable<Timestamptz>,
        previous_subscription_id -> Nullable<Uuid>,
        cancellation_reason_encrypted -> Nullable<Bytea>,
        cancellation_reason_nonce -> Nullable<Bytea>,
        paddle_trial_end -> Nullable<Timestamptz>,
        first_billed_at -> Nullable<Timestamptz>,
        next_billed_at -> Nullable<Timestamptz>,
        canceled_at -> Nullable<Timestamptz>,
        paused_at -> Nullable<Timestamptz>,
        trial_starts_at -> Nullable<Timestamptz>,
        trial_ends_at -> Nullable<Timestamptz>,
        scheduled_change -> Nullable<Jsonb>,
        management_urls -> Nullable<Jsonb>,
        discount -> Nullable<Jsonb>,
        #[max_length = 50]
        collection_mode -> Nullable<Varchar>,
        billing_details -> Nullable<Jsonb>,
        #[max_length = 50]
        scheduled_plan_change -> Nullable<Varchar>,
        scheduled_change_date -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    template_preferences (id) {
        id -> Uuid,
        user_id -> Uuid,
        character_id -> Nullable<Uuid>,
        #[max_length = 255]
        template_id -> Nullable<Varchar>,
        #[max_length = 20]
        tense -> Varchar,
        #[max_length = 20]
        narration -> Varchar,
        #[max_length = 50]
        perspective -> Varchar,
        #[max_length = 50]
        length -> Varchar,
        enable_info_box -> Bool,
        enable_stats_tracker -> Bool,
        enable_thinking -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    usage_tracking (id) {
        id -> Uuid,
        user_id -> Uuid,
        period_start -> Timestamptz,
        period_end -> Timestamptz,
        prompt_tokens_used -> Int8,
        completion_tokens_used -> Int8,
        estimated_cost_cents -> Int8,
        model_breakdown -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    user_assets (id) {
        id -> Int4,
        user_id -> Uuid,
        persona_id -> Nullable<Uuid>,
        #[max_length = 50]
        asset_type -> Varchar,
        uri -> Nullable<Text>,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 50]
        ext -> Varchar,
        data -> Nullable<Bytea>,
        #[max_length = 100]
        content_type -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    user_credits (user_id) {
        user_id -> Uuid,
        balance -> Int4,
        lifetime_earned -> Int4,
        lifetime_spent -> Int4,
        last_monthly_grant -> Nullable<Timestamptz>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
        version -> Int4,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    user_personas (id) {
        id -> Uuid,
        user_id -> Uuid,
        name -> Varchar,
        description -> Bytea,
        spec -> Nullable<Varchar>,
        spec_version -> Nullable<Varchar>,
        personality -> Nullable<Bytea>,
        scenario -> Nullable<Bytea>,
        first_mes -> Nullable<Bytea>,
        mes_example -> Nullable<Bytea>,
        system_prompt -> Nullable<Bytea>,
        post_history_instructions -> Nullable<Bytea>,
        tags -> Nullable<DbArrayNullableText>,
        avatar -> Nullable<Varchar>,
        description_nonce -> Nullable<Bytea>,
        personality_nonce -> Nullable<Bytea>,
        scenario_nonce -> Nullable<Bytea>,
        first_mes_nonce -> Nullable<Bytea>,
        mes_example_nonce -> Nullable<Bytea>,
        system_prompt_nonce -> Nullable<Bytea>,
        post_history_instructions_nonce -> Nullable<Bytea>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    user_settings (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 100]
        default_model_name -> Nullable<Varchar>,
        default_temperature -> Nullable<Numeric>,
        default_max_output_tokens -> Nullable<Int4>,
        default_frequency_penalty -> Nullable<Numeric>,
        default_presence_penalty -> Nullable<Numeric>,
        default_top_p -> Nullable<Numeric>,
        default_top_k -> Nullable<Int4>,
        default_seed -> Nullable<Int4>,
        default_thinking_budget -> Nullable<Int4>,
        default_enable_code_execution -> Nullable<Bool>,
        default_context_total_token_limit -> Nullable<Int4>,
        default_context_recent_history_budget -> Nullable<Int4>,
        default_context_rag_budget -> Nullable<Int4>,
        auto_save_chats -> Nullable<Bool>,
        #[max_length = 20]
        theme -> Nullable<Varchar>,
        notifications_enabled -> Nullable<Bool>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        typing_speed -> Nullable<Int4>,
        #[max_length = 255]
        preferred_local_model -> Nullable<Varchar>,
        local_llm_enabled -> Nullable<Bool>,
        local_model_preferences -> Nullable<Jsonb>,
        default_thinking_level -> Nullable<Text>,
        default_rag_chronicles_limit -> Nullable<Int4>,
        default_rag_lorebooks_limit -> Nullable<Int4>,
        default_rag_older_chat_limit -> Nullable<Int4>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types::UserRole;
    use super::sql_types::AccountStatus;

    users (id) {
        id -> Uuid,
        #[max_length = 255]
        username -> Varchar,
        password_hash -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        email -> Varchar,
        #[max_length = 128]
        kek_salt -> Varchar,
        encrypted_dek -> Bytea,
        encrypted_dek_by_recovery -> Nullable<Bytea>,
        recovery_kek_salt -> Nullable<Text>,
        dek_nonce -> Bytea,
        recovery_dek_nonce -> Nullable<Bytea>,
        role -> UserRole,
        account_status -> AccountStatus,
        default_persona_id -> Nullable<Uuid>,
        total_prompt_tokens -> Int8,
        total_completion_tokens -> Int8,
        total_token_cost_cents -> Int8,
        tokens_last_reset_at -> Nullable<Timestamptz>,
        token_usage_updated_at -> Timestamptz,
        cached_credit_balance -> Nullable<Int4>,
        #[max_length = 50]
        cached_subscription_tier -> Nullable<Varchar>,
        last_daily_usage_reset -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use super::backend_sql_types::*;
    use diesel_derive_enum::DbEnum;

    webhook_events (id) {
        id -> Uuid,
        #[max_length = 255]
        event_id -> Varchar,
        #[max_length = 100]
        event_type -> Varchar,
        #[max_length = 500]
        paddle_signature -> Varchar,
        #[max_length = 64]
        payload_hash -> Varchar,
        processed_at -> Timestamptz,
        #[max_length = 50]
        processing_status -> Varchar,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(agent_context_analysis -> chat_sessions (chat_session_id));
diesel::joinable!(agent_context_analysis -> users (user_id));
diesel::joinable!(character_assets -> characters (character_id));
diesel::joinable!(character_lorebooks -> characters (character_id));
diesel::joinable!(character_lorebooks -> lorebooks (lorebook_id));
diesel::joinable!(character_lorebooks -> users (user_id));
diesel::joinable!(character_opinions -> message_variants (message_variant_id));
diesel::joinable!(characters -> users (user_id));
diesel::joinable!(chat_character_lorebook_overrides -> chat_sessions (chat_session_id));
diesel::joinable!(chat_character_lorebook_overrides -> lorebooks (lorebook_id));
diesel::joinable!(chat_character_lorebook_overrides -> users (user_id));
diesel::joinable!(chat_character_overrides -> characters (original_character_id));
diesel::joinable!(chat_character_overrides -> chat_sessions (chat_session_id));
diesel::joinable!(chat_messages -> chat_sessions (session_id));
diesel::joinable!(chat_messages -> users (user_id));
diesel::joinable!(chat_session_lorebooks -> chat_sessions (chat_session_id));
diesel::joinable!(chat_session_lorebooks -> lorebooks (lorebook_id));
diesel::joinable!(chat_session_lorebooks -> users (user_id));
diesel::joinable!(chat_sessions -> player_chronicles (player_chronicle_id));
diesel::joinable!(chat_sessions -> user_personas (active_custom_persona_id));
diesel::joinable!(chat_sessions -> users (user_id));
diesel::joinable!(chronicle_events -> chat_sessions (chat_session_id));
diesel::joinable!(chronicle_events -> message_variants (message_variant_id));
diesel::joinable!(chronicle_events -> player_chronicles (chronicle_id));
diesel::joinable!(chronicle_events -> users (user_id));
diesel::joinable!(cognitive_facts -> message_variants (message_variant_id));
diesel::joinable!(credit_transactions -> users (user_id));
diesel::joinable!(daily_usage_tracking -> users (user_id));
diesel::joinable!(email_verification_tokens -> users (user_id));
diesel::joinable!(entity_observations -> message_variants (message_variant_id));
diesel::joinable!(lorebook_entries -> lorebooks (lorebook_id));
diesel::joinable!(lorebook_entries -> users (user_id));
diesel::joinable!(lorebooks -> users (user_id));
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
diesel::joinable!(user_settings -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    agent_context_analysis,
    character_assets,
    character_lorebooks,
    character_opinions,
    characters,
    chat_character_lorebook_overrides,
    chat_character_overrides,
    chat_messages,
    chat_session_lorebooks,
    chat_sessions,
    chronicle_events,
    cognitive_core_memory,
    cognitive_facts,
    credit_packages,
    credit_transactions,
    daily_usage_tracking,
    email_verification_tokens,
    entity_observations,
    lorebook_entries,
    lorebooks,
    message_variants,
    narrative_tasks,
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
