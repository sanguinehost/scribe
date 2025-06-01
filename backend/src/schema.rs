// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "account_status"))]
    pub struct AccountStatus;

    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "message_type"))]
    pub struct MessageType;

    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "user_role"))]
    pub struct UserRole;
}

diesel::table! {
    use diesel::sql_types::{Int4, Text, Timestamptz, Uuid, Varchar};
    use diesel_derive_enum::DbEnum;

    character_assets (id) {
        id -> Int4,
        character_id -> Uuid,
        #[max_length = 50]
        asset_type -> Varchar,
        uri -> Text,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 50]
        ext -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::{Array, Bool, Bytea, Int4, Int8, Jsonb, Nullable, Numeric, Text, Timestamptz, Uuid, Varchar};
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
        tags -> Nullable<Array<Nullable<Text>>>,
        #[max_length = 255]
        creator -> Nullable<Varchar>,
        #[max_length = 255]
        character_version -> Nullable<Varchar>,
        alternate_greetings -> Nullable<Array<Nullable<Text>>>,
        #[max_length = 255]
        nickname -> Nullable<Varchar>,
        creator_notes_multilingual -> Nullable<Jsonb>,
        source -> Nullable<Array<Nullable<Text>>>,
        group_only_greetings -> Nullable<Array<Nullable<Text>>>,
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
        system_tags -> Nullable<Array<Nullable<Text>>>,
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
    }
}

diesel::table! {
    use diesel::sql_types::{Bytea, Timestamptz, Uuid, Varchar};
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
    use diesel::sql_types::{Bytea, Int4, Jsonb, Nullable, Timestamptz, Uuid, Varchar};
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
        prompt_tokens -> Nullable<Int4>,
        completion_tokens -> Nullable<Int4>,
    }
}

diesel::table! {
    use diesel::sql_types::{Timestamptz, Uuid};
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
    use diesel::sql_types::{Array, Bool, Bytea, Int4, Jsonb, Nullable, Numeric, Text, Timestamptz, Uuid, Varchar};
    use diesel_derive_enum::DbEnum;

    chat_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        character_id -> Uuid,
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
        gemini_thinking_budget -> Nullable<Int4>,
        gemini_enable_code_execution -> Nullable<Bool>,
        #[max_length = 50]
        visibility -> Nullable<Varchar>,
        active_custom_persona_id -> Nullable<Uuid>,
        active_impersonated_character_id -> Nullable<Uuid>,
        system_prompt_ciphertext -> Nullable<Bytea>,
        system_prompt_nonce -> Nullable<Bytea>,
        title_ciphertext -> Nullable<Bytea>,
        title_nonce -> Nullable<Bytea>,
        stop_sequences -> Nullable<Array<Nullable<Text>>>,
    }
}

diesel::table! {
    use diesel::sql_types::{Bool, Bytea, Int4, Nullable, Timestamptz, Uuid, Varchar};
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
    use diesel::sql_types::{Bool, Nullable, Text, Timestamptz, Uuid, Varchar};
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
    use diesel::sql_types::{Nullable, Text, Timestamptz, Uuid, Varchar};
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
    use diesel::sql_types::{Bool, Nullable, Text, Timestamptz, Uuid};
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
    use diesel::sql_types::{Bool, Uuid};
    use diesel_derive_enum::DbEnum;

    old_votes (chat_id, message_id) {
        chat_id -> Uuid,
        message_id -> Uuid,
        is_upvoted -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::{Nullable, Text, Timestamptz};
    use diesel_derive_enum::DbEnum;

    sessions (id) {
        id -> Text,
        expires -> Nullable<Timestamptz>,
        session -> Text,
    }
}

diesel::table! {
    use diesel::sql_types::{Array, Bytea, Nullable, Text, Timestamptz, Uuid, Varchar};
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
        tags -> Nullable<Array<Nullable<Text>>>,
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
    use diesel::sql_types::{Bytea, Nullable, Text, Timestamptz, Uuid, Varchar};
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
    }
}

diesel::joinable!(character_assets -> characters (character_id));
diesel::joinable!(characters -> users (user_id));
diesel::joinable!(chat_character_overrides -> characters (original_character_id));
diesel::joinable!(chat_character_overrides -> chat_sessions (chat_session_id));
diesel::joinable!(chat_messages -> chat_sessions (session_id));
diesel::joinable!(chat_messages -> users (user_id));
diesel::joinable!(chat_session_lorebooks -> chat_sessions (chat_session_id));
diesel::joinable!(chat_session_lorebooks -> lorebooks (lorebook_id));
diesel::joinable!(chat_session_lorebooks -> users (user_id));
diesel::joinable!(chat_sessions -> user_personas (active_custom_persona_id));
diesel::joinable!(chat_sessions -> users (user_id));
diesel::joinable!(lorebook_entries -> lorebooks (lorebook_id));
diesel::joinable!(lorebook_entries -> users (user_id));
diesel::joinable!(lorebooks -> users (user_id));
diesel::joinable!(old_documents -> users (user_id));
diesel::joinable!(old_suggestions -> users (user_id));
diesel::joinable!(old_votes -> chat_messages (message_id));
diesel::joinable!(old_votes -> chat_sessions (chat_id));

diesel::allow_tables_to_appear_in_same_query!(
    character_assets,
    characters,
    chat_character_overrides,
    chat_messages,
    chat_session_lorebooks,
    chat_sessions,
    lorebook_entries,
    lorebooks,
    old_documents,
    old_suggestions,
    old_votes,
    sessions,
    user_personas,
    users,
);
