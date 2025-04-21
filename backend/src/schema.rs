// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "message_type"))]
    pub struct MessageType;
}

diesel::table! {
    use diesel::sql_types::*;
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
    use diesel::sql_types::*;
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
        description -> Nullable<Text>,
        personality -> Nullable<Text>,
        scenario -> Nullable<Text>,
        first_mes -> Nullable<Text>,
        mes_example -> Nullable<Text>,
        creator_notes -> Nullable<Text>,
        system_prompt -> Nullable<Text>,
        post_history_instructions -> Nullable<Text>,
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
        persona -> Nullable<Text>,
        world_scenario -> Nullable<Text>,
        avatar -> Nullable<Text>,
        chat -> Nullable<Text>,
        greeting -> Nullable<Text>,
        definition -> Nullable<Text>,
        default_voice -> Nullable<Text>,
        extensions -> Nullable<Jsonb>,
        data_id -> Nullable<Int4>,
        #[max_length = 255]
        category -> Nullable<Varchar>,
        #[max_length = 50]
        definition_visibility -> Nullable<Varchar>,
        depth -> Nullable<Int4>,
        example_dialogue -> Nullable<Text>,
        favorite -> Nullable<Bool>,
        #[max_length = 50]
        first_message_visibility -> Nullable<Varchar>,
        height -> Nullable<Numeric>,
        last_activity -> Nullable<Timestamptz>,
        #[max_length = 255]
        migrated_from -> Nullable<Varchar>,
        model_prompt -> Nullable<Text>,
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
        user_persona -> Nullable<Text>,
        #[max_length = 50]
        user_persona_visibility -> Nullable<Varchar>,
        #[max_length = 50]
        visibility -> Nullable<Varchar>,
        weight -> Nullable<Numeric>,
        #[max_length = 50]
        world_scenario_visibility -> Nullable<Varchar>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;
    use super::sql_types::MessageType;

    chat_messages (id) {
        id -> Uuid,
        session_id -> Uuid,
        message_type -> MessageType,
        content -> Text,
        rag_embedding_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    chat_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        character_id -> Uuid,
        #[max_length = 255]
        title -> Nullable<Varchar>,
        system_prompt -> Nullable<Text>,
        temperature -> Nullable<Numeric>,
        max_output_tokens -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    lorebook_entries (id) {
        id -> Int4,
        lorebook_id -> Int4,
        keys -> Array<Nullable<Text>>,
        content -> Text,
        extensions -> Nullable<Jsonb>,
        enabled -> Bool,
        insertion_order -> Int4,
        case_sensitive -> Nullable<Bool>,
        use_regex -> Bool,
        constant -> Nullable<Bool>,
        #[max_length = 255]
        name -> Nullable<Varchar>,
        priority -> Nullable<Int4>,
        #[max_length = 255]
        entry_id -> Nullable<Varchar>,
        comment -> Nullable<Text>,
        selective -> Nullable<Bool>,
        secondary_keys -> Nullable<Array<Nullable<Text>>>,
        #[max_length = 50]
        position -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    lorebooks (id) {
        id -> Int4,
        character_id -> Uuid,
        #[max_length = 255]
        name -> Nullable<Varchar>,
        description -> Nullable<Text>,
        scan_depth -> Nullable<Int4>,
        token_budget -> Nullable<Int4>,
        recursive_scanning -> Nullable<Bool>,
        extensions -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    sessions (id) {
        id -> Text,
        expires -> Nullable<Timestamptz>,
        session -> Text,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel_derive_enum::DbEnum;

    users (id) {
        id -> Uuid,
        #[max_length = 255]
        username -> Varchar,
        password_hash -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(character_assets -> characters (character_id));
diesel::joinable!(characters -> users (user_id));
diesel::joinable!(chat_messages -> chat_sessions (session_id));
diesel::joinable!(chat_sessions -> characters (character_id));
diesel::joinable!(chat_sessions -> users (user_id));
diesel::joinable!(lorebook_entries -> lorebooks (lorebook_id));
diesel::joinable!(lorebooks -> characters (character_id));

diesel::allow_tables_to_appear_in_same_query!(
    character_assets,
    characters,
    chat_messages,
    chat_sessions,
    lorebook_entries,
    lorebooks,
    sessions,
    users,
);
