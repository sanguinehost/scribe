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
    users,
);
