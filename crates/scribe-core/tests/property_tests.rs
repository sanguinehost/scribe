use proptest::prelude::*;
use scribe_core::{UserRole, AccountStatus};
use serde_json;

proptest! {
    #[test]
    fn test_user_role_roundtrip(role in any_user_role()) {
        let serialized = serde_json::to_string(&role).unwrap();
        let deserialized: UserRole = serde_json::from_str(&serialized).unwrap();
        assert_eq!(role, deserialized);
    }

    #[test]
    fn test_account_status_roundtrip(status in any_account_status()) {
        let serialized = serde_json::to_string(&status).unwrap();
        let deserialized: AccountStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(status, deserialized);
    }
}

fn any_user_role() -> impl Strategy<Value = UserRole> {
    prop_oneof![
        Just(UserRole::User),
        Just(UserRole::Moderator),
        Just(UserRole::Administrator),
    ]
}

fn any_account_status() -> impl Strategy<Value = AccountStatus> {
    prop_oneof![
        Just(AccountStatus::Active),
        Just(AccountStatus::Locked),
        Just(AccountStatus::Pending),
    ]
}
