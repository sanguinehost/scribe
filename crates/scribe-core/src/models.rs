use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UserRole {
    #[default]
    User,
    Moderator,
    Administrator,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "User"),
            Self::Moderator => write!(f, "Moderator"),
            Self::Administrator => write!(f, "Administrator"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccountStatus {
    #[default]
    Active,
    Locked,
    Pending,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Locked => write!(f, "locked"),
            Self::Pending => write!(f, "pending"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_user_role_display(role in proptest::sample::select(vec![UserRole::User, UserRole::Moderator, UserRole::Administrator])) {
            let display_str = format!("{}", role);
            assert!(matches!(display_str.as_str(), "User" | "Moderator" | "Administrator"));
        }
    }
}
