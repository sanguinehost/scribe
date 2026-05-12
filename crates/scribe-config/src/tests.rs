use super::*;

#[test]
fn test_default_config() {
    let config = Config::load().unwrap_or_else(|_| {
        // If env vars are not set, it might fail, so we test defaults via serde
        serde_json::from_str::<Config>("{}").unwrap()
    });
    assert_eq!(config.port, 8080);
}

#[test]
fn test_environment_defaults() {
    let mut config = serde_json::from_str::<Config>("{}").unwrap();
    config.environment = Some("local".to_string());
    config.session_cookie_secure = true;
    config.apply_environment_defaults();
    assert_eq!(config.session_cookie_secure, false);
}
