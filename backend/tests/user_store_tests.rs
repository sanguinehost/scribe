#[cfg(test)]
#[allow(clippy::items_after_statements)]
#[allow(clippy::module_inception)]
mod user_store_tests {
    // Import create_test_pool from the db_integration_tests module
    // Note: Tests need to be structured correctly for cross-file imports, or helpers moved to lib/test_utils.
    // Assuming for now that db_integration_tests is accessible or helpers will be refactored.
    // If compilation fails here, we need to move test helpers.
    // For now, let's just reference it conceptually and add needed imports.
    // use crate::db_integration_tests::create_test_pool; // Placeholder comment

    use scribe_backend::auth::get_user_by_username;
    // Replace setup_test_db with a function that returns the correct pool type (likely async)
    // Assuming create_test_pool returns the `scribe_backend::state::DbPool` needed by auth functions
    // use deadpool_diesel::Runtime; // No longer needed directly
    // use deadpool_diesel::postgres::Manager; // No longer needed directly
    use diesel::prelude::*;
    use scribe_backend::models::users::User; // Needed for assertions
    // use scribe_backend::state::DbPool; // Will get from TestApp
    use secrecy::{ExposeSecret, SecretString};
    // Use crate namespace for test helpers
    use scribe_backend::test_helpers::{self, TestDataGuard}; // Removed TestApp

    use uuid::Uuid; // Added import for Uuid

    // Helper functions for basic verification
    async fn test_basic_credential_verification(
        pool: &scribe_backend::state::DbPool,
        guard: &mut TestDataGuard,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (username, email, password_secret) = generate_test_user_data();

        let created_user = create_test_user_for_verification(
            pool,
            username.clone(),
            email.clone(),
            password_secret.clone(),
        )
        .await?;
        guard.add_user(created_user.id);

        // Test basic scenarios
        verify_and_assert(
            pool,
            &username,
            password_secret.clone(),
            Ok(created_user.id),
            "username",
        )
        .await?;
        verify_and_assert(
            pool,
            &email,
            password_secret.clone(),
            Ok(created_user.id),
            "email",
        )
        .await?;

        let wrong_password = SecretString::new("wrong".to_string().into());
        verify_and_assert(
            pool,
            &username,
            wrong_password,
            Err(scribe_backend::auth::AuthError::WrongCredentials),
            "wrong password",
        )
        .await?;

        Ok(())
    }

    fn generate_test_user_data() -> (String, String, SecretString) {
        let username = format!(
            "testuser_{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!(
            "test_{}@example.com",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let password = SecretString::new("password123".to_string().into());
        (username, email, password)
    }

    async fn create_test_user_for_verification(
        pool: &scribe_backend::state::DbPool,
        username: String,
        email: String,
        password: SecretString,
    ) -> Result<scribe_backend::models::users::User, Box<dyn std::error::Error>> {
        let obj = pool.get().await?;
        let payload = scribe_backend::models::auth::RegisterPayload {
            recovery_phrase: None,
            username,
            email,
            password,
        };
        obj.interact(move |conn| {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
            rt.block_on(scribe_backend::auth::create_user(conn, payload))
        })
        .await?
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    async fn verify_and_assert(
        pool: &scribe_backend::state::DbPool,
        identifier: &str,
        password: SecretString,
        expected: Result<Uuid, scribe_backend::auth::AuthError>,
        test_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let obj = pool.get().await?;
        let id = identifier.to_string();
        let result = obj
            .interact(move |conn| scribe_backend::auth::verify_credentials(conn, &id, password))
            .await?;

        match expected {
            Ok(expected_id) => {
                let (user, dek) = result.map_err(|e| format!("Test {test_name} failed: {e:?}"))?;
                assert_eq!(user.id, expected_id, "Test {test_name}: ID mismatch");
                assert!(dek.is_some(), "Test {test_name}: DEK missing");
            }
            Err(expected_err) => {
                assert!(
                    matches!(result, Err(ref e) if e == &expected_err),
                    "Test {test_name}: Expected {expected_err:?}, got {result:?}"
                );
            }
        }
        Ok(())
    }

    async fn test_crypto_failure_scenarios(
        pool: &scribe_backend::state::DbPool,
        user_id: Uuid,
        username: &str,
        password: SecretString,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let obj = pool.get().await?;
        let invalid_salt = "!!!invalid_base64_salt!!!".to_string();
        obj.interact({
            let user_id_c = user_id;
            let salt_c = invalid_salt;
            move |conn| {
                diesel::update(scribe_backend::schema::users::table.find(user_id_c))
                    .set(scribe_backend::schema::users::kek_salt.eq(salt_c))
                    .execute(conn)
            }
        })
        .await??;

        let obj2 = pool.get().await?;
        let result = {
            let username_c = username.to_string();
            obj2.interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &username_c, password)
            })
            .await?
        };

        assert!(
            matches!(
                result,
                Err(scribe_backend::auth::AuthError::CryptoOperationFailed(_))
            ),
            "Expected crypto failure, got: {result:?}"
        );
        Ok(())
    }

    // Add imports from scribe-backend packages
    // Just import the crypto module

    // Moved from models/users.rs
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // This test is pure computation, no external services needed
    async fn test_password_hashing_and_verification() -> Result<(), Box<dyn std::error::Error>> {
        let password_string = "test_password123".to_string();
        let password_secret = SecretString::new(password_string.clone().into());

        let hashed_password = bcrypt::hash(password_secret.expose_secret(), bcrypt::DEFAULT_COST)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let is_valid = bcrypt::verify(&password_string, &hashed_password)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert!(
            is_valid,
            "Password verification should succeed for the correct password."
        );

        let incorrect_password = "wrong_password";
        let is_invalid = bcrypt::verify(incorrect_password, &hashed_password)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert!(
            !is_invalid,
            "Password verification should fail for an incorrect password."
        );

        let hashed_password_again =
            bcrypt::hash(password_secret.expose_secret(), bcrypt::DEFAULT_COST)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert_ne!(
            hashed_password, hashed_password_again,
            "Hashing the same password twice should produce different hashes due to salting."
        );
        let is_valid_again = bcrypt::verify(&password_string, &hashed_password_again)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert!(
            is_valid_again,
            "Verification should still succeed with the second hash."
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_create_user() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        // 1. Define username and email
        let username = format!(
            "testcreateuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!(
            "test1_{}@example.com",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let password = secrecy::SecretString::new("password123".to_string().into());

        // REMOVED: Pre-hash the password
        // let hashed_password = scribe_backend::auth::hash_password(password.clone()).await?;

        // 2. Call create_user
        let obj = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone = username.clone();
        let email_clone = email.clone();
        let password_clone = password.clone(); // For KEK derivation and internal hashing

        let create_result = obj
            .interact(move |conn| {
                let register_payload = scribe_backend::models::auth::RegisterPayload {
                    recovery_phrase: None,
                    username: username_clone,
                    email: email_clone,
                    password: password_clone,
                };
                // Create a new Runtime for the blocking task to handle async in a sync context
                let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime in test");
                rt.block_on(scribe_backend::auth::create_user(conn, register_payload))
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 3. Assert Ok result
        assert!(
            create_result.is_ok(),
            "User creation failed: {:?}",
            create_result.err()
        );
        let created_user = create_result.unwrap();
        assert_eq!(created_user.username, username);
        guard.add_user(created_user.id); // Add to guard

        // 4. Verify the user exists in DB using get_user_by_username
        let obj2 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone2 = username.clone();
        let get_user_result = obj2
            .interact(move |conn| {
                scribe_backend::auth::get_user_by_username(conn, &username_clone2)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        assert!(
            get_user_result.is_ok(),
            "Unable to retrieve created user: {:?}",
            get_user_result.err()
        );
        let retrieved_user = get_user_result.unwrap();
        assert_eq!(retrieved_user.id, created_user.id);
        assert_eq!(retrieved_user.username, username);

        // 5. Test duplicate username constraint
        let obj3 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone3 = username.clone();
        let duplicate_email = format!(
            "test2_{}@example.com",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let password_for_duplicate =
            secrecy::SecretString::new("another_password".to_string().into());

        // REMOVED: Pre-hash the password for the duplicate attempt
        // let hashed_password_for_duplicate = scribe_backend::auth::hash_password(password_for_duplicate.clone()).await?;

        let password_clone3 = password_for_duplicate.clone(); // For KEK derivation and internal hashing

        let duplicate_result = obj3
            .interact(move |conn| {
                let register_payload = scribe_backend::models::auth::RegisterPayload {
                    recovery_phrase: None,
                    username: username_clone3,
                    email: duplicate_email,
                    password: password_clone3,
                };
                // Create a new Runtime for the blocking task to handle async in a sync context
                let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime in test");
                rt.block_on(scribe_backend::auth::create_user(conn, register_payload))
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        assert!(
            matches!(
                duplicate_result,
                Err(scribe_backend::auth::AuthError::UsernameTaken)
            ),
            "Expected UsernameTaken error for duplicate username, got: {duplicate_result:?}"
        );
        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_get_user_by_username() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        // Create a user using the auth::create_user function
        let username = format!(
            "testgetuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!(
            "getuser_{}@example.com",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let password = SecretString::new("password_get_user".to_string().into());

        // REMOVED: let hashed_password = scribe_backend::auth::hash_password(password.clone()).await?;

        let obj_create = pool.get().await?;
        let created_user_result = obj_create
            .interact({
                let username_c = username.clone(); // Renamed to avoid conflict
                let email_c = email.clone(); // Renamed
                let password_c = password.clone(); // Renamed
                move |conn| {
                    let register_payload = scribe_backend::models::auth::RegisterPayload {
                        recovery_phrase: None,
                        username: username_c,
                        email: email_c,
                        password: password_c,
                    };
                    // Create a runtime to handle async in a sync context
                    let rt =
                        tokio::runtime::Runtime::new().expect("Failed to create runtime in test");
                    rt.block_on(scribe_backend::auth::create_user(conn, register_payload))
                }
            })
            .await?; // Handle interact error

        let created_user = created_user_result?; // Handle AuthError
        guard.add_user(created_user.id);

        let user_id = created_user.id;

        // Test finding the existing user
        let obj2 = pool // Use pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone1 = username.to_string();
        let found_user_result: Result<User, scribe_backend::auth::AuthError> = obj2
            .interact(move |conn| get_user_by_username(conn, &username_clone1))
            .await
            .map_err(|interact_err| Box::new(interact_err) as Box<dyn std::error::Error>)?;

        assert!(
            found_user_result.is_ok(),
            "Expected Ok, got {found_user_result:?}"
        );
        let found_user: Option<User> = match found_user_result {
            Ok(user) => Some(user),
            Err(scribe_backend::auth::AuthError::UserNotFound) => None,
            Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error>),
        };

        assert!(found_user.is_some(), "User should be found");
        let user = found_user.unwrap();
        assert_eq!(user.username, username);
        assert_eq!(user.id, user_id);

        // Test finding a non-existent user
        let obj3 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let not_found_user_result: Result<User, scribe_backend::auth::AuthError> = obj3
            .interact(|conn| get_user_by_username(conn, "nonexistentuser"))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        assert!(
            matches!(
                not_found_user_result,
                Err(scribe_backend::auth::AuthError::UserNotFound)
            ),
            "Expected UserNotFound error, got {not_found_user_result:?}"
        );
        let not_found_user: Option<User> = None;

        assert!(not_found_user.is_none(), "User should not be found");
        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_get_user() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        // Create a user using the auth::create_user function
        let username_for_get = format!(
            "testgetuserbyid_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email_for_get = format!(
            "getuserbyid_{}@example.com",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let password_for_get = SecretString::new("password_get_user_by_id".to_string().into());

        // REMOVED: let hashed_password_for_get = scribe_backend::auth::hash_password(password_for_get.clone()).await?;

        let obj_create = pool.get().await?;
        let created_user = obj_create
            .interact({
                let username_c = username_for_get.clone(); // Renamed
                let email_c = email_for_get.clone(); // Renamed
                let password_c = password_for_get.clone(); // Renamed
                move |conn| {
                    let register_payload = scribe_backend::models::auth::RegisterPayload {
                        recovery_phrase: None,
                        username: username_c,
                        email: email_c,
                        password: password_c,
                    };
                    // Create a runtime to handle async in a sync context
                    let rt =
                        tokio::runtime::Runtime::new().expect("Failed to create runtime in test");
                    rt.block_on(scribe_backend::auth::create_user(conn, register_payload))
                }
            })
            .await??; // Propagate interact error then AuthError
        guard.add_user(created_user.id);

        let user_id_to_find = created_user.id;

        // Test finding the existing user by ID
        let obj_get = pool.get().await?;
        let found_user_result: Result<User, scribe_backend::auth::AuthError> = obj_get
            .interact(move |conn| scribe_backend::auth::get_user(conn, user_id_to_find))
            .await?;

        assert!(
            found_user_result.is_ok(),
            "User should be found by ID. Error: {:?}",
            found_user_result.err()
        );
        let user = found_user_result.unwrap();
        assert_eq!(user.username, username_for_get);
        assert_eq!(user.id, user_id_to_find);

        // Test finding a non-existent user by ID
        let non_existent_uuid = Uuid::new_v4();
        let obj_get_non_existent = pool.get().await?;
        let not_found_user_result: Result<User, scribe_backend::auth::AuthError> =
            obj_get_non_existent
                .interact(move |conn| scribe_backend::auth::get_user(conn, non_existent_uuid))
                .await?;

        assert!(
            matches!(
                not_found_user_result,
                Err(scribe_backend::auth::AuthError::UserNotFound)
            ),
            "Expected UserNotFound error for non-existent ID, got {not_found_user_result:?}"
        );
        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_verify_credentials_basic() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        test_basic_credential_verification(pool, &mut guard).await?;

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_verify_credentials_crypto_failure() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        let (username, email, password_secret) = generate_test_user_data();
        let created_user = create_test_user_for_verification(
            pool,
            username.clone(),
            email.clone(),
            password_secret.clone(),
        )
        .await?;
        guard.add_user(created_user.id);

        test_crypto_failure_scenarios(pool, created_user.id, &username, password_secret).await?;

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_user_from_session_token_success() {
        let _test_app = self::test_helpers::spawn_app(false, false, false).await; // Use spawn_app
        // let _user_store = AuthBackend::new(pool.clone()); // AuthBackend can be used if needed
        // let _auth_backend = AuthBackend::new(pool.clone()); // Redundant with above

        // Setup: Create a user and a session
        // ... existing code ...
        // This test is incomplete and will likely need further refactoring
        // based on how session tokens are handled with the new API-based login.
        // For now, just updating the setup.
    }
}
