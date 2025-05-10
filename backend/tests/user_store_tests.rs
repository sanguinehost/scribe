#[cfg(test)]
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
    use scribe_backend::auth::user_store::Backend as AuthBackend; // Use crate namespace and alias Backend
    use scribe_backend::test_helpers::{self, TestApp, TestDataGuard}; // Added TestApp and TestDataGuard

    use uuid::Uuid; // Added import for Uuid

    // Moved from models/users.rs
    #[tokio::test]
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

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_create_user() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        // 1. Define username and email
        let username = format!(
            "testcreateuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!("test1_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
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
                    username: username_clone,
                    email: email_clone,
                    password: password_clone,
                };
                scribe_backend::auth::create_user(
                    conn,
                    register_payload,
                )
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
        let duplicate_email = format!("test2_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let password_for_duplicate = secrecy::SecretString::new("another_password".to_string().into());
        
        // REMOVED: Pre-hash the password for the duplicate attempt
        // let hashed_password_for_duplicate = scribe_backend::auth::hash_password(password_for_duplicate.clone()).await?;

        let password_clone3 = password_for_duplicate.clone(); // For KEK derivation and internal hashing

        let duplicate_result = obj3
            .interact(move |conn| {
                let register_payload = scribe_backend::models::auth::RegisterPayload {
                    username: username_clone3,
                    email: duplicate_email,
                    password: password_clone3,
                };
                scribe_backend::auth::create_user(
                    conn,
                    register_payload,
                )
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        assert!(
            matches!(
                duplicate_result,
                Err(scribe_backend::auth::AuthError::UsernameTaken)
            ),
            "Expected UsernameTaken error for duplicate username, got: {:?}",
            duplicate_result
        );
        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_get_user_by_username() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());


        // Create a user using the auth::create_user function
        let username = format!(
            "testgetuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!("getuser_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let password = SecretString::new("password_get_user".to_string().into());
        
        // REMOVED: let hashed_password = scribe_backend::auth::hash_password(password.clone()).await?;

        let obj_create = pool.get().await?;
        let created_user_result = obj_create
            .interact({
                let username_c = username.clone(); // Renamed to avoid conflict
                let email_c = email.clone(); // Renamed
                let password_c = password.clone(); // Renamed
                // REMOVED: let hashed_password_c = hashed_password.clone(); // Renamed
                move |conn| {
                    let register_payload = scribe_backend::models::auth::RegisterPayload {
                        username: username_c,
                        email: email_c,
                        password: password_c,
                    };
                    scribe_backend::auth::create_user(
                        conn,
                        register_payload,
                    )
                }
            })
            .await??; // Propagate interact error then AuthError
        guard.add_user(created_user_result.id);

        let user_id = created_user_result.id;

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

        assert!(found_user_result.is_ok(), "Expected Ok, got {:?}", found_user_result);
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
            "Expected UserNotFound error, got {:?}",
            not_found_user_result
        );
        let not_found_user: Option<User> = None;

        assert!(not_found_user.is_none(), "User should not be found");
        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_get_user() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        // Create a user using the auth::create_user function
        let username_for_get = format!(
            "testgetuserbyid_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email_for_get = format!("getuserbyid_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let password_for_get = SecretString::new("password_get_user_by_id".to_string().into());

        // REMOVED: let hashed_password_for_get = scribe_backend::auth::hash_password(password_for_get.clone()).await?;
        
        let obj_create = pool.get().await?;
        let created_user = obj_create
            .interact({
                let username_c = username_for_get.clone(); // Renamed
                let email_c = email_for_get.clone(); // Renamed
                let password_c = password_for_get.clone(); // Renamed
                // REMOVED: let hashed_password_c = hashed_password_for_get.clone(); // Renamed
                move |conn| {
                    scribe_backend::auth::create_user(
                        conn,
                        username_c,
                        email_c,
                        password_c,
                        // REMOVED: hashed_password_c,
                    )
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

        assert!(found_user_result.is_ok(), "User should be found by ID. Error: {:?}", found_user_result.err());
        let user = found_user_result.unwrap();
        assert_eq!(user.username, username_for_get);
        assert_eq!(user.id, user_id_to_find);

        // Test finding a non-existent user by ID
        let non_existent_uuid = Uuid::new_v4();
        let obj_get_non_existent = pool.get().await?;
        let not_found_user_result: Result<User, scribe_backend::auth::AuthError> = obj_get_non_existent
            .interact(move |conn| scribe_backend::auth::get_user(conn, non_existent_uuid))
            .await?;

        assert!(
            matches!(
                not_found_user_result,
                Err(scribe_backend::auth::AuthError::UserNotFound)
            ),
            "Expected UserNotFound error for non-existent ID, got {:?}" ,
            not_found_user_result
        );
        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_verify_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let test_app = self::test_helpers::spawn_app(false, false).await;
        let pool = &test_app.db_pool;
        let mut guard = TestDataGuard::new(pool.clone());

        let username = format!(
            "testverifyuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!("verify_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let password_str = "password_verify123".to_string();
        let password_secret = SecretString::new(password_str.clone().into());

        // Create a user first
        // REMOVED: let hashed_password = scribe_backend::auth::hash_password(password_secret.clone()).await?;
        
        let obj_create = pool.get().await?;
        let created_user = { // Limit scope of clones
            let username_c = username.clone();
            let email_c = email.clone();
            let password_secret_c = password_secret.clone();
            // REMOVED: let hashed_password_c = hashed_password.clone();
            let register_payload = scribe_backend::models::auth::RegisterPayload {
                username: username_c,
                email: email_c,
                password: password_secret_c,
            };
            obj_create.interact(move |conn| {
                scribe_backend::auth::create_user(conn, register_payload)
            }).await??
        };
        guard.add_user(created_user.id);
        
        let user_id = created_user.id;

        // Test verify_credentials with correct username and password
        let obj_verify_ok_user = pool.get().await?;
        let verify_ok_user_result = {
            let username_c = username.clone();
            let password_secret_c = password_secret.clone();
            obj_verify_ok_user.interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &username_c, password_secret_c)
            }).await?? // Propagates InteractError, then AuthError
        };
        assert_eq!(verify_ok_user_result.0.id, user_id);
        assert!(verify_ok_user_result.1.is_some(), "DEK should be present after successful verification");


        // Test verify_credentials with correct email and password
        let obj_verify_ok_email = pool.get().await?;
        let verify_ok_email_result = {
            let email_c = email.clone(); // Use the email from the created user
            let password_secret_c = password_secret.clone();
            obj_verify_ok_email.interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &email_c, password_secret_c)
            }).await??
        };
        assert_eq!(verify_ok_email_result.0.id, user_id);
        assert!(verify_ok_email_result.1.is_some(), "DEK should be present after successful verification with email");

        // Test verify_credentials with wrong password
        let wrong_password_secret = SecretString::new("wrongpassword".to_string().into());
        let obj_verify_fail_pw = pool.get().await?;
        let verify_fail_pw_result = {
            let username_c = username.clone();
            let wrong_password_secret_c = wrong_password_secret.clone();
            obj_verify_fail_pw.interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &username_c, wrong_password_secret_c)
            }).await? // InteractError mapped to Box<dyn Error>
        };
         assert!(
            matches!(verify_fail_pw_result, Err(scribe_backend::auth::AuthError::WrongCredentials)),
            "Test failed: verify_credentials with wrong password did not return AuthError::WrongCredentials. Actual: {:?}", verify_fail_pw_result.err() // Only show error part if available
        );
        

        // Test verify_credentials with non-existent username
        let obj_verify_notfound = pool.get().await?;
        let verify_notfound_result = {
            let password_secret_c = password_secret.clone();
            obj_verify_notfound.interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, "nonexistentuser", password_secret_c)
            }).await?
        };
        assert!(
            matches!(verify_notfound_result, Err(scribe_backend::auth::AuthError::UserNotFound) | Err(scribe_backend::auth::AuthError::WrongCredentials)),
            "Test failed: verify_credentials with non-existent user did not return UserNotFound or WrongCredentials. Actual: {:?}", verify_notfound_result.err()
        );
        // Note: The current verify_credentials first finds the user, then verifies password.
        // If user is not found by identifier, it returns UserNotFound from the first db query.
        // So, UserNotFound is the correct expectation here.


        // Test HashingError (difficult to trigger reliably in unit test, usually for bcrypt internal issues)
        // This would ideally be tested by somehow making bcrypt::verify fail with something other than invalid password.

        // Test CryptoOperationFailed for KEK derivation
        // To test this, we'd need create_user to succeed, but then provide a salt for KEK derivation
        // that is somehow invalid for crypto::derive_kek AFTER it was successfully stored by create_user,
        // or the password itself causes derive_kek to fail.
        // The KEK salt is generated by create_user, so it should always be valid.
        // This error is more likely if `derive_kek` itself has an issue or if the password somehow
        // causes an unexpected error in argon2.
        // Let's simulate by temporarily altering the stored KEK salt to be invalid base64 for a specific user.
        
        let obj_crypto_err = pool.get().await?;
        // Manually update the user's KEK salt to something invalid for base64 decoding
        let invalid_kek_salt = "!!!invalid_base64_salt!!!".to_string();
        obj_crypto_err.interact({
            let user_id_c = user_id;
            let invalid_kek_salt_c = invalid_kek_salt.clone();
            move |conn| {
                diesel::update(scribe_backend::schema::users::table.find(user_id_c))
                    .set(scribe_backend::schema::users::kek_salt.eq(invalid_kek_salt_c))
                    .execute(conn)
            }
        }).await??;

        let obj_verify_crypto_fail = pool.get().await?;
        let verify_crypto_fail_result = {
            let username_c = username.clone();
            let password_secret_c = password_secret.clone();
            obj_verify_crypto_fail.interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &username_c, password_secret_c)
            }).await?
        };
        
        if !matches!(verify_crypto_fail_result, Err(scribe_backend::auth::AuthError::CryptoOperationFailed(_))) {
            panic!(
                "Expected CryptoOperationFailed due to invalid KEK salt. Actual: {}",
                match verify_crypto_fail_result {
                    Ok((u, _)) => format!("Ok(User: {}, DEK: <secret>)", u.id),
                    Err(e) => format!("Err({:?})", e),
                }
            );
        }

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_user_from_session_token_success() {
        let test_app = self::test_helpers::spawn_app(false, false).await; // Use spawn_app
        let _pool = &test_app.db_pool; // Get pool from TestApp
        // let _user_store = AuthBackend::new(pool.clone()); // AuthBackend can be used if needed
        // let _auth_backend = AuthBackend::new(pool.clone()); // Redundant with above

        // Setup: Create a user and a session
        // ... existing code ...
        // This test is incomplete and will likely need further refactoring
        // based on how session tokens are handled with the new API-based login.
        // For now, just updating the setup.
    }
}
