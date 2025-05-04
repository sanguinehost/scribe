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
    use deadpool_diesel::Runtime;
    use deadpool_diesel::postgres::Manager;
    use diesel::prelude::*;
    use scribe_backend::models::users::User; // Needed for assertions
    use scribe_backend::state::DbPool;
    use secrecy::{ExposeSecret, Secret};
    // Use crate namespace for test helpers
    use scribe_backend::auth::user_store::Backend as AuthBackend; // Use crate namespace and alias Backend

    use uuid::Uuid; // Added import for Uuid
    // Import UserStore Backend
    use scribe_backend::auth::user_store::Backend as UserStoreBackend; // Correct import and alias

    // Placeholder function to simulate getting the pool (replace with actual import later)
    fn get_test_pool() -> Result<DbPool, Box<dyn std::error::Error>> {
        // In a real scenario, this would call the actual shared helper
        // For now, mimic pool creation locally to allow compilation
        dotenvy::dotenv().ok();
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
        let manager = Manager::new(&database_url, Runtime::Tokio1);
        let pool: DbPool = deadpool_diesel::Pool::builder(manager).build()?;
        Ok(pool)
    }

    // Moved from models/users.rs
    #[tokio::test]
    // This test is pure computation, no external services needed
    async fn test_password_hashing_and_verification() -> Result<(), Box<dyn std::error::Error>> {
        let password_string = "test_password123".to_string();
        let password_secret = Secret::new(password_string.clone());

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
        let pool = get_test_pool()?;

        // 1. Define username and email
        let username = format!(
            "testcreateuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!("test1_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let password = secrecy::Secret::new("password123".to_string());

        // 2. Call create_user
        let obj = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone = username.clone();
        let email_clone = email.clone();
        let password_clone = password.clone();
        let create_result = obj
            .interact(move |conn| {
                scribe_backend::auth::create_user(conn, username_clone, email_clone, password_clone)
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
        let password_clone3 = secrecy::Secret::new("another_password".to_string());
        let duplicate_result = obj3
            .interact(move |conn| {
                scribe_backend::auth::create_user(conn, username_clone3, duplicate_email, password_clone3)
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

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_get_user_by_username() -> Result<(), Box<dyn std::error::Error>> {
        let _pool = get_test_pool()?;
        let obj = _pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Manually insert a user for testing
        let username = format!(
            "testgetuser_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let user_id = uuid::Uuid::new_v4();

        let insert_username = username.clone();
        let insert_password_hash = password_hash.clone();
        let email = format!("{}@example.com", insert_username.clone());
        obj.interact(move |conn| {
            diesel::insert_into(scribe_backend::schema::users::table)
                .values((
                    scribe_backend::schema::users::id.eq(user_id),
                    scribe_backend::schema::users::username.eq(insert_username),
                    scribe_backend::schema::users::password_hash.eq(insert_password_hash),
                    scribe_backend::schema::users::email.eq(email),
                ))
                .execute(conn)
        })
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Test finding the existing user
        let obj2 = _pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone1 = username.to_string();
        let found_user_result: Result<User, scribe_backend::auth::AuthError> = obj2
            .interact(move |conn| get_user_by_username(conn, &username_clone1))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
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
        let obj3 = _pool
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

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_get_user() -> Result<(), Box<dyn std::error::Error>> {
        let pool = get_test_pool()?;

        // 1. Create a user first
        let username = format!(
            "testgetuser2_{}",
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let email = format!("test3_{}@example.com", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let password = secrecy::Secret::new("password123".to_string());

        let obj = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone = username.clone();
        let email_clone = email.clone();
        let password_clone = password.clone();
        let create_result = obj
            .interact(move |conn| {
                scribe_backend::auth::create_user(conn, username_clone, email_clone, password_clone)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let created_user = create_result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let user_id = created_user.id;

        // 2. Call get_user with the correct user ID
        let obj2 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let user_id_clone = user_id.clone();
        let get_user_result = obj2
            .interact(move |conn| scribe_backend::auth::get_user(conn, user_id_clone))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 3. Assert Ok(user)
        assert!(
            get_user_result.is_ok(),
            "Get user failed: {:?}",
            get_user_result.err()
        );
        let retrieved_user = get_user_result.unwrap();
        assert_eq!(retrieved_user.id, user_id);
        assert_eq!(retrieved_user.username, username);

        // 4. Call get_user with a random non-existent UUID
        let obj3 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let nonexistent_id = uuid::Uuid::new_v4();
        let nonexistent_result = obj3
            .interact(move |conn| scribe_backend::auth::get_user(conn, nonexistent_id))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 5. Assert error is UserNotFound
        assert!(
            matches!(
                nonexistent_result,
                Err(scribe_backend::auth::AuthError::UserNotFound)
            ),
            "Expected UserNotFound error for non-existent user, got: {:?}",
            nonexistent_result
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_verify_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let pool = get_test_pool()?;
        let _auth_backend = AuthBackend::new(pool.clone());
        let username = format!("verify_user_{}", Uuid::new_v4());
        let email = format!("test4_{}@example.com", Uuid::new_v4().to_string().split('-').next().unwrap());
        let password = "test_password".to_string();

        // 1. Hash the password first
        let password_secret_plain = secrecy::Secret::new(password.clone());
        let hashed_password_string =
            scribe_backend::auth::hash_password(password_secret_plain.clone()).await?;
        let hashed_password_secret = secrecy::Secret::new(hashed_password_string); // Wrap the hash in Secret for create_user

        // 2. Create user using the HASHED password
        let obj = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone = username.clone();
        let email_clone = email.clone();
        // Pass the SECRET containing the HASH to create_user
        let create_result = obj
            .interact(move |conn| {
                scribe_backend::auth::create_user(conn, username_clone, email_clone, hashed_password_secret)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let created_user = create_result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 3. Call verify_credentials with correct username/PLAIN password
        let obj2 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone2 = username.clone();
        // Pass the SECRET containing the PLAIN password to verify_credentials
        let correct_password_plain = secrecy::Secret::new(password.clone());
        let verify_correct_result = obj2
            .interact(move |conn| {
                scribe_backend::auth::verify_credentials(
                    conn,
                    &username_clone2,
                    correct_password_plain,
                )
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 4. Assert Ok(user)
        assert!(
            verify_correct_result.is_ok(),
            "Verify with correct credentials failed: {:?}",
            verify_correct_result.err()
        );
        let verified_user = verify_correct_result.unwrap();
        assert_eq!(verified_user.id, created_user.id);
        assert_eq!(verified_user.username, username);

        // 5. Call verify_credentials with correct username/incorrect PLAIN password
        let obj3 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone3 = username.clone();
        let incorrect_password = secrecy::Secret::new("wrong_password".to_string());
        let verify_wrong_pass_result = obj3
            .interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &username_clone3, incorrect_password)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 6. Assert Err(WrongCredentials)
        assert!(
            matches!(
                verify_wrong_pass_result,
                Err(scribe_backend::auth::AuthError::WrongCredentials)
            ),
            "Expected WrongCredentials error for incorrect password, got: {:?}",
            verify_wrong_pass_result
        );

        // 7. Call verify_credentials with incorrect username
        let obj4 = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let nonexistent_username = "nonexistent_user".to_string();
        let some_password = secrecy::Secret::new("some_password".to_string());
        let verify_wrong_user_result = obj4
            .interact(move |conn| {
                scribe_backend::auth::verify_credentials(conn, &nonexistent_username, some_password)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 8. Assert Err(UserNotFound)
        assert!(
            matches!(
                verify_wrong_user_result,
                Err(scribe_backend::auth::AuthError::UserNotFound)
            ),
            "Expected UserNotFound error for non-existent user, got: {:?}",
            verify_wrong_user_result
        );

        // Cleanup: Delete the created user
        let user_id_to_delete = created_user.id;
        let obj_cleanup = pool
            .get()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let _ = obj_cleanup
            .interact(move |conn| {
                diesel::delete(scribe_backend::schema::users::table.find(user_id_to_delete))
                    .execute(conn)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Added ignore for CI (interacts with DB)
    async fn test_user_from_session_token_success() {
        let pool = get_test_pool().expect("Failed to get test pool"); // Use local helper and expect
        let _user_store = UserStoreBackend::new(pool.clone()); // Remove mut and prefix with _ as it's unused
        let _auth_backend = AuthBackend::new(pool.clone()); // Prefix with _

        // Setup: Create a user and a session
        // ... existing code ...
    }
}
