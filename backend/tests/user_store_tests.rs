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
    use scribe_backend::state::DbPool;
    use scribe_backend::models::users::User; // Needed for assertions
    use secrecy::{ExposeSecret, Secret};
    use diesel::prelude::*;
    use deadpool_diesel::postgres::Manager;
    use deadpool_diesel::Runtime;

    // Placeholder function to simulate getting the pool (replace with actual import later)
    fn get_test_pool() -> Result<DbPool, Box<dyn std::error::Error>> {
        // In a real scenario, this would call the actual shared helper
        // For now, mimic pool creation locally to allow compilation
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
        let manager = Manager::new(&database_url, Runtime::Tokio1);
        let pool: DbPool = deadpool_diesel::Pool::builder(manager).build()?;
        Ok(pool)
    }

    // Moved from models/users.rs
    #[tokio::test]
    async fn test_password_hashing_and_verification() -> Result<(), Box<dyn std::error::Error>> {
        let password_string = "test_password123".to_string();
        let password_secret = Secret::new(password_string.clone());

        let hashed_password = bcrypt::hash(password_secret.expose_secret(), bcrypt::DEFAULT_COST)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let is_valid = bcrypt::verify(&password_string, &hashed_password)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert!(is_valid, "Password verification should succeed for the correct password.");

        let incorrect_password = "wrong_password";
        let is_invalid = bcrypt::verify(incorrect_password, &hashed_password)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert!(!is_invalid, "Password verification should fail for an incorrect password.");

        let hashed_password_again = bcrypt::hash(password_secret.expose_secret(), bcrypt::DEFAULT_COST)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert_ne!(hashed_password, hashed_password_again, "Hashing the same password twice should produce different hashes due to salting.");
        let is_valid_again = bcrypt::verify(&password_string, &hashed_password_again)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert!(is_valid_again, "Verification should still succeed with the second hash.");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_user() -> Result<(), Box<dyn std::error::Error>> {
        let _pool = get_test_pool()?;
        // TODO: Implement test
        // 1. Define username and password
        // 2. Call create_user
        // 3. Assert Ok result
        // 4. Query DB directly or use get_user to verify creation and password hash storage (requires get_user to be implemented)
        // 5. Consider testing duplicate username constraint
        panic!("test_create_user not implemented");
        // Ok(())
    }

    #[tokio::test]
    async fn test_get_user_by_username() -> Result<(), Box<dyn std::error::Error>> {
        let _pool = get_test_pool()?;
        let obj = _pool.get().await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Manually insert a user for testing
        let username = "testgetuser";
        let password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let user_id = uuid::Uuid::new_v4();

        let insert_username = username.to_string();
        let insert_password_hash = password_hash.clone();
        obj.interact(move |conn| {
            diesel::insert_into(scribe_backend::schema::users::table)
                .values((
                    scribe_backend::schema::users::id.eq(user_id),
                    scribe_backend::schema::users::username.eq(insert_username),
                    scribe_backend::schema::users::password_hash.eq(insert_password_hash),
                ))
                .execute(conn)
        }).await
          .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?
          .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Test finding the existing user
        let obj2 = _pool.get().await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let username_clone1 = username.to_string();
        let found_user_result: Result<User, scribe_backend::auth::AuthError> = obj2.interact(move |conn| {
             get_user_by_username(conn, &username_clone1)
        }).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
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
        let obj3 = _pool.get().await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let not_found_user_result: Result<User, scribe_backend::auth::AuthError> = obj3.interact(|conn| {
            get_user_by_username(conn, "nonexistentuser")
        }).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        assert!(matches!(not_found_user_result, Err(scribe_backend::auth::AuthError::UserNotFound)), "Expected UserNotFound error, got {:?}", not_found_user_result);
        let not_found_user: Option<User> = None;

        assert!(not_found_user.is_none(), "User should not be found");

        Ok(())
    }

    #[tokio::test]
    async fn test_get_user() -> Result<(), Box<dyn std::error::Error>> {
        let _pool = get_test_pool()?;
        // TODO: Implement test
        // 1. Create a user first
        // 2. Call get_user with the correct user ID
        // 3. Assert Ok(Some(user))
        // 4. Call get_user with a random non-existent UUID
        // 5. Assert Ok(None)
        panic!("test_get_user not implemented");
        // Ok(())
    }

    #[tokio::test]
    async fn test_verify_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let _pool = get_test_pool()?;
        // TODO: Implement test
        // 1. Create a user
        // 2. Call verify_credentials with correct username/password
        // 3. Assert Ok(Some(user))
        // 4. Call verify_credentials with correct username/incorrect password
        // 5. Assert Ok(None)
        // 6. Call verify_credentials with incorrect username
        // 7. Assert Ok(None)
        panic!("test_verify_credentials not implemented");
        // Ok(())
    }
} 