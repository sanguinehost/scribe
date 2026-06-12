import os

replacements = {
    "scribe_core::schema": "crate::schema",
    "scribe_core::{AccountStatus, UserRole, DbBigInt, DbBlob, DbId, DbTimestamp}": "crate::db::{DbId, DbTimestamp};\nuse crate::db::{DbBigInt, DbBlob};\nuse crate::models::{AccountStatus, UserRole}",
    "AppError::DekMissing": "AppError::InternalServerError(\"DEK missing\".to_string())",
    "AppError::BadRequest(": "AppError::InternalServerError(",
    "AppError::DatabaseQueryError(": "AppError::InternalServerError(",
    "CoreError::DatabaseQueryError(": "CoreError::Internal(",
}

for root, _, files in os.walk("crates/scribe-identity/src"):
    for file in files:
        if file.endswith(".rs"):
            filepath = os.path.join(root, file)
            with open(filepath, "r") as f:
                content = f.read()
            
            new_content = content
            for old, new in replacements.items():
                new_content = new_content.replace(old, new)
            
            if new_content != content:
                with open(filepath, "w") as f:
                    f.write(new_content)
                print(f"Updated {filepath}")
