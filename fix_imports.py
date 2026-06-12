import os

replacements = {
    "scribe_core::AppError": "crate::error::AppError",
    "scribe_core::CoreError": "scribe_core::error::CoreError",
    "scribe_core::EmailService": "crate::email::EmailService",
    "scribe_core::privacy::loggable_user_id": "crate::privacy::loggable_user_id",
    "scribe_core::loggable_user_id": "crate::privacy::loggable_user_id",
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
