import os

replacements = {
    "CoreError::InternalServerErrorGeneric(": "CoreError::Internal(",
    "scribe_core::error::CoreError": "scribe_core::CoreError",
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
