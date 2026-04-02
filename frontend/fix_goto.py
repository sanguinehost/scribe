import os
import re

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # If goto( is not in the file, skip
    # (except for edge cases where goto is renamed to _goto, but let's check both)
    if 'goto(' not in content and '_goto(' not in content:
        return

    # Check if 'resolve' is already imported from '$app/paths'
    has_resolve_import = re.search(r"import\s+\{.*resolve.*\}\s+from\s+['\"]\$app/paths['\"]", content)

    # We want to replace goto('...') with goto(resolve('...'))
    # Sometime it's _goto.
    # We must ensure we don't replace if it's already goto(resolve(...))

    # regex to find goto(...) where the inside does NOT start with 'resolve('
    # we need to capture the inner content and if it doesn't start with resolve(, we wrap it.

    new_content = re.sub(r'(\b_?goto\()\s*(?!resolve\()([^\)]+)\)', r'\1resolve(\2))', content)

    if new_content == content:
        return # no modification made

    print(f"Modifying {filepath}")

    # Now, add import { resolve } from '$app/paths';
    # to the script block if there is a script block, and it's not imported yet.
    if not has_resolve_import:
        # Find the script block. we might have <script> or <script lang="ts">

        script_pattern = r'(<script[^>]*>)'
        match = re.search(script_pattern, new_content)
        if match:
            # check if $app/paths is already imported
            paths_import = re.search(r"import\s+\{([^\}]+)\}\s+from\s+['\"]\$app/paths['\"]", new_content)
            if paths_import:
                # Add resolve to the existing import
                existing_imports = paths_import.group(1)
                new_imports = existing_imports.strip() + ', resolve'
                def replace_paths_import(m):
                    return f"import {{ {new_imports} }} from '$app/paths'"
                new_content = re.sub(r"import\s+\{[^\}]+\}\s+from\s+['\"]\$app/paths['\"]", replace_paths_import, new_content)
            else:
                # Just insert the new import after <script ...>
                script_tag = match.group(1)
                new_content = new_content.replace(script_tag, script_tag + "\n\timport { resolve } from '$app/paths';")
        else:
            # wait, if it's a .ts file, there is no <script> tag.
            if filepath.endswith('.ts') or filepath.endswith('.js'):
                paths_import = re.search(r"import\s+\{([^\}]+)\}\s+from\s+['\"]\$app/paths['\"]", new_content)
                if paths_import:
                    existing_imports = paths_import.group(1)
                    new_imports = existing_imports.strip() + ', resolve'
                    def replace_paths_import(m):
                        return f"import {{ {new_imports} }} from '$app/paths'"
                    new_content = re.sub(r"import\s+\{[^\}]+\}\s+from\s+['\"]\$app/paths['\"]", replace_paths_import, new_content)
                else:
                    new_content = "import { resolve } from '$app/paths';\n" + new_content

    with open(filepath, 'w') as f:
        f.write(new_content)

for root, _, files in os.walk('src'):
    for f in files:
        if f.endswith('.svelte') or f.endswith('.ts') or f.endswith('.js'):
            process_file(os.path.join(root, f))
