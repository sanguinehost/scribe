#!/usr/bin/env python3
"""
Pre-commit hook to scan for potential credit card data patterns.
Helps maintain SAQ-A compliance by preventing cardholder data from being committed.

Usage:
    Add to .pre-commit-config.yaml:
    - repo: local
      hooks:
        - id: card-data-scan
          name: Scan for credit card data
          entry: python .pre-commit-card-scan.py
          language: system
          types: [text]
          exclude: ^(.pre-commit-card-scan.py|docs/PAYMENT_COMPLIANCE.md)$
"""

import re
import sys
import argparse
from pathlib import Path

# Patterns that might indicate cardholder data (PCI DSS scope)
# Pre-compiled for Python 3.13 compatibility
CARD_PATTERNS = [
    # Credit card numbers (basic patterns)
    (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', re.IGNORECASE), 'Credit card number pattern'),
    (re.compile(r'\b\d{13,19}\b', re.IGNORECASE), 'Potential card number (13-19 digits)'),

    # Base64 encoded card numbers (only when explicitly near card data keywords)
    (re.compile(r'(credit.?card|card.?number|cvv.?code).*[A-Za-z0-9+/]{16,24}={0,2}', re.IGNORECASE), 'Potential base64 encoded card data'),
    (re.compile(r'[A-Za-z0-9+/]{16,24}={0,2}.*(credit.?card|card.?number|cvv.?code)', re.IGNORECASE), 'Potential base64 encoded card data'),

    # CVV patterns
    (re.compile(r'\bcvv\s*[:=]\s*\d{3,4}\b', re.IGNORECASE), 'CVV code pattern'),
    (re.compile(r'\bcvc\s*[:=]\s*\d{3,4}\b', re.IGNORECASE), 'CVC code pattern'),
    (re.compile(r'"cvv":\s*"\d{3,4}"', re.IGNORECASE), 'JSON CVV pattern'),
    (re.compile(r'"cvc":\s*"\d{3,4}"', re.IGNORECASE), 'JSON CVC pattern'),

    # Expiration date patterns
    (re.compile(r'\bexp\w*\s*[:=]\s*\d{2}[/\-]\d{2,4}', re.IGNORECASE), 'Expiration date pattern'),
    (re.compile(r'\b\d{2}[/\-]\d{2,4}\s*exp', re.IGNORECASE), 'Expiration date pattern'),
    (re.compile(r'"expiry":\s*"\d{2}[/\-]\d{2,4}"', re.IGNORECASE), 'JSON expiry pattern'),
    (re.compile(r'"exp_month":\s*\d{1,2}', re.IGNORECASE), 'JSON expiry month pattern'),
    (re.compile(r'"exp_year":\s*\d{2,4}', re.IGNORECASE), 'JSON expiry year pattern'),

    # Common field names that suggest card data
    (re.compile(r'card_number|cardNumber|creditCardNumber', re.IGNORECASE), 'Card number field'),
    (re.compile(r'expiry_date|expiryDate|expiration_date', re.IGNORECASE), 'Expiry field'),
    (re.compile(r'"cvv":|"cvc":|cvv_code|cvc_code', re.IGNORECASE), 'CVV/CVC field'),
    (re.compile(r'cardholder_name|cardholderName', re.IGNORECASE), 'Cardholder name field'),

    # Environment variables or configuration with card data
    (re.compile(r'CARD_NUMBER|CREDIT_CARD|CVV_CODE', re.IGNORECASE), 'Card data in environment variable'),
    (re.compile(r'card.*=.*\d{13,19}', re.IGNORECASE), 'Card assignment pattern'),

    # URL parameters or query strings with card data
    (re.compile(r'[?&]card_?number=\d+', re.IGNORECASE), 'Card number in URL parameter'),
    (re.compile(r'[?&]cvv=\d{3,4}', re.IGNORECASE), 'CVV in URL parameter'),
    (re.compile(r'[?&]expiry=\d{2}[/\-]\d{2,4}', re.IGNORECASE), 'Expiry in URL parameter'),

    # Log patterns that might leak card data
    (re.compile(r'card.*\d{13,19}', re.IGNORECASE), 'Card data in log-like format'),
    (re.compile(r'payment.*\d{13,19}', re.IGNORECASE), 'Payment data with potential card number'),

    # Form input names
    (re.compile(r'name=["\']card', re.IGNORECASE), 'Card data form input'),
    (re.compile(r'name=["\']cvv', re.IGNORECASE), 'CVV form input'),
    (re.compile(r'name=["\']exp', re.IGNORECASE), 'Expiry form input'),

    # Database column names
    (re.compile(r'ALTER TABLE.*ADD.*card', re.IGNORECASE), 'Card column in database migration'),
    (re.compile(r'CREATE TABLE.*card_number', re.IGNORECASE), 'Card number in table creation'),
]

# Patterns to ignore (legitimate test data or documentation references)
# Pre-compiled for Python 3.13 compatibility
IGNORE_PATTERNS = [
    # Test card numbers (approved for sandbox testing)
    re.compile(r'4242\s*4242\s*4242\s*4242', re.IGNORECASE),
    re.compile(r'4000\s*0566\s*5566\s*5556', re.IGNORECASE),
    re.compile(r'4532-1234-5678-9012', re.IGNORECASE),

    # Test and documentation references
    re.compile(r'test.*card', re.IGNORECASE),
    re.compile(r'example.*card', re.IGNORECASE),
    re.compile(r'paddle.*reference', re.IGNORECASE),
    re.compile(r'transaction.*id', re.IGNORECASE),
    re.compile(r'\.pre-commit-card-scan\.py', re.IGNORECASE),
    re.compile(r'pci-compliance-check\.yml', re.IGNORECASE),

    # Common non-card patterns that look like card numbers
    re.compile(r'port.*\d{13,19}', re.IGNORECASE),
    re.compile(r'timestamp.*\d{13,19}', re.IGNORECASE),
    re.compile(r'id.*\d{13,19}', re.IGNORECASE),
    re.compile(r'uuid.*\d{13,19}', re.IGNORECASE),
    re.compile(r'version.*\d{13,19}', re.IGNORECASE),
    re.compile(r'migration.*\d{13,19}', re.IGNORECASE),

    # Base64 patterns that are not card data
    re.compile(r'jwt.*[A-Za-z0-9+/]+=*', re.IGNORECASE),
    re.compile(r'bearer.*[A-Za-z0-9+/]+=*', re.IGNORECASE),
    re.compile(r'authorization.*[A-Za-z0-9+/]+=*', re.IGNORECASE),
    re.compile(r'token.*[A-Za-z0-9+/]+=*', re.IGNORECASE),
    re.compile(r'secret.*[A-Za-z0-9+/]+=*', re.IGNORECASE),

    # Legitimate expiry patterns (non-payment)
    re.compile(r'cache.*exp', re.IGNORECASE),
    re.compile(r'session.*exp', re.IGNORECASE),
    re.compile(r'jwt.*exp', re.IGNORECASE),

    # Character and UI card patterns (not payment cards)
    re.compile(r'character.*card', re.IGNORECASE),
    re.compile(r'charactercard', re.IGNORECASE),
    re.compile(r'card.*component', re.IGNORECASE),
    re.compile(r'ui/card', re.IGNORECASE),
    re.compile(r'CardHeader|CardTitle|CardDescription|CardContent', re.IGNORECASE),
    re.compile(r'ParsedCharacterCard', re.IGNORECASE),
    re.compile(r'CharacterCardV[23]', re.IGNORECASE),
    re.compile(r'LorebookCard|LorebookEntryCard', re.IGNORECASE),

    # Legitimate payment system architecture (not card data)
    re.compile(r'payment.*service', re.IGNORECASE),
    re.compile(r'payment.*route', re.IGNORECASE),
    re.compile(r'credit.*service', re.IGNORECASE),
    re.compile(r'credit.*store', re.IGNORECASE),
    re.compile(r'subscription.*service', re.IGNORECASE),
    re.compile(r'models::payment', re.IGNORECASE),
    re.compile(r'services::payment', re.IGNORECASE),
    re.compile(r'paddle.*transaction', re.IGNORECASE),
    re.compile(r'CreditService|CreditBalance|CreditTransaction', re.IGNORECASE),
    re.compile(r'payment.*feature', re.IGNORECASE),
    re.compile(r'enable.*payment', re.IGNORECASE),

    # UUID patterns (not card numbers)
    re.compile(r'00000000-0000-0000-0000-000000000000', re.IGNORECASE),
    re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE),
    re.compile(r'"user_id":\s*"[0-9a-f]{8}-[0-9a-f]{4}', re.IGNORECASE),
    re.compile(r'user_id.*00000000-0000-0000-0000', re.IGNORECASE),
    re.compile(r'uuid.*pattern', re.IGNORECASE),
    re.compile(r'previd.*00000000', re.IGNORECASE),
    re.compile(r'payment_webhook_idempotency_tests\.rs', re.IGNORECASE),

    # Session/auth expiry (not payment expiry)
    re.compile(r'session.*expiry|expiry.*session', re.IGNORECASE),
    re.compile(r'expires.*utc|utc.*expiry', re.IGNORECASE),
    re.compile(r'offset.*expiry|expiry.*offset', re.IGNORECASE),
    re.compile(r'auth_tests.*expiry_date', re.IGNORECASE),
    re.compile(r'loaded_record.*expiry_date', re.IGNORECASE),
    re.compile(r'expiry_date.*time::duration', re.IGNORECASE),
    re.compile(r'offsetdatetime.*expiry_date', re.IGNORECASE),
    re.compile(r'expiry_date.*offsetdatetime', re.IGNORECASE),
    re.compile(r'let expiry_date = offsetdatetime', re.IGNORECASE),
    re.compile(r'^\s*expiry_date,\s*$', re.IGNORECASE),
    re.compile(r'backend/tests/auth_tests\.rs', re.IGNORECASE),

    # Build artifacts and generated files
    re.compile(r'\.vercel/', re.IGNORECASE),
    re.compile(r'\.svelte-kit/', re.IGNORECASE),
    re.compile(r'immutable/chunks/', re.IGNORECASE),
    re.compile(r'version\.json', re.IGNORECASE),
    re.compile(r'_journal\.json', re.IGNORECASE),
    re.compile(r'snapshot\.json', re.IGNORECASE),

    # Privacy examples (legitimate examples for detection testing)
    re.compile(r'privacy.*examples', re.IGNORECASE),
    re.compile(r'sensitive_content.*example', re.IGNORECASE),
    re.compile(r'4532-1234-5678-9012', re.IGNORECASE),
    re.compile(r'security\.rs.*credit_card', re.IGNORECASE),
    re.compile(r'llm/llamacpp/security\.rs', re.IGNORECASE),

    # Encryption test files (legitimate test data for encryption verification)
    re.compile(r'backend/tests/credit_encryption_tests\.rs', re.IGNORECASE),
    re.compile(r'backend/tests/payment_encryption_tests\.rs', re.IGNORECASE),
    re.compile(r'backend/tests/payment_security_tests\.rs', re.IGNORECASE),
    re.compile(r'encryption_tests.*4111', re.IGNORECASE),
    re.compile(r'sensitive_description.*4111', re.IGNORECASE),

    # Build and compiled files (timestamped data, not card numbers)
    re.compile(r'"version":"[0-9]{13}"', re.IGNORECASE),
    re.compile(r'when.*[0-9]{13}', re.IGNORECASE),

    # Unix timestamps (milliseconds since epoch)
    re.compile(r'timestamp.*\d{13}', re.IGNORECASE),
    re.compile(r'expires_at.*\d{13}', re.IGNORECASE),
    re.compile(r'expiresAt.*\d{13}', re.IGNORECASE),
    re.compile(r'\d{13}.*//.*timestamp', re.IGNORECASE),
    re.compile(r'\d{13}.*milliseconds', re.IGNORECASE),
    re.compile(r'desktop/src/storage\.rs', re.IGNORECASE),
]

def scan_file(file_path_in):
    """Scan a single file for card data patterns."""
    # Ensure file_path is a Path object and convert to string
    file_path = Path(file_path_in) if not isinstance(file_path_in, Path) else file_path_in
    file_path_str = str(file_path)

    # Skip files by path patterns
    skip_paths = [
        '.vercel/',
        '.svelte-kit/',
        'node_modules/',
        'target/',
        '.git/',
        'immutable/chunks/',
    ]

    if any(skip in file_path_str for skip in skip_paths):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Warning: Could not read {file_path_str}: {e}")
        return []

    issues = []
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        # Ensure line is a string
        try:
            line = str(line) if not isinstance(line, str) else line
            line_lower = line.lower()
        except Exception as e:
            print(f"Warning: Could not process line {i} in {file_path_str}: {e} (type: {type(line)})")
            continue

        # Check if line should be ignored
        ignore = False
        for pattern_idx, ignore_pattern in enumerate(IGNORE_PATTERNS):
            try:
                if ignore_pattern.search(line_lower) or ignore_pattern.search(file_path_str):
                    ignore = True
                    break
            except TypeError as e:
                print(f"Warning: TypeError in ignore pattern #{pattern_idx} for {file_path_str}:{i} - {e}")
                print(f"  Pattern type: {type(ignore_pattern)}, pattern: {repr(ignore_pattern)[:100]}")
                print(f"  line_lower type: {type(line_lower)}, value: {repr(line_lower)[:100]}")
                print(f"  file_path_str type: {type(file_path_str)}, value: {repr(file_path_str)[:100]}")
                continue

        if ignore:
            continue

        # Check for card data patterns
        for pattern, description in CARD_PATTERNS:
            try:
                if pattern.search(line_lower):
                    issues.append({
                        'file': file_path_str,  # Use string instead of Path object
                        'line': i,
                        'pattern': description,
                        'content': line.strip()[:100]  # Truncate long lines
                    })
            except TypeError as e:
                print(f"Warning: TypeError in card pattern for {file_path_str}:{i} - {e}")
                print(f"  line_lower type: {type(line_lower)}, value: {repr(line_lower)[:100]}")
                continue

    return issues

def main():
    parser = argparse.ArgumentParser(description='Scan for credit card data patterns')
    parser.add_argument('files', nargs='*', help='Files to scan')
    parser.add_argument('--all', action='store_true', help='Scan all text files in repository')
    args = parser.parse_args()

    files_to_scan = []

    if args.all:
        # Scan all text files in repository
        repo_root = Path('.')
        files_to_scan = [
            f for f in repo_root.rglob('*')
            if f.is_file() and f.suffix in ['.rs', '.py', '.js', '.ts', '.tsx', '.svelte', '.json', '.md', '.txt', '.yml', '.yaml']
            and not any(exclude in str(f) for exclude in ['.git/', 'target/', 'node_modules/', '.cargo/'])
        ]
    else:
        files_to_scan = [Path(f) for f in args.files if Path(f).exists()]

    all_issues = []

    for file_path in files_to_scan:
        issues = scan_file(file_path)
        all_issues.extend(issues)

    if all_issues:
        print("🚨 POTENTIAL CARDHOLDER DATA DETECTED!")
        print("⚠️  This may violate SAQ-A compliance requirements.")
        print("📋 The following patterns were found:")
        print()

        for issue in all_issues:
            print(f"File: {issue['file']}")
            print(f"Line: {issue['line']}")
            print(f"Pattern: {issue['pattern']}")
            print(f"Content: {issue['content']}")
            print("-" * 50)

        print()
        print("🛡️  SAQ-A Compliance Reminder:")
        print("   - Never store, process, or transmit cardholder data")
        print("   - Use only Paddle transaction/customer/subscription IDs")
        print("   - All payment data should be handled by Paddle")
        print()
        print("✅ If these are legitimate test references or documentation:")
        print("   - Ensure they're clearly marked as examples")
        print("   - Use placeholder patterns like 'xxxx-xxxx-xxxx-xxxx'")
        print("   - Consider adding to ignore patterns in this script")

        return 1
    else:
        print("✅ No cardholder data patterns detected - SAQ-A compliance maintained.")
        if not args.files:
            print(f"   Scanned {len(files_to_scan)} files in repository.")
        return 0

if __name__ == '__main__':
    sys.exit(main())
