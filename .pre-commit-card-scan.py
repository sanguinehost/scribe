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
CARD_PATTERNS = [
    # Credit card numbers (basic patterns)
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'Credit card number pattern'),
    (r'\b\d{13,19}\b', 'Potential card number (13-19 digits)'),

    # Base64 encoded card numbers (only when explicitly near card data keywords)
    (r'(credit.?card|card.?number|cvv.?code).*[A-Za-z0-9+/]{16,24}={0,2}', 'Potential base64 encoded card data'),
    (r'[A-Za-z0-9+/]{16,24}={0,2}.*(credit.?card|card.?number|cvv.?code)', 'Potential base64 encoded card data'),

    # CVV patterns
    (r'\bcvv\s*[:=]\s*\d{3,4}\b', 'CVV code pattern'),
    (r'\bcvc\s*[:=]\s*\d{3,4}\b', 'CVC code pattern'),
    (r'"cvv":\s*"\d{3,4}"', 'JSON CVV pattern'),
    (r'"cvc":\s*"\d{3,4}"', 'JSON CVC pattern'),

    # Expiration date patterns
    (r'\bexp\w*\s*[:=]\s*\d{2}[/\-]\d{2,4}', 'Expiration date pattern'),
    (r'\b\d{2}[/\-]\d{2,4}\s*exp', 'Expiration date pattern'),
    (r'"expiry":\s*"\d{2}[/\-]\d{2,4}"', 'JSON expiry pattern'),
    (r'"exp_month":\s*\d{1,2}', 'JSON expiry month pattern'),
    (r'"exp_year":\s*\d{2,4}', 'JSON expiry year pattern'),

    # Common field names that suggest card data
    (r'card_number|cardNumber|creditCardNumber', 'Card number field'),
    (r'expiry_date|expiryDate|expiration_date', 'Expiry field'),
    (r'"cvv":|"cvc":|cvv_code|cvc_code', 'CVV/CVC field'),
    (r'cardholder_name|cardholderName', 'Cardholder name field'),

    # Environment variables or configuration with card data
    (r'CARD_NUMBER|CREDIT_CARD|CVV_CODE', 'Card data in environment variable'),
    (r'card.*=.*\d{13,19}', 'Card assignment pattern'),

    # URL parameters or query strings with card data
    (r'[?&]card_?number=\d+', 'Card number in URL parameter'),
    (r'[?&]cvv=\d{3,4}', 'CVV in URL parameter'),
    (r'[?&]expiry=\d{2}[/\-]\d{2,4}', 'Expiry in URL parameter'),

    # Log patterns that might leak card data
    (r'card.*\d{13,19}', 'Card data in log-like format'),
    (r'payment.*\d{13,19}', 'Payment data with potential card number'),

    # Form input names
    (r'name=["\']card', 'Card data form input'),
    (r'name=["\']cvv', 'CVV form input'),
    (r'name=["\']exp', 'Expiry form input'),

    # Database column names
    (r'ALTER TABLE.*ADD.*card', 'Card column in database migration'),
    (r'CREATE TABLE.*card_number', 'Card number in table creation'),
]

# Patterns to ignore (legitimate test data or documentation references)
IGNORE_PATTERNS = [
    # Test card numbers (approved for sandbox testing)
    r'4242\s*4242\s*4242\s*4242',  # Common test card number
    r'4000\s*0566\s*5566\s*5556',  # Visa debit test card
    r'4532-1234-5678-9012',  # Privacy detection test card

    # Test and documentation references
    r'test.*card',  # Test card references
    r'example.*card',  # Example references
    r'paddle.*reference',  # Paddle reference patterns
    r'transaction.*id',  # Transaction ID patterns
    r'\.pre-commit-card-scan\.py',  # This script itself
    r'pci-compliance-check\.yml',  # GitHub workflow file

    # Common non-card patterns that look like card numbers
    r'port.*\d{13,19}',  # Port numbers
    r'timestamp.*\d{13,19}',  # Unix timestamps
    r'id.*\d{13,19}',  # Generic IDs
    r'uuid.*\d{13,19}',  # UUIDs with numbers
    r'version.*\d{13,19}',  # Version numbers
    r'migration.*\d{13,19}',  # Migration timestamps

    # Base64 patterns that are not card data
    r'jwt.*[A-Za-z0-9+/]+=*',  # JWT tokens
    r'bearer.*[A-Za-z0-9+/]+=*',  # Bearer tokens
    r'authorization.*[A-Za-z0-9+/]+=*',  # Auth headers
    r'token.*[A-Za-z0-9+/]+=*',  # Generic tokens
    r'secret.*[A-Za-z0-9+/]+=*',  # Encoded secrets (not card data)

    # Legitimate expiry patterns (non-payment)
    r'cache.*exp',  # Cache expiry
    r'session.*exp',  # Session expiry
    r'jwt.*exp',  # JWT expiry

    # Character and UI card patterns (not payment cards)
    r'character.*card',  # Character card references
    r'charactercard',  # Character card types
    r'card.*component',  # UI card components
    r'ui/card',  # UI card imports
    r'CardHeader|CardTitle|CardDescription|CardContent',  # UI card components
    r'ParsedCharacterCard',  # Character card parsing
    r'CharacterCardV[23]',  # Character card versions
    r'LorebookCard|LorebookEntryCard',  # Lorebook UI cards

    # Legitimate payment system architecture (not card data)
    r'payment.*service',  # Payment service classes
    r'payment.*route',  # Payment API routes
    r'credit.*service',  # Credit service classes
    r'credit.*store',  # Credit stores/state management
    r'subscription.*service',  # Subscription services
    r'models::payment',  # Payment models
    r'services::payment',  # Payment services
    r'paddle.*transaction',  # Paddle transaction references
    r'CreditService|CreditBalance|CreditTransaction',  # Credit-related types
    r'payment.*feature',  # Payment feature flags
    r'enable.*payment',  # Payment feature enablement

    # UUID patterns (not card numbers)
    r'00000000-0000-0000-0000-000000000000',  # NULL UUID pattern
    r'uuid.*pattern',  # UUID references
    r'previd.*00000000',  # Migration prev IDs

    # Session/auth expiry (not payment expiry)
    r'session.*expiry|expiry.*session',  # Session expiry
    r'expires.*utc|utc.*expiry',  # UTC timestamp expiry
    r'offset.*expiry|expiry.*offset',  # Offset expiry
    r'auth_tests.*expiry_date',  # Auth test expiry dates
    r'loaded_record.*expiry_date',  # Session record expiry
    r'expiry_date.*time::duration',  # Time duration expiry
    r'offsetdatetime.*expiry_date',  # OffsetDateTime expiry
    r'expiry_date.*offsetdatetime',  # OffsetDateTime expiry
    r'let expiry_date = offsetdatetime',  # Variable declarations
    r'^\s*expiry_date,\s*$',  # Isolated variable name
    r'backend/tests/auth_tests\.rs',  # Specific auth test file

    # Build artifacts and generated files
    r'\.vercel/',  # Vercel build output
    r'\.svelte-kit/',  # SvelteKit build output
    r'immutable/chunks/',  # JS chunks with hashes
    r'version\.json',  # Version files with timestamps
    r'_journal\.json',  # Migration journals
    r'snapshot\.json',  # DB snapshots

    # Privacy examples (legitimate examples for detection testing)
    r'privacy.*examples',  # Privacy detection examples
    r'sensitive_content.*example',  # Example content for testing
    r'4532-1234-5678-9012',  # Specific privacy detection test card
    r'security\.rs.*credit_card',  # Security detection patterns in security.rs
    r'llm/llamacpp/security\.rs',  # LLM security pattern definitions

    # Build and compiled files (timestamped data, not card numbers)
    r'"version":"[0-9]{13}"',  # Version timestamps
    r'when.*[0-9]{13}',  # Migration timestamps
]

def scan_file(file_path):
    """Scan a single file for card data patterns."""
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
        print(f"Warning: Could not read {file_path}: {e}")
        return []

    issues = []
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        line_lower = line.lower()

        # Check if line should be ignored
        ignore = False
        for ignore_pattern in IGNORE_PATTERNS:
            if re.search(ignore_pattern, line_lower, re.IGNORECASE) or re.search(ignore_pattern, file_path_str, re.IGNORECASE):
                ignore = True
                break

        if ignore:
            continue

        # Check for card data patterns
        for pattern, description in CARD_PATTERNS:
            if re.search(pattern, line_lower, re.IGNORECASE):
                issues.append({
                    'file': file_path,
                    'line': i,
                    'pattern': description,
                    'content': line.strip()[:100]  # Truncate long lines
                })

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
