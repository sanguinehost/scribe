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

    # CVV patterns
    (r'\bcvv\s*[:=]\s*\d{3,4}\b', 'CVV code pattern'),
    (r'\bcvc\s*[:=]\s*\d{3,4}\b', 'CVC code pattern'),

    # Expiration date patterns
    (r'\bexp\w*\s*[:=]\s*\d{2}[/\-]\d{2,4}', 'Expiration date pattern'),
    (r'\b\d{2}[/\-]\d{2,4}\s*exp', 'Expiration date pattern'),

    # Common field names that suggest card data
    (r'card_number|cardNumber|creditCardNumber', 'Card number field'),
    (r'expiry_date|expiryDate|expiration_date', 'Expiry field'),
    (r'"cvv":|"cvc":|cvv_code|cvc_code', 'CVV/CVC field'),

    # Avoid false positives for test patterns and documentation
]

# Patterns to ignore (legitimate test data or documentation references)
IGNORE_PATTERNS = [
    # Test card numbers (approved for sandbox testing)
    r'4242\s*4242\s*4242\s*4242',  # Common test card number
    r'4000\s*0566\s*5566\s*5556',  # Visa debit test card

    # Test and documentation references
    r'test.*card',  # Test card references
    r'example.*card',  # Example references
    r'paddle.*reference',  # Paddle reference patterns
    r'transaction.*id',  # Transaction ID patterns
    r'\.pre-commit-card-scan\.py',  # This script itself
    r'pci-compliance-check\.yml',  # GitHub workflow file

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