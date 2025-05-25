# Account Locking Functionality

This document describes the account locking functionality implemented in Sanguine Scribe.

## Overview

The account locking feature allows administrators to lock user accounts, preventing them from logging in. This is useful for:
- Temporarily disabling accounts for security concerns
- Handling accounts that violate terms of service
- Implementing administrative controls for user management

## Implementation

The feature has been implemented in both the backend and CLI client:

### Backend Implementation

1. Database Schema
   - The `users` table includes an `account_status` column with an enum type (`active` or `locked`)
   - Default status for new accounts is `active`

2. Authentication Flow
   - In `auth/mod.rs`, the `verify_credentials` function checks the account status
   - If the account is locked, it returns a new `AuthError::AccountLocked` variant
   - The error is properly mapped to an appropriate HTTP response in `routes/auth.rs`

3. Admin API
   - Two endpoints have been added for locking and unlocking user accounts:
     - `PUT /api/admin/users/{id}/lock` for locking accounts
     - `PUT /api/admin/users/{id}/unlock` for unlocking accounts
   - These endpoints are restricted to users with the Administrator role

### CLI Implementation

1. Client Interface
   - The client checks for locked accounts during login
   - It displays an appropriate error message: "Your account is locked. Please contact an administrator."

2. Admin Commands
   - Administrators can lock and unlock accounts via the CLI interface
   - The lock/unlock functionality is available through the admin menu option 4

## Usage

### For Administrators

1. Locking an Account
   - Log in as an administrator
   - Select option 4 from the admin menu
   - Enter the user ID or username of the account to lock
   - Select option 1 to lock the account

2. Unlocking an Account
   - Log in as an administrator
   - Select option 4 from the admin menu
   - Enter the user ID or username of the account to unlock
   - Select option 2 to unlock the account

## Error Handling

The system provides appropriate error messages:
- When an administrator attempts to manage accounts: success or failure messages for locking/unlocking
- When a locked user attempts to log in: "Your account is locked. Please contact an administrator."