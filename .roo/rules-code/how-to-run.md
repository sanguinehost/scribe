---
description: 
globs: 
alwaysApply: true
---
To run this app we:
`cargo run -p scribe-backend`

Followed (optionally) by:
`cargo run -p scribe-cli` for CLI interactivity 

For tests we run:
`cargo test`

And for a full test run (including integration/external tests):
`cargo tarpaulin --all-targets --exclude-files "*/main.rs" --out html -- --include-ignored`