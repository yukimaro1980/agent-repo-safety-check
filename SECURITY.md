# Security Policy

## Supported Versions

This project is currently pre-1.0. Security fixes are handled on the `main` branch.

## Reporting a Vulnerability

Please do not open a public issue containing secrets, tokens, private keys, or sensitive logs.

For now, open a GitHub issue with a minimal reproduction that does not include real secrets. If the repository later grows a private reporting channel, this file will be updated.

## Scope

In scope:

- Secret value disclosure in reports
- Unsafe reading of target files
- Scanner behavior that modifies target projects
- Incorrect documentation that could encourage unsafe use

Out of scope:

- False positives that are clearly labeled as confirmation candidates
- Missing detections for patterns the project does not claim to support yet
