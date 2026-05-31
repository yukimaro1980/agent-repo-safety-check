# Security Policy

## Supported Versions

This project is currently pre-1.0. Security fixes are handled on the `main` branch.

## Reporting a Vulnerability

Please do not open a public issue containing secrets, tokens, private keys, or sensitive logs.

Use GitHub's private vulnerability reporting for sensitive reports when it is available on the repository.

If the private reporting button is not visible yet, open a public GitHub issue that contains only a minimal, non-sensitive description and ask for a private reporting channel. Do not include exploit details, real secrets, private repository paths, customer data, or sensitive logs in a public issue.

## Scope

In scope:

- Secret value disclosure in reports
- Unsafe reading of target files
- Scanner behavior that modifies target projects
- Incorrect documentation that could encourage unsafe use

Out of scope:

- False positives that are clearly labeled as confirmation candidates
- Missing detections for patterns the project does not claim to support yet
