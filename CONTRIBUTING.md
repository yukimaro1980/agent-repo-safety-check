# Contributing

Thanks for considering a contribution.

This project is a read-only local safety checklist for developers and AI-agent users. Contributions are welcome when they keep that boundary clear.

## Good Contributions

- New checks with clear evidence, risk, check method, and next action text
- Test fixtures that avoid real secrets
- Documentation improvements for non-security-specialist users
- False-positive reductions
- Safer redaction behavior

## Safety Rules

- Do not add checks that print secret values.
- Do not add auto-fix, delete, quarantine, or rewrite behavior.
- Treat findings as confirmation candidates, not proof of compromise.
- Prefer small, explainable heuristics with tests.

## Development

```powershell
python -m unittest
```

Please include tests for new scanner behavior.
