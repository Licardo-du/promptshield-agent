# Contributing

Thanks for considering a contribution to PromptShield.

## Development Setup

Use Python 3.10 or newer.

```bash
python -m unittest
python -m promptshield scan examples/vulnerable_agent
python -m promptshield ui --smoke-test
```

## Pull Request Guidelines

- Keep changes focused and small.
- Add or update tests for rule or CLI behavior changes.
- Do not commit `.env`, API keys, generated reports, cache folders, or local virtual environments.
- Keep security findings deterministic where possible so demos and tests remain stable.

## Adding Detection Rules

Detection rules live in `promptshield/rules.py`.

When adding a rule:

- Give it a stable `PSH` rule ID.
- Set a clear severity and category.
- Include a remediation message.
- Add or update tests under `tests/`.

