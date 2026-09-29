# Contributing to ISH-CyberGenius-XDR

Thank you for contributing to ISH-CyberGenius-XDR.

The project focuses on defensive XDR investigation, detection, behavioral correlation, ATT&CK mapping, explainable risk analysis, evidence management and security response.

## Before you start

- Read [README.md](README.md) for architecture and setup.
- Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.
- Never commit credentials, API keys, tokens, private keys, customer data or real security telemetry.
- Keep changes focused and explain security-sensitive behavior clearly.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e '.[test]'
Copy-Item .env.example .env
```

## Validation

Run before opening a pull request:

```bash
python -m compileall -q app tests
pytest -q
```

The GitHub Actions workflow validates Python 3.11, 3.12 and 3.13.

## Pull requests

A good pull request should:

- Explain the problem and the security/operational impact.
- Include tests for behavior changes where practical.
- Preserve deterministic and explainable detection/correlation behavior.
- Avoid weakening authentication or response-action safeguards.
- Update documentation when public behavior or configuration changes.
- Keep secrets and sensitive telemetry out of commits and test fixtures.

## Detection and correlation changes

When adding or changing a rule:

1. Give the rule a stable identifier.
2. Document the observable behavior it detects.
3. Add or update tests.
4. Define ATT&CK mappings when applicable.
5. Keep risk scoring explainable.
6. Avoid claiming an event exists unless it is present in the evidence store or returned by an integrated Microsoft API.

## Security-sensitive changes

Changes affecting authentication, Microsoft permissions, Defender response actions, secret handling, persistence or network access require extra review and explicit documentation.

Do not use public issues for undisclosed vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## Code style

Prefer small, readable Python changes with explicit behavior over unnecessary abstraction. Keep APIs and persistence behavior backward-compatible unless the change intentionally introduces a versioned breaking change.
