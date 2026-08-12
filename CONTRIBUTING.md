# Contributing to CloudSentinel

First off, thank you for considering contributing to CloudSentinel!

## Development Setup

1. Fork the repository and clone it locally.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
   pip install -r backend/requirements.txt
   pip install pytest ruff bandit pip-audit
   ```

## Adding New Rules

If you're adding a new security rule to `AWSScanner` or `AzureScanner`:
1. Implement the detection logic using the cloud SDKs (`boto3` or `azure-identity`).
2. Add a `mock` representation in `mock/expected_findings.json`.
3. Add a remediation mapping in `backend/engine/remediation.py`.
4. Ensure the finding maps to MITRE or CIS frameworks.
5. Write tests covering your detection logic.

## Quality Gates

Before submitting a Pull Request, you must pass the quality gates:

```bash
# 1. Tests
python -m pytest tests/

# 2. Linting
ruff check .

# 3. Security
bandit -r backend/
pip-audit -r backend/requirements.txt
```

Your PR will be evaluated by GitHub Actions CI. All checks must pass before it can be merged.
