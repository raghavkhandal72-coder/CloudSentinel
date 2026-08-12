# Security Policy

## Supported Versions

Currently, the `main` branch of CloudSentinel is supported with security updates. Older releases are not currently maintained for security patches.

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Instead, please report them via email to `security@example.com` (replace with actual email if deployed). You should receive a response within 48 hours. If the issue is confirmed, a patch will be developed and a security advisory will be published.

## Credential Handling & Cloud Safety

CloudSentinel operates in read-only mode by design. It does not store or transmit your cloud credentials anywhere. All API calls are made directly from your local machine to AWS/Azure endpoints.

**WARNING**: Never commit your `.env` files, AWS Access Keys, Azure Secrets, or `.pem`/`.key` files to version control. The repository includes a `.gitignore` to help prevent this, and CI runs `gitleaks` to detect accidental commits.

If you are using the intentionally vulnerable Terraform lab in `lab/terraform/`, **ONLY** deploy it into an isolated test environment. It intentionally provisions highly insecure configurations (e.g., public S3 buckets, open SSH).

## Responsible Disclosure

If you find a vulnerability, we ask that you follow responsible disclosure principles:
- Give us a reasonable amount of time to fix the issue before publishing it.
- Do not exploit the vulnerability beyond what is necessary to prove its existence.
- Do not degrade the performance of the tool or destroy data during your research.
