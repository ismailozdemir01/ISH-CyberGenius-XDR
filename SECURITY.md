# Security Policy

## Supported versions

The main branch is the supported version.

## Deployment requirements

- Set a strong random `API_KEY` before starting the application.
- Never commit `.env`, Microsoft client secrets, OAuth tokens, or database files.
- Keep Microsoft Graph and Defender application permissions at the minimum required scope.
- Treat `POST /api/response/isolate` and `POST /api/response/unisolate` as privileged containment operations.
- Put the service behind TLS and an additional network access control layer when exposed outside a trusted host.
- Rotate Microsoft client secrets and API keys if exposure is suspected.

## Reporting a vulnerability

Do not open a public issue for credentials, tokens, private customer data, or an exploitable security vulnerability. Contact the repository owner privately through GitHub and include reproduction details, affected version/commit, and mitigation information where available.

## Secret handling

The repository contains configuration placeholders only. Security review should include Git history and GitHub secret-scanning/push-protection before changing repository visibility.
