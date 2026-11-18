# Security Policy

## Vulnerability reports

Please **do not post secrets, personal data, or exploit details** in a public GitHub issue. If enabled, use GitHub's **Security → Report a vulnerability** private reporting form; otherwise contact the repository owner privately.

Include the affected file or endpoint, impact, reproducible steps and a safe minimal proof of concept without real data.

## Particular areas to protect

Student/teacher credentials, class access codes, lesson data and access-control safeguards.

## Secrets and deployments

Keep API credentials, tokens, private keys and local `.env` files out of commits. Store production settings in the deployment provider's secret manager or GitHub Actions secrets. If a key is exposed, immediately revoke and rotate it: simply deleting it in the newest commit leaves historical exposure.

## Dependencies

Review weekly Dependabot pull requests; verify builds and data-source behavior before merging. No automatic major-version upgrades or auto-merge are configured.
