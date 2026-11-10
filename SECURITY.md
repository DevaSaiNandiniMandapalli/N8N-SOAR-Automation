# Security Policy

## Supported scope

This repository contains a sanitized n8n workflow and documentation. It does not
contain production credentials, customer data or the raw workflow export.

## Reporting a vulnerability

Do not open a public issue for a suspected secret leak or security defect.

Contact the maintainer privately:

- GitHub: [@DevaSaiNandiniMandapalli](https://github.com/DevaSaiNandiniMandapalli)

Include the affected file, the commit ID, a description and, if possible, a
redacted reproduction. Never include a live credential in the report.

## Credential exposure

The original export contained eight hard-coded credentials, a Discord webhook URL
and a Telegram chat ID. They were replaced with placeholders before the first
commit. **Sanitization does not revoke a credential.**

If you believe a credential was exposed:

1. Revoke or rotate it at the provider immediately.
2. Review provider audit logs for unauthorised use.
3. Check n8n execution history and reverse-proxy logs for unexpected calls.
4. Remove the value from every copy: exports, backups, screenshots, chat logs and
   tickets. Git history rewriting is required only if a secret was actually committed.
5. Record the rotation date and the affected integration.

## Secrets in this repository

- `.env` files are ignored.
- Real credentials must be stored in n8n credentials or a secrets manager.
- The sanitized workflow uses `REPLACE_WITH_*` placeholders.
- `scripts/secret_scan.py` and the CI workflow scan for credential patterns.

## Deployment hardening

See [`docs/14-security.md`](docs/14-security.md). Minimum requirements:

- Terminate n8n behind HTTPS.
- Authenticate the Wazuh webhook and restrict it by source IP.
- Replace inline headers with n8n credentials.
- Do not disable TLS verification for FortiGate or IRIS.
- Restrict access to the n8n editor and the Laya console.
- Enable execution-data pruning.
- Treat Wazuh payloads as sensitive: they can contain usernames, commands, file
  paths, IP addresses and hostnames.
