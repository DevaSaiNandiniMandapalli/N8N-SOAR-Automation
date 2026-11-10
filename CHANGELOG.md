# Changelog

## 1.0.0 — 2026-11-10

### Added

- Static audit of the exported Enterprise SOC SOAR Pipeline
  (`ORQ4n82CacFdx45s`): 31 nodes, 36 connections, 13 Code nodes.
- Sanitized, importable workflow with all credentials, webhook URLs, chat IDs,
  infrastructure addresses and instance metadata removed.
- 16 technical documents, including architecture, node reference, code audit,
  data flow, integrations, installation, testing, troubleshooting and security.
- Mermaid diagrams for context, pipeline, sequence and data model.
- Synthetic Wazuh alert and n8n webhook fixtures.
- `sanitize_workflow.py`, `validate_workflow.py`, `secret_scan.py`.
- Unit tests and GitHub Actions validation workflow.
- Findings register with severity, evidence and remediation guidance.

### Security

- Replaced 8 hard-coded credentials, 1 Discord webhook URL, 1 Telegram chat ID,
  3 infrastructure addresses and 3 instance identifiers.
- Sanitizer verification: 0 surviving original secrets, 0 unredacted
  secret-pattern findings.
- Added rotation guidance for all previously embedded credentials.

### Known limitations

- No live workflow execution was performed. Findings are based on static analysis
  of the export and read-only service metadata.
- The Hermes/Laya HMAC-SHA256 implementation was not present in the export or on
  the audited local system and is therefore not documented as implemented.
- No authenticated n8n screenshots were available.
