# Documentation Index

Complete technical documentation for the Enterprise SOC SOAR Pipeline audit.

| # | Document | Contents |
|---|---|---|
| 01 | [Project overview](01-project-overview.md) | Objectives, problem statement, solution, scope, metrics, terminology |
| 02 | [System architecture](02-architecture.md) | Context, deployment, stages, fan-out/fan-in, execution modes, error architecture |
| 03 | [Node-by-node reference](03-node-reference.md) | All 31 nodes and all 36 connections, parameters and audit notes |
| 04 | [Code audit](04-code-audit.md) | Line-by-line review of all 13 Code nodes, syntax results, defect register |
| 05 | [Data flow and execution](05-data-flow.md) | Item shapes, seven execution paths, race and retention analysis |
| 06 | [Wazuh integration](06-wazuh-integration.md) | Alert structure, field mapping, webhook contract, hardening checklist |
| 07 | [IOC and threat intelligence](07-ioc-and-threat-intelligence.md) | Extraction, routing, six providers, aggregation, failure matrix |
| 08 | [Correlation and severity](08-correlation-and-severity.md) | Four scoring systems, verdicts, worked scenarios, IRIS mapping |
| 09 | [Hermes AI and HMAC status](09-hermes-ai-integration.md) | Search evidence, Laya client contract, HMAC not found, proposed design |
| 10 | [Notifications and response](10-notifications-and-response.md) | IRIS, Discord, Telegram, Slack, FortiGate, response matrix |
| 11 | [Installation](11-installation.md) | Import, credentials, environment, Wazuh setup, activation checklist |
| 12 | [Testing and validation](12-testing-and-validation.md) | Validation layers, executed results, proposed runtime tests, CI |
| 13 | [Troubleshooting](13-troubleshooting.md) | Symptom/cause/action tables for every subsystem |
| 14 | [Security](14-security.md) | Threat model, secret rotation, ingress, injection, TLS, retention |
| 15 | [Limitations and roadmap](15-limitations-and-roadmap.md) | Audit limits, functional limits, unverified behaviour, P0–P3 roadmap |
| 16 | [Audit report](16-audit-report.md) | Executive summary, 27 findings, verification log, attestation |

Additional artefacts:

- [Sanitisation report](sanitization-report.json) — 0 surviving secrets, 0 findings
- [Diagram sources](diagrams/) — Mermaid `.mmd` files
- [Asset notes](assets/README.md) — why no screenshots are included

Start with [01 — Project overview](01-project-overview.md), then
[16 — Audit report](16-audit-report.md) for the findings.
