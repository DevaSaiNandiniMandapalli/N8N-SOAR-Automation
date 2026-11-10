# 01 — Project Overview

| Item | Value |
|---|---|
| Project | AI SOC Copilot — Enterprise SOC SOAR Pipeline |
| Document | Project overview and audit scope |
| Version | 1.0 |
| Date | 2026-11-10 |
| Workflow | `Enterprise SOC SOAR Pipeline` |
| Workflow ID (raw export) | `ORQ4n82CacFdx45s` |
| Audit method | Static analysis of the exported workflow, plus read-only service metadata checks |
| Live execution performed | No |
| Live workflow modified | No |
| Repository visibility | Private |

---

## 1. Executive summary

The AI SOC Copilot is an n8n workflow that receives Wazuh security alerts, extracts
indicators of compromise (IOCs), enriches them with six threat-intelligence providers,
correlates the evidence, produces an analyst-facing incident report, asks a locally
hosted decision engine called **Laya** for an authoritative verdict, and then routes
escalated incidents to DFIR-IRIS, Discord, Telegram and Slack. A final conditional path
is intended to create a FortiGate address object for public source IPs.

The exported workflow contains **31 nodes and 36 connections**. Thirteen of those nodes
are JavaScript Code nodes totalling approximately **2,960 lines**. The workflow is
ambitious and covers a realistic SOC triage lifecycle: ingestion, normalisation,
deduplication, IOC classification, provider fan-out, evidence aggregation, branch-specific
incident assembly, correlation, severity derivation, report generation, a decision gate,
and multi-channel response.

The static audit found that the design is stronger than its implementation in several
important places. The most serious issues are:

1. **Thirteen tracked values were embedded directly in the workflow export**: six
   threat-intelligence API keys, two bearer tokens, a Discord webhook URL, a Telegram
   chat ID and three workflow-level identifiers. Private/public infrastructure addresses,
   credential IDs and `webhookId` values were also present. The sanitized repository
   removes or replaces all of them, but the originals must still be rotated.
2. **The Laya decision call is implemented inside a Code node.** n8n's Code node
   documentation states that Code nodes cannot make HTTP requests. The call therefore
   depends on an unsupported runtime capability and, when it fails, the fail-safe
   escalates every alert at rule level 8 or above. The authoritative decision engine is
   effectively not integrated in a supported way.
3. **The Final Report node contains a `ReferenceError` path.** Its IRIS source reference
   uses an undefined variable `d` when the source IP is falsy, which aborts report
   generation for those alerts.
4. **The webhook is unauthenticated and has no rate limit.** Anyone who can reach the
   n8n webhook can inject alerts, consume paid threat-intelligence quota, create
   notifications and potentially create FortiGate address objects.

Eight high-severity findings cover incomplete containment, dead-end branches, three
competing severity calculations, unreliable deduplication, ThreatFox error handling,
broken hash enrichment, non-monotonic IRIS severity mapping, and retention/error-handling
gaps. Nine medium and six low findings cover extraction coverage, provider parsing,
message formatting, trust assumptions and maintainability.

The workflow is a solid prototype and a useful blueprint. It is not yet a production-grade
SOAR platform. The documentation deliberately separates **observed behaviour** from
**intended behaviour**, and it does not describe Hermes or HMAC-SHA256 as implemented
because neither was found in the export or on the audited system.

---

## 2. Problem statement

A Wazuh deployment can generate thousands of alerts per day. Analysts must answer four
questions for each alert:

1. Is the source or artifact actually malicious?
2. Does the evidence corroborate across independent sources?
3. How severe is the incident, and does it require containment?
4. Which systems and humans need to know, and with what context?

Doing this manually creates predictable problems:

- **Alert fatigue.** Low-value telemetry competes with genuine threats.
- **Inconsistent enrichment.** Different analysts query different providers and interpret
  results differently.
- **Quota waste.** Paid APIs are called for private IPs, duplicate alerts and benign
  telemetry.
- **Slow containment.** The time between detection and a firewall decision is dominated
  by manual lookups and ticket creation.
- **Weak auditability.** Decisions are recorded in chat messages rather than a structured
  case record.

The pipeline addresses these problems by automating the repeatable parts and keeping a
human decision gate at the end.

---

## 3. Proposed solution

The workflow implements a linear pipeline with two analysis branches and a response
fan-out:

```text
Wazuh webhook
  → field normalisation
  → IOC extraction
  → 3-minute deduplication
  → routing gate (external TI vs internal host analysis)
      ├─ external: six TI providers → merge → aggregate → normalise → incident
      └─ internal: host/user/command/MITRE analysis → incident
  → merge branches
  → corroboration and verdict
  → incident summary
  → severity derivation
  → analyst report + IRIS payload
  → Laya decision gate
      ├─ not escalated: stop
      └─ escalated: IRIS → Discord, Telegram, Slack
                      └─ HIGH/CRITICAL → public IP? → FortiGate address object
```

### Design goals inferred from the implementation

| Goal | Implementation intent | Status |
|---|---|---|
| Reduce duplicate work | 3-minute static-data dedup with high-volume fingerprints | Partial |
| Avoid wasting TI quota | Skip providers for private/local events | Implemented, with gaps |
| Corroborate threats | Six independent providers, risk weights, source counts | Implemented, with parsing bugs |
| Separate external and internal analysis | IF gate and branch-specific incident builders | Implemented |
| Produce analyst-ready context | Structured report with scene, evidence and recommendation | Implemented, one crash path |
| Keep a human/authoritative gate | Laya decision client with fail-safe escalation | Unsupported HTTP call |
| Record decisions | IRIS alert plus Discord/Telegram/Slack messages | Implemented, incomplete |
| Contain threats | FortiGate address object creation | Incomplete, not a block |

---

## 4. Scope of the audit

### In scope

- All 31 nodes and 36 connections in the exported workflow.
- All 13 Code nodes, reviewed line by line (approximately 2,960 lines).
- Every non-code node parameter, expression, header, body and condition.
- The external and internal analysis branches, including unconnected outputs.
- Threat-intelligence request construction, response parsing and scoring.
- Deduplication, IOC extraction, aggregation and normalisation.
- Correlation, severity derivation, report generation and IRIS payload mapping.
- Notification and containment integrations.
- Secret handling and sanitisation.
- Structural validation and syntax checks of the exported code.

### Out of scope

- Executing the live workflow or sending test alerts to the production webhook.
- Reading the authenticated n8n editor or execution history.
- The source code of the Laya/Hermes engine. It was not available on the audited system.
- The FortiGate firewall policy, which is not part of the export.
- DFIR-IRIS server configuration and case lifecycle.
- Wazuh manager configuration beyond the expected alert contract.
- Performance and load testing.
- Screenshots of authenticated interfaces.

### Evidence sources

| Evidence | Location | Use |
|---|---|---|
| Raw n8n export | `Enterprise SOC SOAR Pipeline.json` (not published) | Authoritative node and connection data |
| Sanitized export | `workflows/enterprise-soc-soar-pipeline.sanitized.json` | Publishable workflow |
| Code extracts | Audit workspace, 13 `.js` files | Line-level review and syntax checks |
| Non-code node dump | Audit workspace, secrets masked | Parameter review |
| Sanitisation report | `docs/sanitization-report.json` | Secret-removal verification |
| Laya health/stats | Read-only `GET /api/health`, `GET /api/stats` | Engine identity and availability only |
| n8n documentation | Official Code and Merge node docs | Runtime capability constraints |

The raw export was never copied into this repository.

---

## 5. What the workflow actually does

### 5.1 Ingestion and normalisation

The webhook accepts `POST /wazuh-alerts`. The **Edit Fields** node maps seven fields from
the Wazuh payload, with fallbacks for a direct alert body:

- `rule_level`
- `agent_name`
- `description`
- `source_ip`
- `rule_id`
- `agent_id`
- `groups`

`includeOtherFields` is enabled, so the original webhook item is preserved alongside the
mapped fields. This is important because downstream nodes read both the mapped fields and
the nested `body` object.

### 5.2 IOC extraction and deduplication

**IOC Extraction** runs once per item. It preserves the alert, recursively scans strings
up to depth 10, and collects public IPv4 addresses, private IPv4 addresses, domains, URLs
and MD5/SHA-1/SHA-256 hashes. It sets a primary IOC using the priority public IP → URL →
domain → hash → private IP, and sets `ti_required` when any external IOC exists.

**Dedup Check** builds a fingerprint from the rule, agent, source IP, user and command,
then suppresses an alert if the same fingerprint was seen in the last three minutes.
High-volume rule families use a coarser rule-plus-agent fingerprint.

### 5.3 Routing

**IOC Routing** re-evaluates the alert rather than trusting the extraction result. It
looks for a public IP or a valid hash, detects local host events, and sets `ti_required`.
This second gate is the one that actually drives the **TI required?** IF node.

### 5.4 External branch

Six HTTP Request nodes run from the true output:

| Provider | Endpoint family | Input |
|---|---|---|
| VirusTotal | `/api/v3/ip_addresses/{value}` | `ioc.value` |
| AbuseIPDB | `/api/v2/check` | first public IP or `source_ip` |
| AlienVault OTX | `/api/v1/indicators/IPv4/{ip}/general` | `source_ip` |
| GreyNoise | `/api/v3/community/{ip}` | `source_ip` |
| ThreatFox | `/api/v1/` search | `source_ip` |
| LeakIX | `/host/{ip}` | `source_ip` |

All six connect to **Merge1** with six inputs. **TI Aggregator** turns the merged provider
responses into one threat-intelligence object, a 0–100 risk score, evidence strings,
malicious sources and a provider coverage percentage. **TI Normalizer** reshapes that
object, and **External Incident** wraps it in the common `{ incident: ... }` schema.

### 5.5 Internal branch

The false output of **TI required?** goes to **Internal Analysis**, which extracts the
user, target user, command and MITRE ATT&CK fields from the raw alert. **Internal
Incident** builds the same incident schema with `analysis_type: "internal"` and a
rule-level-derived severity.

### 5.6 Correlation and reporting

**Merge2** combines the external and internal incident objects. **TI Corroboration &
Scoring** assigns a verdict:

- `BENIGN_TELEMETRY` for low-level alerts without malicious evidence.
- `INTERNAL_SECURITY_EVENT` or `BENIGN_INTERNAL_EVENT` for internal alerts.
- `TRUE_POSITIVE_THREAT` for corroborated external threats.
- `UNCORROBORATED_OR_TRAINING` otherwise.

**Incident Summary** rebuilds the incident with a consistent schema and derives severity
from the rule level only when the incident has no severity. **Severity** then recomputes
severity from the rule level and TI evidence, overriding the corroboration result in
several cases. **Final Report** produces the analyst report, scene lines, summary,
recommendation and the DFIR-IRIS payload.

### 5.7 Decision and response

**Laya Decision Gate** posts a triage payload to the Laya engine, reads
`action`/`decision`, and stops the workflow when the action is not `ESCALATED`. On
escalation it appends the Laya correlation ID, verdict, confidence, layer and reason to
the IRIS payload and forwards the item to four nodes:

- **DFIR-IRIS Alert** creates the case, then **Discord Alert** posts an embed.
- **Severity Confirmation** checks for HIGH or CRITICAL and, on true, **Is Public IP?**
  checks the source IP. A public IP reaches **FortiGate HTTP Request node**.
- **Send a text message** posts a Telegram report.
- **Slack** posts a Slack report.

---

## 6. Observed capabilities and honest non-capabilities

### Present in the export

- Wazuh webhook ingestion.
- Field normalisation with fallbacks.
- Recursive IOC extraction for IPv4, URLs, domains and three hash lengths.
- Three-minute deduplication.
- Six threat-intelligence integrations.
- Deterministic risk scoring.
- External and internal incident branches.
- Verdict assignment and severity derivation.
- Analyst report and IRIS payload.
- Laya decision client (unsupported transport).
- DFIR-IRIS, Discord, Telegram, Slack and FortiGate HTTP calls.

### Not present in the export

- Native n8n AI/LLM nodes (for example, an AI Agent or OpenAI node).
- The Laya/Hermes engine source code.
- An HMAC-SHA256 signing or verification implementation.
- The referenced error workflow (`settings.errorWorkflow` was not exported).
- A firewall policy that blocks the created address object.
- A database schema, dashboard, frontend, or automated test suite for the workflow.
- Screenshots of the authenticated n8n canvas.
- Any evidence that the live workflow has the same configuration as the export.

### Claims that must not be made

- Do not claim HMAC-SHA256 authentication is implemented.
- Do not claim FortiGate blocking works. The node creates an address object.
- Do not claim the Laya integration is operational through the Code node.
- Do not claim the workflow was executed, load-tested or penetration-tested.
- Do not claim the notification channels are monitored or acknowledged.

---

## 7. Key metrics

| Metric | Value |
|---|---|
| Nodes | 31 |
| Connections | 36 |
| Code nodes | 13 |
| Code lines | ~2,960 |
| Code size | ~78 KB |
| HTTP Request nodes | 9 |
| IF nodes | 3 |
| Merge nodes | 2 |
| Webhook triggers | 1 |
| Credentials embedded in raw export | 8 provider/firewall/IRIS values |
| Other exposed identifiers | 1 Discord webhook URL, 1 Telegram chat ID, 3 infrastructure addresses, 3 instance identifiers |
| Findings | 4 critical, 8 high, 9 medium, 6 low |
| Sanitizer survivors | 0 |
| Secret-pattern findings in sanitized export | 0 |

---

## 8. How to read this documentation

| If you want to… | Read |
|---|---|
| Understand the business problem | This document |
| See the system and trust boundaries | [02 — Architecture](02-architecture.md) |
| Look up a specific node | [03 — Node reference](03-node-reference.md) |
| Review the JavaScript in detail | [04 — Code audit](04-code-audit.md) |
| Follow one alert through the system | [05 — Data flow](05-data-flow.md) |
| Connect Wazuh correctly | [06 — Wazuh integration](06-wazuh-integration.md) |
| Understand IOC extraction and TI | [07 — IOC and threat intelligence](07-ioc-and-threat-intelligence.md) |
| Understand scoring and verdicts | [08 — Correlation and severity](08-correlation-and-severity.md) |
| Find Hermes or HMAC details | [09 — Hermes AI integration](09-hermes-ai-integration.md) |
| Configure notifications and response | [10 — Notifications and response](10-notifications-and-response.md) |
| Deploy the workflow | [11 — Installation](11-installation.md) |
| Run validation and tests | [12 — Testing and validation](12-testing-and-validation.md) |
| Fix a failure | [13 — Troubleshooting](13-troubleshooting.md) |
| Harden the deployment | [14 — Security](14-security.md) |
| See what is missing | [15 — Limitations and roadmap](15-limitations-and-roadmap.md) |
| Read the findings register | [16 — Audit report](16-audit-report.md) |

---

## 9. Terminology

| Term | Meaning in this project |
|---|---|
| Alert | A single Wazuh event delivered to the webhook |
| IOC | Indicator of compromise: IP, URL, domain or file hash |
| TI | Threat intelligence from an external provider |
| Enrichment | Querying providers for reputation and metadata |
| Corroboration | Agreement across independent malicious signals |
| Incident | The normalised object built from one alert and its enrichment |
| Severity | LOW, MEDIUM, HIGH or CRITICAL |
| Verdict | The assessment label such as `TRUE_POSITIVE_THREAT` |
| Laya | Local decision engine called at `/api/triage` |
| Hermes | A separate integration named in the audit request; not found in this export |
| Fail-safe | Escalating when the decision engine is unreachable |
| Fan-out / fan-in | One node calling several nodes / several nodes merging into one |
| Static data | n8n's per-workflow persistent key-value store |

---

## 10. Document control and attestation

This overview describes the workflow as exported on 2026-11-10. It is a static review.
No statement in this document should be read as a runtime test result. Where the audit
could not verify something, the document says so explicitly.

The raw export remains outside the repository. The sanitized export is inactive and
contains placeholders only. The original credentials must be rotated regardless of the
sanitisation result.

See [16 — Audit report](16-audit-report.md) for the full findings register and evidence.
