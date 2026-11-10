# N8N SOAR Automation — AI SOC Copilot

Private engineering repository for the **Enterprise SOC SOAR Pipeline**, an n8n-based
security orchestration and automation workflow that ingests Wazuh alerts, enriches
indicators with six threat-intelligence providers, correlates evidence, produces an
analyst-grade incident report, and routes escalated incidents to DFIR-IRIS, Discord,
Telegram, Slack and an optional FortiGate containment step.

> **Status:** audited and sanitized from a live export (workflow `ORQ4n82CacFdx45s`).
> The audit was **static**: the workflow was not executed, and no live n8n configuration
> was modified. Runtime claims are limited to what the exported configuration and the
> reachable service metadata support.

---

## 1. What this repository contains

| Area | Contents |
|---|---|
| Workflow | Sanitized, importable n8n JSON with 31 nodes and 36 connections |
| Documentation | 16 documents covering architecture, every node, every Code node, data flow, security, operations and limitations |
| Diagrams | Mermaid source for context, pipeline, sequence and data-model views |
| Samples | Synthetic Wazuh alert and n8n webhook item |
| Validation | Structural validator, secret scanner, unit tests and CI workflow |
| Audit | Findings register, sanitization report and evidence notes |

The original raw export is **not** included and must never be committed.

---

## 2. Architecture at a glance

```mermaid
flowchart LR
    W["Wazuh Manager"] -->|"POST /webhook/wazuh-alerts"| N["n8n workflow<br/>31 nodes / 36 connections"]
    N --> IOC["IOC Extraction"]
    IOC --> DD["Dedup Check<br/>3-minute static-data window"]
    DD --> RT["IOC Routing"]
    RT -->|"ti_required = true"| TI["Threat intelligence<br/>VirusTotal · AbuseIPDB · OTX<br/>GreyNoise · ThreatFox · LeakIX"]
    RT -->|"ti_required = false"| IA["Internal Analysis"]
    TI --> AG["TI Aggregator"]
    AG --> NM["TI Normalizer"]
    NM --> EI["External Incident"]
    IA --> II["Internal Incident"]
    EI --> M["Merge2"]
    II --> M
    M --> CS["TI Corroboration & Scoring"]
    CS --> IS["Incident Summary"]
    IS --> SV["Severity"]
    SV --> FR["Final Report"]
    FR --> LG["Laya Decision Gate"]
    LG -.->|"HTTP POST /api/triage"| L["Laya / Hermes engine"]
    LG -->|"ESCALATED"| IR["DFIR-IRIS Alert"]
    IR --> DC["Discord"]
    LG --> SC["Severity Confirmation"]
    SC -->|"HIGH / CRITICAL"| IP["Is Public IP?"]
    IP -->|"public"| FG["FortiGate CMDB"]
    LG --> TG["Telegram"]
    LG --> SL["Slack"]
```

Detailed diagrams: [`docs/02-architecture.md`](docs/02-architecture.md) and
[`docs/diagrams/`](docs/diagrams/).

---

## 3. Observed capabilities

These are present in the exported workflow:

- Wazuh webhook ingestion (`POST /wazuh-alerts`), no authentication configured.
- Wazuh alert normalisation into `rule_level`, `agent_name`, `description`,
  `source_ip`, `rule_id`, `agent_id` and `groups`.
- Recursive IOC extraction for IPv4 addresses, URLs, MD5/SHA-1/SHA-256 hashes and a
  restricted set of domains.
- Three-minute in-workflow deduplication using n8n static workflow data.
- Threat-intelligence enrichment through VirusTotal, AbuseIPDB, AlienVault OTX,
  GreyNoise, ThreatFox and LeakIX.
- Deterministic risk scoring (0–100) and severity derivation.
- Separate external-threat and internal-host analysis branches.
- Incident correlation and verdict assignment (`TRUE_POSITIVE_THREAT`,
  `UNCORROBORATED_OR_TRAINING`, `INTERNAL_SECURITY_EVENT`, `BENIGN_TELEMETRY`).
- Analyst report generation with a structured alert scene, evidence, recommendation
  and an IRIS payload.
- A Laya decision-gate client with a fail-safe, plus DFIR-IRIS, Discord, Telegram,
  Slack and FortiGate HTTP integrations.

These are **not** present in this export:

- Any native n8n AI/LLM node.
- The Laya/Hermes engine implementation, its model code or its HMAC-SHA256 signing
  implementation.
- The referenced error workflow (`settings.errorWorkflow` pointed to a workflow that
  was not exported).
- A dashboard, frontend, database schema or test suite.
- The FortiGate firewall policy that would actually block traffic.
- Screenshots of the authenticated n8n canvas.

See [`docs/15-limitations-and-roadmap.md`](docs/15-limitations-and-roadmap.md).

---

## 4. Repository map

```text
.
├── README.md
├── SECURITY.md
├── CHANGELOG.md
├── .env.example
├── .gitignore
├── docs/
│   ├── 01-project-overview.md
│   ├── 02-architecture.md
│   ├── 03-node-reference.md
│   ├── 04-code-audit.md
│   ├── 05-data-flow.md
│   ├── 06-wazuh-integration.md
│   ├── 07-ioc-and-threat-intelligence.md
│   ├── 08-correlation-and-severity.md
│   ├── 09-hermes-ai-integration.md
│   ├── 10-notifications-and-response.md
│   ├── 11-installation.md
│   ├── 12-testing-and-validation.md
│   ├── 13-troubleshooting.md
│   ├── 14-security.md
│   ├── 15-limitations-and-roadmap.md
│   ├── 16-audit-report.md
│   ├── sanitization-report.json
│   ├── assets/
│   └── diagrams/
├── workflows/
│   ├── enterprise-soc-soar-pipeline.sanitized.json
│   └── samples/
│       ├── wazuh-alert.sample.json
│       └── n8n-webhook-item.sample.json
├── scripts/
│   ├── sanitize_workflow.py
│   ├── validate_workflow.py
│   └── secret_scan.py
├── tests/
│   ├── test_workflow.py
│   └── fixtures/
└── .github/workflows/validate.yml
```

---

## 5. Quick start

### 5.1 Import

1. Open n8n → **Workflows** → **Import from File**.
2. Select `workflows/enterprise-soc-soar-pipeline.sanitized.json`.
3. The workflow imports **inactive** and with placeholders. Do not activate it yet.

### 5.2 Configure credentials

The sanitized export contains no credentials. Recreate them in n8n:

| Integration | Credential / header | Placeholder |
|---|---|---|
| VirusTotal | `x-apikey` | `REPLACE_WITH_VIRUSTOTAL_API_KEY` |
| AbuseIPDB | `key` | `REPLACE_WITH_ABUSEIPDB_API_KEY` |
| AlienVault OTX | `X-OTX-API-KEY` | `REPLACE_WITH_OTX_API_KEY` |
| GreyNoise | `key` | `REPLACE_WITH_GREYNOISE_API_KEY` |
| ThreatFox | `auth-key` | `REPLACE_WITH_THREATFOX_AUTH_KEY` |
| LeakIX | `api-Key` | `REPLACE_WITH_LEAKIX_API_KEY` |
| FortiGate | `Authorization` | `Bearer REPLACE_WITH_FORTIGATE_API_TOKEN` |
| DFIR-IRIS | `Authorization` | `Bearer REPLACE_WITH_DFIR_IRIS_API_TOKEN` |
| Discord | webhook URL | `REPLACE_WITH_DISCORD_WEBHOOK_ID/TOKEN` |
| Telegram | `telegramApi` credential + chat ID | `REPLACE_WITH_TELEGRAM_CHAT_ID` |
| Slack | `slackApi` credential + channel | `#security-reports` |

Prefer n8n **Header Auth** credentials over inline header values. If you keep
inline values, bind them to environment variables and restrict access to the n8n
instance.

### 5.3 Network placeholders

| Placeholder | Meaning |
|---|---|
| `REPLACE_WITH_LAYA_HOST` | Host running the Laya/Hermes triage engine |
| `REPLACE_WITH_IRIS_HOST` | DFIR-IRIS base URL |
| `REPLACE_WITH_FORTIGATE_HOST` | FortiGate management address |

### 5.4 Validate locally

```bash
python scripts/validate_workflow.py \
  --workflow workflows/enterprise-soc-soar-pipeline.sanitized.json

python scripts/secret_scan.py --root .

python -m unittest discover -s tests -v
```

`validate_workflow.py` also runs `node --check` against every Code node extracted
from the workflow, so it requires Node.js 18+.

### 5.5 Webhook

The Wazuh integration posts to:

```text
POST {N8N_BASE_URL}/webhook/wazuh-alerts
Content-Type: application/json
```

The request body is the Wazuh alert object. n8n wraps it in `body`, which is why the
workflow reads `$json.body.rule.level`. See
[`docs/06-wazuh-integration.md`](docs/06-wazuh-integration.md).

> The exported webhook has **no authentication and no IP allowlist**. Add Header Auth,
> JWT or an IP allowlist before exposing the endpoint outside a trusted network.

---

## 6. Security notice

The original export contained:

- 8 hard-coded provider/firewall/IRIS credentials,
- 1 Discord webhook URL,
- 1 Telegram chat ID,
- private and public infrastructure addresses,
- n8n `instanceId`, `versionId`, credential IDs and an `errorWorkflow` reference.

All were removed or replaced. The sanitizer reports **0 surviving original secrets**
and **0 unredacted secret-pattern findings**.

**Rotate every credential that was present in the original export.** Sanitization
does not un-leak a value that has already existed in a file, a screenshot, a chat or a
backup. See [`SECURITY.md`](SECURITY.md) and
[`docs/14-security.md`](docs/14-security.md).

---

## 7. Audit snapshot

| Metric | Value |
|---|---|
| Nodes | 31 |
| Connections | 36 |
| Code nodes | 13 (2,960 lines, ~78 KB) |
| HTTP integration nodes | 9 |
| IF nodes | 3 |
| Merge nodes | 2 |
| Webhook trigger | 1 (`POST /wazuh-alerts`) |
| Notification channels | Discord, Telegram, Slack, DFIR-IRIS |
| Containment integrations | FortiGate CMDB (incomplete) |
| Critical findings | 4 |
| High findings | 8 |
| Medium findings | 9 |
| Low findings | 6 |

The full register, evidence and recommendations are in
[`docs/16-audit-report.md`](docs/16-audit-report.md).

---

## 8. Documentation index

1. [Project overview](docs/01-project-overview.md)
2. [System architecture](docs/02-architecture.md)
3. [Node-by-node reference](docs/03-node-reference.md)
4. [Code audit](docs/04-code-audit.md)
5. [Data flow and execution](docs/05-data-flow.md)
6. [Wazuh integration](docs/06-wazuh-integration.md)
7. [IOC extraction and threat intelligence](docs/07-ioc-and-threat-intelligence.md)
8. [Correlation and severity scoring](docs/08-correlation-and-severity.md)
9. [Hermes AI integration and HMAC status](docs/09-hermes-ai-integration.md)
10. [Notifications and response actions](docs/10-notifications-and-response.md)
11. [Installation and configuration](docs/11-installation.md)
12. [Testing and validation](docs/12-testing-and-validation.md)
13. [Troubleshooting](docs/13-troubleshooting.md)
14. [Security considerations](docs/14-security.md)
15. [Limitations and roadmap](docs/15-limitations-and-roadmap.md)
16. [Audit report](docs/16-audit-report.md)

---

## 9. Ownership

Private project maintained by **Deva Sai Nandini Mandapalli**
([@DevaSaiNandiniMandapalli](https://github.com/DevaSaiNandiniMandapalli)).

No open-source licence is granted by this repository. All rights reserved.
