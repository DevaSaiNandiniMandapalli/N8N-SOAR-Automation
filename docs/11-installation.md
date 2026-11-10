# 11 — Installation and Configuration

| Item | Value |
|---|---|
| Document | Deployment and configuration guide |
| Version | 1.0 |
| Date | 2026-11-10 |
| Scope | Importing and configuring the **sanitized** workflow. No live execution was performed during the audit. |

> **Do not activate this workflow in production until the critical findings in
> [16 — Audit report](16-audit-report.md) are addressed.** The sanitized export imports
> inactive and contains placeholders only.

---

## 1. Prerequisites

| Component | Minimum | Notes |
|---|---|---|
| n8n | 2.x (export metadata reports 2.40.5) | Self-hosted recommended; Code node behaviour varies by version |
| Node.js | 18+ | Only needed for local validation (`node --check`) |
| Python | 3.10+ | Only needed for the validation scripts in this repository |
| Wazuh manager | Any version supporting an HTTP integration | Must be able to POST JSON |
| DFIR-IRIS | Reachable over HTTPS | Case management |
| Laya engine | Reachable decision service | Optional until C-02 is fixed |
| FortiGate | Management API enabled | Optional; containment is incomplete |
| Accounts | Six TI providers, Telegram bot, Slack app, Discord webhook | Use dedicated service accounts |

The workflow itself does not require a database beyond n8n's own internal storage for
workflow definitions, credentials and execution history. No application database, queue or
object store is introduced by this project.

---

## 2. Repository layout for deployment

```text
workflows/enterprise-soc-soar-pipeline.sanitized.json   ← import this file
workflows/samples/*.json                                ← synthetic fixtures
.env.example                                           ← copy to .env, never commit
scripts/*.py                                           ← local validation
docs/                                                  ← documentation
```

The original raw export must remain outside the repository. Add it to a secure location
with restricted access, or delete it after rotation if policy permits.

---

## 3. Step 1 — Validate locally before import

```bash
python scripts/validate_workflow.py \
  --workflow workflows/enterprise-soc-soar-pipeline.sanitized.json

python scripts/secret_scan.py --root .

python -m unittest discover -s tests -v
```

Expected results are documented in [12 — Testing and validation](12-testing-and-validation.md).
`validate_workflow.py` also runs `node --check` against every Code node, so Node.js must be
on `PATH`.

---

## 4. Step 2 — Import the workflow

1. Open n8n → **Workflows** → **Import from File**.
2. Select `workflows/enterprise-soc-soar-pipeline.sanitized.json`.
3. Confirm the import reports **31 nodes**.
4. Confirm the workflow is **inactive** (`active: false` in the sanitized export).
5. Rename the workflow if needed. The sanitized export keeps the original name but removes
   the workflow `id`, `versionId`, `meta.instanceId`, credential IDs, `webhookId` and
   `settings.errorWorkflow`.

Importing generates a new workflow ID and a new webhook ID. Update the Wazuh integration
with the new webhook URL.

---

## 5. Step 3 — Configure credentials

### 5.1 Required credential mapping

| Node | Placeholder | Where to set it |
|---|---|---|
| `virus total` | `REPLACE_WITH_VIRUSTOTAL_API_KEY` | `x-apikey` header |
| `AbuseIPDB` | `REPLACE_WITH_ABUSEIPDB_API_KEY` | `key` header |
| `OTX` | `REPLACE_WITH_OTX_API_KEY` | `X-OTX-API-KEY` header |
| `Grey Noise` | `REPLACE_WITH_GREYNOISE_API_KEY` | `key` header |
| `Threat Fox` | `REPLACE_WITH_THREATFOX_AUTH_KEY` | `auth-key` header |
| `Leakix` | `REPLACE_WITH_LEAKIX_API_KEY` | `api-Key` header |
| `FortiGate HTTP Request node` | `Bearer REPLACE_WITH_FORTIGATE_API_TOKEN` | `Authorization` header |
| `DFIR-IRIS Alert` | `Bearer REPLACE_WITH_DFIR_IRIS_API_TOKEN` | `Authorization` header |
| `Discord Alert` | Discord webhook ID/token in the URL | `url` parameter |
| `Send a text message` | `REPLACE_WITH_TELEGRAM_CHAT_ID` + `telegramApi` credential | chat ID + n8n credential |
| `Slack` | `slackApi` credential + `#security-reports` | n8n credential + channel |

### 5.2 Preferred pattern

Create **Header Auth** credentials in n8n for each bearer/API-key integration and select
them in the HTTP Request nodes. If you keep inline header values, bind them to environment
variables using n8n expressions (for example `{{$env.VIRUSTOTAL_API_KEY}}`) and restrict
access to the n8n environment.

Never commit a real value. `.gitignore` excludes `.env`, `*.local.json`, raw exports,
private workflow directories and temporary output.

### 5.3 Network placeholders

| Placeholder | Replace with |
|---|---|
| `REPLACE_WITH_LAYA_HOST` | Host or container address of the Laya engine |
| `REPLACE_WITH_IRIS_HOST` | DFIR-IRIS base hostname |
| `REPLACE_WITH_FORTIGATE_HOST` | FortiGate management address |
| `REPLACE_WITH_N8N_HOST` | n8n hostname used by the Wazuh integration |

The Laya Code node uses plain `http://` on port 9999. If you keep that design during
testing, isolate it on a private network. The recommended target is an HTTP Request node
over HTTPS with HMAC signing (see [09](09-hermes-ai-integration.md)).

---

## 6. Step 4 — Environment configuration

```bash
cp .env.example .env
# edit .env locally; never commit it
```

Key groups in `.env.example`:

| Group | Variables |
|---|---|
| n8n | `N8N_HOST`, `N8N_PORT`, `N8N_PROTOCOL`, `N8N_ENCRYPTION_KEY`, `WEBHOOK_URL`, `GENERIC_TIMEZONE`, execution pruning |
| TI providers | six `*_API_KEY` entries |
| Laya | `LAYA_BASE_URL`, `LAYA_TRIAGE_PATH`, `LAYA_API_TOKEN`, `LAYA_HMAC_SECRET`, `LAYA_REQUEST_TIMEOUT_MS` |
| DFIR-IRIS | `DFIR_IRIS_URL`, `DFIR_IRIS_API_KEY`, `DFIR_IRIS_CUSTOMER_ID` |
| FortiGate | `FORTIGATE_HOST`, `PORT`, `API_TOKEN`, `VDOM` |
| Notifications | Discord webhook, Telegram token/chat ID, Slack token/channel |

**Important.** `LAYA_HMAC_SECRET` and `LAYA_API_TOKEN` are documented placeholders, not
active configuration. `.env.example` says explicitly that HMAC is **not used by this
export**. Do not assume setting them enables signing.

Recommended n8n execution settings:

```text
EXECUTIONS_DATA_PRUNE=true
EXECUTIONS_DATA_MAX_AGE=168
EXECUTIONS_DATA_SAVE_ON_SUCCESS=none
```

Wazuh alerts can contain usernames, commands and raw logs. Minimise execution-data
retention in production.

---

## 7. Step 5 — Configure the Wazuh integration

The exact block depends on your Wazuh version; verify against its documentation. An
illustrative example:

```xml
<ossec_config>
  <integration>
    <name>custom-webhook</name>
    <hook_url>https://REPLACE_WITH_N8N_HOST/webhook/wazuh-alerts</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

Checklist:

- [ ] POST to the new production webhook URL.
- [ ] `Content-Type: application/json`.
- [ ] Filter by rule/group so the workflow does not receive every level-7+ event.
- [ ] Add an authentication header or IP allowlist at the reverse proxy.
- [ ] Set a bounded timeout and retry policy.
- [ ] Use the synthetic fixture `workflows/samples/wazuh-alert.sample.json` for a first
      test.

See [06 — Wazuh integration](06-wazuh-integration.md) for the expected alert fields.

---

## 8. Step 6 — Harden the webhook before activation

The exported webhook has **no authentication**. Minimum controls:

| Control | Implementation |
|---|---|
| Header Auth / JWT / mTLS | n8n webhook authentication or reverse proxy |
| IP allowlist | Reverse proxy or firewall, restricted to the Wazuh manager |
| Rate limiting | Reverse proxy, per source IP |
| Body size limit | Reverse proxy + schema validation node |
| Schema validation | New Set/Code node requiring `rule.id`, numeric `rule.level`, `agent.name` |
| TLS | HTTPS with a valid certificate |
| Fast response | Return `202 Accepted` and process asynchronously if Wazuh retries on timeout |

Also enable TLS verification on DFIR-IRIS and FortiGate by removing
`allowUnauthorizedCerts: true` once valid certificates are in place.

---

## 9. Step 7 — Pre-activation checklist

| # | Check | Why |
|---|---|---|
| 1 | All 13 original credentials rotated | They existed in the raw export; sanitisation does not revoke them |
| 2 | No real secret in any committed file | `python scripts/secret_scan.py --root .` |
| 3 | Workflow imported inactive | Avoid accidental live traffic |
| 4 | Webhook authenticated and IP-restricted | C-04 |
| 5 | `Final Report` `ReferenceError` fixed | C-03 |
| 6 | Laya call moved to an HTTP Request node | C-02 |
| 7 | FortiGate method set to POST/PUT and policy created | H-01 |
| 8 | IF false outputs connected or explicitly logged | H-02 |
| 9 | One severity function | H-03 |
| 10 | ThreatFox status mapping fixed | H-05 |
| 11 | IRIS severity IDs verified against the IRIS instance | H-07 |
| 12 | Execution-data pruning enabled | H-08 |
| 13 | Synthetic alert produces one IRIS case and three chat messages | Runtime validation |
| 14 | Duplicate alert is suppressed with a record | M-08 |
| 15 | Provider error path produces `unavailable`, not CRITICAL | H-05 / M-09 |

Items 5–12 are **code changes**, not configuration. Until they are done, the workflow
should be treated as a reference implementation, not a production SOAR control.

---

## 10. Step 8 — Activation

1. Activate the workflow in n8n.
2. Publish the production webhook URL to Wazuh.
3. Send one synthetic alert from a test host.
4. Inspect the n8n execution view node by node.
5. Verify the IRIS case, the three chat messages and the Laya decision record.
6. Verify that a duplicate alert within three minutes is suppressed.
7. Verify that an invalid payload is rejected at the schema-validation node.
8. Review execution history for secret leakage and redact as needed.
9. Enable monitoring of provider 401/429/5xx responses.

Do **not** test with real production alerts until the checklist above passes.

---

## 11. Upgrade and rollback

| Action | Procedure |
|---|---|
| Upgrade | Import the new sanitized export as a duplicate; compare node counts; migrate credentials; deactivate the old workflow after validation |
| Rollback | Deactivate the new workflow, reactivate the previous version, point Wazuh back to the previous webhook URL |
| Secret rotation | Update n8n credentials, then revoke the old value at the provider; no workflow edit is needed if credentials are used |
| Config change | Prefer environment variables / n8n credentials over editing node parameters |

Keep the raw export out of Git. Keep `.env` out of Git. Review `git log -p` before pushing
if any secret was ever staged locally (see [14 — Security](14-security.md)).

---

## 12. Validation commands

```bash
# Structural + Code node syntax validation
python scripts/validate_workflow.py \
  --workflow workflows/enterprise-soc-soar-pipeline.sanitized.json

# Secret scan of the whole repository
python scripts/secret_scan.py --root .

# Secret scan including Git history (after a commit exists)
python scripts/secret_scan.py --root . --history

# Unit tests
python -m unittest discover -s tests -v

# Regenerate the sanitized export from a raw export (never publish the raw file)
python scripts/sanitize_workflow.py \
  --source /secure/path/raw-export.json \
  --output workflows/enterprise-soc-soar-pipeline.sanitized.json \
  --report docs/sanitization-report.json
```

---

## 13. Related documents

- [06 — Wazuh integration](06-wazuh-integration.md)
- [09 — Hermes AI integration](09-hermes-ai-integration.md)
- [12 — Testing and validation](12-testing-and-validation.md)
- [13 — Troubleshooting](13-troubleshooting.md)
- [14 — Security](14-security.md)
- [16 — Audit report](16-audit-report.md)
