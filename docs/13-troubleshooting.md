# 13 — Troubleshooting

| Item | Value |
|---|---|
| Document | Operational troubleshooting guide |
| Version | 1.0 |
| Date | 2026-11-10 |
| Basis | Static analysis; no live execution was performed during the audit |

> This guide maps symptoms to the **most likely cause visible in the exported
> configuration**. It does not contain verified runtime fixes. Confirm each diagnosis in
> the n8n execution view before changing the workflow.

---

## 1. First diagnostic steps

1. Open the failing execution in n8n and identify the last successful node.
2. Inspect the input and output JSON of that node.
3. Check whether the node produced zero items (common in this workflow).
4. Check the n8n execution-log level and the reverse-proxy logs.
5. Never paste real credentials, tokens or full alert bodies into a ticket or chat.

Useful read-only checks (replace placeholders):

```bash
# Laya engine health (read-only)
curl -sS --max-time 5 https://REPLACE_WITH_LAYA_HOST:9999/api/health

# Local repository validation
python scripts/validate_workflow.py \
  --workflow workflows/enterprise-soc-soar-pipeline.sanitized.json
python scripts/secret_scan.py --root .
```

Do not send a POST to `/api/triage` as a casual test; use a synthetic payload and a
non-production engine.

---

## 2. Ingestion failures

| Symptom | Likely cause | Action |
|---|---|---|
| Workflow never triggers | Wazuh posts to the wrong URL, wrong method, or the test URL instead of the production URL | Confirm `POST {N8N_BASE_URL}/webhook/wazuh-alerts`; verify the workflow is active |
| `rule_level` is `null` | Wazuh sent a raw body, not JSON with `Content-Type: application/json`, or the field is nested differently | Confirm n8n sees `$json.body.rule.level`; add a schema-validation node |
| `source_ip` is `null` | Wazuh used `data.src_ip`, Suricata `data.alert.source.ip`, or a Windows event field | `Edit Fields` only reads `data.srcip`; rely on `IOC Routing`'s wider candidate list or extend the mapping |
| Wazuh reports timeouts | The webhook responds only after six TI calls, report generation and four notifications | Return `202 Accepted` early and process asynchronously; check Wazuh retry settings |
| Duplicate executions | Wazuh retries on timeout; dedup is not atomic and is per workflow instance | Increase the webhook response speed; see H-04 |

---

## 3. Deduplication and routing

| Symptom | Likely cause | Action |
|---|---|---|
| No downstream nodes run after `Dedup Check` | The fingerprint was seen in the last 3 minutes; the node returned `[]` | Intended behaviour, but currently silent. Add a suppression log/metric (M-08) |
| Dedup never suppresses in editor tests | `$getWorkflowStaticData` is not reliably persisted for manual executions; test payloads with `test: true` bypass dedup | Validate dedup with a published webhook execution |
| Every alert bypasses TI | `IOC Routing` classified it as a local host event (`pam`/`sudo`/`syslog` group, `srcuser`, `command`, or `location: journald`) | Review the local-host rule; a public-IP SSH alert with a username is affected |
| High-volume rules are not collapsed | Regex bugs: `235\d` matches `2350`–`2359` and `8661[123]` matches `86611`–`86613` | Fix to `235\d{2}` and `8661\d` (H-04) |
| All alerts enriched despite dedup | A caller including `test: true` bypasses dedup through the unauthenticated webhook | Authenticate the webhook and remove the broad test bypass in production |

---

## 4. Provider failures

| Symptom | Likely cause | Action |
|---|---|---|
| 401 / 403 from a provider | Key placeholder not replaced, key revoked, wrong header name or wrong plan | Recreate n8n Header Auth credentials; verify the exact header: `x-apikey`, `key`, `X-OTX-API-KEY`, `auth-key`, `api-Key` |
| 429 rate limited | Six providers called per alert with no budget guard | Add caching and a per-hour budget; stagger high-volume alerts |
| All providers show `not_checked` | `continueRegularOutput` produced error items that the shape detectors do not recognise | Add explicit provider tagging and error mapping (M-09) |
| `provider_coverage` is high while results are empty | Coverage counts `unavailable` as checked | Fix M-03 |
| `provider_failures` contains numbers like `[3]` | The aggregator maps indices, not names | Fix M-03 |
| ThreatFox error makes everything CRITICAL | Any non-`no_result` `query_status` becomes `status: success`, and `Severity` treats that as a hit | Fix H-05 with explicit status mapping |
| Hash alerts produce no useful TI | All six provider nodes are IP-oriented | Implement hash/domain/URL-specific paths (H-06) |
| LeakIX always `not_checked` | Response shape does not match `services`/`summary`/`host` | Inspect an actual response; adapt the detector (M-04) |

---

## 5. Merge and item flow

| Symptom | Likely cause | Action |
|---|---|---|
| `Merge1` produces fewer than six items | A provider emitted no item; `alwaysOutputData` is only set on VT and OTX | Inspect each provider output; consider `alwaysOutputData` on all six |
| `TI Aggregator` loses alert context | `$('IOC Extraction').first().json` lookup failed and fell back to `{}` | Confirm the node name is unchanged after import |
| `Merge2` emits nothing | Append mode waits for all connected inputs; only one IF branch executes | Verify behaviour in the deployed n8n version; consider `alwaysOutputData` or a different merge strategy. This is a **design risk requiring runtime verification**, not a confirmed defect |
| Downstream node sees only the first item | All Code nodes use `$input.first().json` | Reduce items before the node or adapt it to `$input.all()` |

---

## 6. Reporting and scoring

| Symptom | Likely cause | Action |
|---|---|---|
| `Final Report` fails with `ReferenceError: d is not defined` | `sourceIp` was falsy and the fallback `d.srcuser` was evaluated (C-03) | Replace the fallback with a resolved `srcuser` value and add a timestamp |
| Severity differs from the verdict | four places compute severity; `Severity` overrides corroboration | Consolidate into one `assess()` function (H-03) |
| Internal level 10 reported as MEDIUM | `Severity` uses the `>= 8` MEDIUM band | Align thresholds with the corroboration node |
| LOW/CRITICAL IRIS priority looks inverted | IRIS IDs: CRITICAL 6, HIGH 5, MEDIUM 1, LOW 4 | Verify against the IRIS instance's severity table (H-07) |
| Repeated alerts collide in IRIS | `alert_source_ref` has no timestamp | Add the Wazuh alert ID or a timestamp |
| `rule_id` is null in the report | Duplicate object keys in `Incident Summary` discard the fallback | Remove the duplicate keys (M-05) |

---

## 7. Laya / Hermes decision gate

| Symptom | Likely cause | Action |
|---|---|---|
| Every alert has verdict `ENGINE_UNAVAILABLE` | The Code node cannot make HTTP requests; `fetch`/`this.helpers.httpRequest` fail (C-02) | Replace the Code node with an HTTP Request node for `POST /api/triage` |
| Every alert escalates with `correlation_id: lay-offline` | Fail-safe escalates rule level ≥8 or HIGH/CRITICAL | Fix the transport; add an alert on sustained `ENGINE_UNAVAILABLE` |
| Node fails instantly with a syntax error | Top-level `await` is not valid in a plain CommonJS module | Move the call to an HTTP Request node; see [04 — Code audit](04-code-audit.md) |
| Request hangs | No timeout in the `fetch` options | Use an HTTP Request node with a configured timeout |
| Engine rejects the request | Unverified: the actual `/api/triage` contract is unknown | Obtain the engine's OpenAPI spec or source; see [09](09-hermes-ai-integration.md) |
| No HMAC headers found | Not implemented in this export | Do not assume signing exists; follow the verification checklist in [09](09-hermes-ai-integration.md) |
| `Laya Decision Gate` returns zero items | `action` was not `ESCALATED`, or `layaDecision` was `null` | Inspect the engine response; decide whether an explicit closure record is needed |

---

## 8. Notification and containment failures

| Symptom | Likely cause | Action |
|---|---|---|
| No IRIS case created | 401/403, wrong host, disabled TLS verification still failing, or `127.0.0.1` pointing at the n8n container | Set `REPLACE_WITH_IRIS_HOST`, verify the token, enable TLS verification with a valid certificate |
| Discord/Telegram/Slack missing the IRIS case ID | Parallel branches evaluated `$('DFIR-IRIS Alert')` before IRIS finished | Serialise IRIS before the chat nodes |
| Telegram internal report has stray `' + idLine + '` text | Literal string instead of interpolation (M-06) | Use `${idLine}` inside the template literal |
| Telegram returns 400 | HTML parse mode with unescaped characters, or message too long | Escape all fields, cap message length |
| Slack message renders oddly or pings the channel | No mrkdwn escaping of `<`, `&`, `@here`, `@channel` | Escape alert-derived values |
| Chat node "succeeds" but nothing is delivered | `continueRegularOutput` + `neverError` hide the failure | Check n8n execution data and provider logs; add explicit error handling |
| FortiGate returns 405 or nothing happens | `method` is not set, so the node defaults to GET | Set POST/PUT and create a deny policy; an address object alone does not block |
| FortiGate certificate warning | `allowUnauthorizedCerts: true` | Install a trusted certificate and enable verification |
| MEDIUM/LOW incidents never reach FortiGate | `Severity Confirmation` false output is unconnected (H-02) | Connect it to an explicit "no containment" log |
| Private IP incidents never reach FortiGate | `Is Public IP?` false output is unconnected | Connect it to an explicit log; review the regex for `N/A` and CGNAT |

---

## 9. Security and hygiene

| Symptom | Likely cause | Action |
|---|---|---|
| A secret appears in Git history | A raw export or `.env` was staged | Remove from the working tree, rotate the value, and rewrite history only if it was actually committed; see [14](14-security.md) |
| Execution history contains full alert bodies | Default n8n execution retention | Set `EXECUTIONS_DATA_SAVE_ON_SUCCESS=none` and prune |
| Unexpected TI quota usage | Unauthenticated webhook or overly broad Wazuh filter | Add auth, IP allowlist, rate limit and schema validation |
| Provider keys still work after rotation | Old inline header values remain in the workflow | Replace all inline headers with n8n credentials |
| Terminal output shows a token | A command echoed a secret | Never print credentials; the sanitizer and secret scanner mask matches |

---

## 10. Escalation path

1. Reproduce with a synthetic alert from `workflows/samples/`.
2. Capture the failing node name, input shape and error message, with secrets redacted.
3. Check the corresponding section of [03 — Node reference](03-node-reference.md) and
   [04 — Code audit](04-code-audit.md).
4. Check [16 — Audit report](16-audit-report.md) for a known finding ID.
5. If the failure is new, add a unit test to `tests/` before changing the workflow.
6. Re-run `validate_workflow.py`, `secret_scan.py` and the unit tests.
7. Report privately per `SECURITY.md`; never include a live credential.

---

## 11. Related documents

- [04 — Code audit](04-code-audit.md)
- [10 — Notifications and response](10-notifications-and-response.md)
- [11 — Installation](11-installation.md)
- [12 — Testing and validation](12-testing-and-validation.md)
- [14 — Security](14-security.md)
- [16 — Audit report](16-audit-report.md)
