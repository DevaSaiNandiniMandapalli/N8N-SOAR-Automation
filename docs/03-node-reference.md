# 03 — Node-by-Node Reference

| Item | Value |
|---|---|
| Document | Complete node reference |
| Version | 1.0 |
| Date | 2026-11-10 |
| Coverage | 31 of 31 nodes, 36 of 36 connections |

This document describes every node in the sanitized export. Parameters are quoted from the
sanitized workflow; secrets are placeholders. Node order follows the execution graph,
not the order in the JSON file.

---

## 0. Complete inventory

| # | Node name | Type | Version | Stage | Mode / key config |
|---|---|---|---|---|---|
| 1 | Webhook | `n8n-nodes-base.webhook` | 2.1 | Ingress | `POST /wazuh-alerts` |
| 2 | Edit Fields | `n8n-nodes-base.set` | 3.5 | Ingress | 7 assignments, keep other fields |
| 3 | IOC Extraction | `n8n-nodes-base.code` | 2 | Pre-processing | Run Once for Each Item |
| 4 | Dedup Check | `n8n-nodes-base.code` | 2 | Pre-processing | Run Once for All Items |
| 5 | IOC Routing | `n8n-nodes-base.code` | 2 | Pre-processing | Run Once for All Items |
| 6 | TI required? | `n8n-nodes-base.if` | 2.3 | Routing | Boolean true on `$json.ti_required` |
| 7 | Threat Fox | `n8n-nodes-base.httpRequest` | 4.4 | External TI | POST JSON body |
| 8 | Grey Noise | `n8n-nodes-base.httpRequest` | 4.4 | External TI | GET community API |
| 9 | AbuseIPDB | `n8n-nodes-base.httpRequest` | 4.4 | External TI | GET with query parameters |
| 10 | OTX | `n8n-nodes-base.httpRequest` | 4.4 | External TI | GET general endpoint |
| 11 | virus total | `n8n-nodes-base.httpRequest` | 4.4 | External TI | GET ip_addresses |
| 12 | Leakix | `n8n-nodes-base.httpRequest` | 4.4 | External TI | GET host endpoint |
| 13 | Merge1 | `n8n-nodes-base.merge` | 3.2 | External TI | `numberInputs: 6`, default Append |
| 14 | TI Aggregator | `n8n-nodes-base.code` | 2 | External TI | `$input.all()` shape detection |
| 15 | TI Normalizer | `n8n-nodes-base.code` | 2 | External TI | Reshape to `alert`/`threat_intelligence`/`assessment` |
| 16 | External Incident | `n8n-nodes-base.code` | 2 | External TI | Wrap in `{ incident }` |
| 17 | Internal Analysis | `n8n-nodes-base.code` | 2 | Internal | Extract user/command/MITRE |
| 18 | Internal Incident | `n8n-nodes-base.code` | 2 | Internal | Wrap in `{ incident }` |
| 19 | Merge2 | `n8n-nodes-base.merge` | 3.2 | Correlation | Default 2 inputs, default Append |
| 20 | TI Corroboration & Scoring | `n8n-nodes-base.code` | 2 | Correlation | Verdict + secondary severity |
| 21 | Incident Summary | `n8n-nodes-base.code` | 2 | Correlation | Schema rebuild |
| 22 | Severity | `n8n-nodes-base.code` | 2 | Correlation | Final severity override |
| 23 | Final Report | `n8n-nodes-base.code` | 2 | Reporting | Report + IRIS payload |
| 24 | Laya Decision Gate | `n8n-nodes-base.code` | 2 | Decision | HTTP call + fail-safe |
| 25 | DFIR-IRIS Alert | `n8n-nodes-base.httpRequest` | 4.4 | Response | POST `/alerts/add` |
| 26 | Discord Alert | `n8n-nodes-base.httpRequest` | 4.4 | Response | POST webhook embed |
| 27 | Severity Confirmation | `n8n-nodes-base.if` | 2.3 | Response | `severity` equals HIGH or CRITICAL |
| 28 | Is Public IP? | `n8n-nodes-base.if` | 2 | Response | Regex excludes private ranges |
| 29 | FortiGate HTTP Request node | `n8n-nodes-base.httpRequest` | 4.4 | Response | CMDB `firewall/address` |
| 30 | Send a text message | `n8n-nodes-base.telegram` | 1.2 | Response | HTML report |
| 31 | Slack | `n8n-nodes-base.slack` | 2.5 | Response | Channel message |

### Connection table (36 edges)

| Source | Output index | Target | Target input |
|---|---:|---|---:|
| Webhook | 0 | Edit Fields | 0 |
| Edit Fields | 0 | IOC Extraction | 0 |
| IOC Extraction | 0 | Dedup Check | 0 |
| Dedup Check | 0 | IOC Routing | 0 |
| IOC Routing | 0 | TI required? | 0 |
| TI required? | 0 | Threat Fox | 0 |
| TI required? | 0 | Grey Noise | 0 |
| TI required? | 0 | AbuseIPDB | 0 |
| TI required? | 0 | OTX | 0 |
| TI required? | 0 | virus total | 0 |
| TI required? | 0 | Leakix | 0 |
| TI required? | 1 | Internal Analysis | 0 |
| Threat Fox | 0 | Merge1 | 0 |
| Grey Noise | 0 | Merge1 | 1 |
| AbuseIPDB | 0 | Merge1 | 2 |
| OTX | 0 | Merge1 | 3 |
| virus total | 0 | Merge1 | 4 |
| Leakix | 0 | Merge1 | 5 |
| Merge1 | 0 | TI Aggregator | 0 |
| TI Aggregator | 0 | TI Normalizer | 0 |
| TI Normalizer | 0 | External Incident | 0 |
| External Incident | 0 | Merge2 | 0 |
| Internal Analysis | 0 | Internal Incident | 0 |
| Internal Incident | 0 | Merge2 | 1 |
| Merge2 | 0 | TI Corroboration & Scoring | 0 |
| TI Corroboration & Scoring | 0 | Incident Summary | 0 |
| Incident Summary | 0 | Severity | 0 |
| Severity | 0 | Final Report | 0 |
| Final Report | 0 | Laya Decision Gate | 0 |
| Laya Decision Gate | 0 | DFIR-IRIS Alert | 0 |
| Laya Decision Gate | 0 | Severity Confirmation | 0 |
| Laya Decision Gate | 0 | Send a text message | 0 |
| Laya Decision Gate | 0 | Slack | 0 |
| DFIR-IRIS Alert | 0 | Discord Alert | 0 |
| Severity Confirmation | 0 | Is Public IP? | 0 |
| Is Public IP? | 0 | FortiGate HTTP Request node | 0 |

**Unconnected outputs (dead ends):**

- `TI required?` has no output beyond the two documented branches.
- `Severity Confirmation` output 1 (false) has **no connection**. MEDIUM and LOW escalated
  incidents never reach `Is Public IP?`, FortiGate or any severity-specific branch.
- `Is Public IP?` output 1 (false) has **no connection**. Private, missing or non-matching
  source IPs silently skip FortiGate.
- `Discord Alert`, `FortiGate HTTP Request node`, `Send a text message` and `Slack` are
  terminal nodes.
- `Dedup Check` returns zero items for suppressed alerts; there is no downstream node for
  that case.

No node is disabled. No node has notes or sticky annotations. No node sets a custom
`onError` other than those listed below.

---

## 1. Webhook

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.webhook` v2.1 |
| Parameters | `httpMethod: POST`, `path: wazuh-alerts`, `options: {}` |
| Credentials | None |
| `webhookId` | Removed by sanitisation; must be regenerated on import |
| Error behaviour | Default (fail execution) |

**Purpose.** Single entry point. Accepts a JSON Wazuh alert. n8n exposes it as
`{N8N_BASE_URL}/webhook/wazuh-alerts` for production executions and
`/webhook-test/wazuh-alerts` for editor tests.

**Input.** An HTTP POST. n8n wraps the parsed JSON body in `body`, so downstream
expressions read `$json.body.rule.level`, not `$json.rule.level`.

**Output.** One item containing `body`, `headers`, `params`, `query` (n8n webhook
metadata). `Edit Fields` merges seven mapped fields into this item.

**Security state.** No authentication, no IP allowlist, no request-size limit, no schema
validation, no rate limiting. `options: {}` means the default response behaviour is used;
the webhook response is produced after the workflow runs. This is the most exposed
surface in the system.

**Findings.** C-04 (unauthenticated ingress), H-08 (execution data retention).

**Recommendation.** Add Header Auth or JWT verification at the webhook, an IP allowlist at
the reverse proxy, a maximum body size, a JSON schema check, and a rate limit. Return an
explicit `202 Accepted` and process asynchronously if the upstream Wazuh integration
retries on timeout.

---

## 2. Edit Fields

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.set` v3.5 |
| `includeOtherFields` | `true` |
| Options | `{}` |
| Error behaviour | Default |

**Assignments:**

| Field | Type | Expression |
|---|---|---|
| `rule_level` | number | `={{ $json.body?.rule?.level ?? $json.rule?.level ?? null }}` |
| `agent_name` | string | `={{ $json.body?.agent?.name ?? $json.agent?.name ?? null }}` |
| `description` | string | `={{ $json.body?.rule?.description ?? $json.rule?.description ?? null }}` |
| `source_ip` | string | `={{ $json.body?.data?.srcip ?? $json.data?.srcip ?? null }}` |
| `rule_id` | string | `={{ $json.body?.rule?.id ?? $json.rule?.id ?? null }}` |
| `agent_id` | string | `={{ $json.body?.agent?.id ?? $json.agent?.id ?? null }}` |
| `groups` | string | `={{ $json.body?.rule?.groups ?? $json.rule?.groups ?? [] }}` |

**Purpose.** Provide a flat, tolerant field set. The `?.` and `??` fallbacks allow the
same workflow to accept a raw Wazuh alert posted directly (without the `body` wrapper).

**Output.** The original webhook item plus the seven mapped fields. Downstream nodes use
both forms: `IOC Extraction` prefers `input.body`, while `Dedup Check` and `IOC Routing`
fall back through `body`, `original_alert` and the mapped fields.

**Observations.**

- `groups` is declared as `string` but Wazuh sends an array. n8n may coerce it; later
  Code nodes read `alert.rule.groups` from the original alert instead, so this field is
  mostly informational.
- `source_ip` only reads `data.srcip`. Wazuh alerts can carry `data.src_ip`,
  `data.source_ip`, Suricata `data.alert.source.ip`, or Windows `data.win.eventdata.ipAddress`.
  `IOC Routing` compensates with a wider candidate list.
- No validation that `rule.level` is numeric or that `srcip` is a valid IP.

---

## 3. IOC Extraction

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.code` v2 |
| Mode | Run Once for Each Item |
| Lines | ~659 |
| Retry | 3 attempts, 3 s apart |

**Purpose.** Preserve the original alert, extract IOCs from known fields and free text,
classify IPv4 addresses as public or private, and set `ti_required`.

**Algorithm.** See [07 — IOC and threat intelligence](07-ioc-and-threat-intelligence.md)
for the full line-level description. Summary:

1. Resolve the alert from `input.body` (object or JSON string), else use `input`.
2. Recursively scan strings, arrays and objects to depth 10.
3. Regexes: URLs `https?://...`, IPv4 `(?:\d{1,3}\.){3}\d{1,3}`, hashes of 32/40/64 hex
   characters, and domain-looking strings.
4. Validate IPv4 octets 0–255; classify `10/8`, `172.16/12`, `192.168/16`, `127/8`,
   `169.254/16` and `0/8` as private.
5. Accept a domain only if its TLD is in a 26-entry allowlist.
6. Primary IOC priority: public IP → URL → domain → hash → private IP.
7. `ti_required` is true if any public IP, URL, domain or hash was found.

**Output.** The input plus `original_alert`, `ioc` (with arrays), `ti_required` and
`internal_analysis_required`.

**Audit notes.** TLD allowlist misses many real TLDs; IPv6 is not handled; the first
public IP may be a destination; `ti_required` here is recomputed by `IOC Routing`; the
node emits a bare object rather than `[{ json: ... }]`, which n8n accepts for this mode.

**Findings.** M-01, M-02.

---

## 4. Dedup Check

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 55 |
| Flags | `onError: continueRegularOutput`, `retryOnFail: true`, `maxTries: 3`, `waitBetweenTries: 3000` |

**Parameters.** `DEDUP_WINDOW_MS = 180000` (3 minutes). Uses
`$getWorkflowStaticData('global').seenAlerts`.

**Behaviour.**

- Test bypass: if `data.test`, `data.body.test` or `data.original_alert.test` is set,
  return the item unchanged.
- Sweep entries older than the window.
- Fingerprint:
  - high-volume rules: `HV|ruleId|agentName`
  - public IP: `EXT|ruleId|agentName|sourceIp`
  - command/user: `INT|ruleId|agentName|user|command`
  - otherwise: `GEN|ruleId|agentName|description`
- If the key exists, **return `[]`** — the execution branch ends with no output and no audit
  record. Otherwise store `seenAlerts[key] = Date.now()`.

High-volume regex: `/^(235\d|19\d{3}|915\d{2}|8661[123])$/`.

**Audit notes.** `235\d` matches four-digit `2350`–`2359`, not `235xx`; `8661[123]`
matches `86611`–`86613`, not `86610`–`86619`. Static workflow data is not shared across
n8n instances and is unreliable for manual executions. There is no atomic check-and-set,
so concurrent executions can both pass. Suppression is silent.

**Findings.** H-04, M-08.

---

## 5. IOC Routing

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 138 |
| Retry | 3 attempts |

**Purpose.** "Primary alert judgement": decide whether external TI or internal host
analysis is required and set the final `ti_required`, `source_ip` and `ioc` values.

**Candidate IPs (in order):** `alert.data.srcip`, `alert.data.src_ip`,
`alert.data.source_ip`, `alert.srcip`, `alert.source_ip`, `data.source_ip`,
`data.ioc.value`. The first non-private value becomes `verifiedPublicIP`.

**Private/local predicate** `isPrivateOrLocalIP` rejects: `localhost`, `127.0.0.1`,
`::1`, `0.0.0.0`, non-4-part strings, `10/8`, `172.16/12`, `192.168/16`, `127/8`,
`169.254/16`, CGNAT `100.64/10`, `0/8`, and `>= 224`.

**Candidate hashes:** `data.md5/sha1/sha256/hash/file_hash`, `syscheck.*_after`, and
top-level hash fields; validated as 32/40/64 hex characters.

**Local host event detection:** rule groups containing `sudo`, `pam` or `syslog`,
`location === 'journald'`, or presence of `data.srcuser` / `data.command`.

**Decision:**

| Condition | `ti_required` | `verifiedIOC` |
|---|---|---|
| Public IP and not a local host event | `true` | `{ type: 'public_ip', value }` |
| Valid hash (and no public IP, or local event) | `true` | `{ type: 'hash', value }` |
| Otherwise | `false` | `{ type: 'none', value: null }` |

It also emits `laya_primary` (stage, verdict, reason, public IP, hash, timestamp),
`gatekeeper`, `source_ip` (public IP or first candidate), and overwrites `ioc`.

**Audit notes.** The first candidate IP is used even if it is a destination address. A
public IP in a *local host event* suppresses TI entirely (the hash branch can still
trigger). `100.64/10` is treated as private here but not in `IOC Extraction`, so the two
nodes disagree. Documentation/test ranges such as `198.18/15` and RFC5737 `203.0.113/24`
are treated as public — this matters for lab and sample data.

**Findings.** H-06, M-02, M-09.

---

## 6. TI required?

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.if` v2.3 |
| Condition | `={{ $json.ti_required }}` is boolean `true` |
| Options | `caseSensitive: true`, `typeValidation: strict`, `version: 3`, combinator `and` |

**Outputs.** Output 0 (true) fans out to the six providers. Output 1 (false) goes to
`Internal Analysis`.

**Audit notes.** Because `typeValidation` is `strict`, a string `"true"` would not match.
`IOC Routing` always sets a real boolean, so this is consistent. There is no third
"unknown" branch. No error workflow is attached.

---

## 7. Threat Fox

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| Method | `POST` |
| URL | `https://threatfox-api.abuse.ch/api/v1/` |
| Headers | `Content-Type: application/json`, `auth-key: REPLACE_WITH_THREATFOX_AUTH_KEY` |
| Body | `={"query":"search_ioc","search_term":"{{$json.source_ip}}"}` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Search ThreatFox for an IOC. **Observation:** the search term is always
`$json.source_ip`, even when `IOC Routing` selected a hash as the verified IOC. For
hash-only alerts this searches an IP that may be `null`.

**Output shape used by the aggregator:** the response's `query_status` field. Any value
other than `no_result` is treated as `success` by `TI Aggregator`. The result is stored
under `threat_intelligence.threatfox.result`.

**Audit notes.** ThreatFox can return error statuses (for example `invalid_auth_key`,
`illegal_search_term`, `too_many_requests`) which are also `query_status !== "no_result"`.
Those become `status: "success"`, and the `Severity` node then treats `tf.status ===
"success"` as a confirmed IOC hit and forces CRITICAL. ThreatFox itself contributes zero
to the risk score. See H-05.

---

## 8. Grey Noise

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| URL | `=https://api.greynoise.io/v3/community/{{$json.source_ip}}` |
| Headers | `key: REPLACE_WITH_GREYNOISE_API_KEY` |
| Options | `response.response.neverError: true` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Community API lookup for the source IP. `neverError` converts non-2xx
responses into data rather than node errors.

**Output shape used by the aggregator:** `classification`, `noise`, `riot` at the top
level. A `malicious` classification adds 30 risk points.

**Audit notes.** No method is set, so the node defaults to GET. The URL is built from an
alert-derived value without validation. `noise` and `riot` are booleans in the API
response but are passed through unchanged.

---

## 9. AbuseIPDB

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| URL | `https://api.abuseipdb.com/api/v2/check` |
| Query | `ipAddress = {{ $json.ioc?.public_ips?.[0] ?? $json.source_ip ?? null }}`, `maxAgeInDays = 90` |
| Headers | `Accept: application/json`, `key: REPLACE_WITH_ABUSEIPDB_API_KEY` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Abuse confidence score, reports, ISP, country and TOR status.

**Output shape used by the aggregator:** `data.abuseConfidenceScore`,
`data.totalReports`, `data.isTor`, `data.countryCode`, `data.countryName`, `data.isp`,
`data.domain`.

**Audit notes.** The query expression reads `$json.ioc.public_ips`, but `IOC Routing`
overwrites `ioc` with `{ type, value }` — there is no `public_ips` array at that point.
The expression therefore falls back to `$json.source_ip`. For hash-only alerts this can
be `null`. The aggregator contains a 249-entry ISO country-code map so the report can
show country names.

---

## 10. OTX

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| URL | `=https://otx.alienvault.com/api/v1/indicators/IPv4/{{$json.source_ip}}/general` |
| Headers | `X-OTX-API-KEY: REPLACE_WITH_OTX_API_KEY` |
| Flags | `continueRegularOutput`, `alwaysOutputData: true` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** AlienVault OTX pulse count for the IP.

**Output shape used by the aggregator:** `pulse_info.count`. More than zero pulses adds
15 risk points.

**Audit notes.** The URL is IPv4-specific. A hash or domain IOC cannot be queried.
`alwaysOutputData` means an empty item may still be emitted on failure, which the
aggregator silently ignores.

---

## 11. virus total

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| URL | `=https://www.virustotal.com/api/v3/ip_addresses/{{$json.ioc.value}}` |
| Headers | `x-apikey: REPLACE_WITH_VIRUSTOTAL_API_KEY` |
| Flags | `continueRegularOutput`, `alwaysOutputData: true` |

**Purpose.** IP reputation and last-analysis statistics.

**Output shape used by the aggregator:** `data.attributes.last_analysis_stats`
(`malicious`, `suspicious`, `harmless`, `undetected`) and `data.attributes.reputation`.
`malicious >= 10` adds 25 points; `malicious > 0` adds 15.

**Audit notes.** The endpoint is hard-coded to `ip_addresses`. When the verified IOC is a
hash or URL, the node queries `/ip_addresses/<hash>` and will not produce useful data.
The node name is lower-case with a space; the sanitizer matches it exactly.

---

## 12. Leakix

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| URL | `=https://leakix.net/host/{{$json.source_ip}}` |
| Headers | `accept: application/json`, `api-Key: REPLACE_WITH_LEAKIX_API_KEY` |
| Flags | `continueRegularOutput`, `retryOnFail: true` (no `maxTries` configured) |

**Purpose.** Exposed-service discovery for the host.

**Output shape expected by the aggregator:** top-level `services`, `summary` or `host`;
`services` must be an array.

**Audit notes.** The LeakIX `/host/` response is not guaranteed to be a flat object with
a `services` array. If the response is an array or a differently shaped object, the
success branch is not entered, and `status` stays `not_checked`. Error detection only
checks `data.error` with `ETIMEDOUT` or a message containing "leakix"; other HTTP errors
are not mapped to `unavailable`. `retryOnFail` has no explicit maximum.

---

## 13. Merge1

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.merge` v3.2 |
| Parameters | `{ "numberInputs": 6 }` |
| Mode | Default (Append) |

**Purpose.** Fan-in for the six provider responses. Inputs are assigned:
0 Threat Fox, 1 Grey Noise, 2 AbuseIPDB, 3 OTX, 4 virus total, 5 Leakix.

**Audit notes.** Append mode waits for all connected inputs and emits their items
sequentially. Provider identity is lost, so `TI Aggregator` must infer it from response
shape. No `alwaysOutputData`, no clash handling, no SQL query.

---

## 14. TI Aggregator

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 533 |
| Retry | 3 attempts |

**Purpose.** Collapse all provider items into one enrichment object.

**Inputs.** `$input.all()` plus a cross-node lookup:
`$('IOC Extraction').first().json` for the original alert. The lookup is wrapped in
`try/catch` and falls back to `{}`.

**Base result.** `original_alert`, `rule_id`, `raw_log`, `rule_level`, `agent_name`,
`description`, `source_ip`, `ioc`, a six-provider `threat_intelligence` skeleton with
`status: not_checked`, `risk_score: 0`, `provider_coverage: 0`,
`assessment_confidence: LOW`, `evidence`, `sources`.

**Provider shape detectors:**

| Provider | Detector | Fields parsed |
|---|---|---|
| GreyNoise | `classification`/`noise`/`riot` present | classification, noise, riot |
| AbuseIPDB | `data.abuseConfidenceScore` present | confidence, reports, tor, country, ISP, domain |
| VirusTotal | `data.attributes` present | reputation, malicious, suspicious, harmless, undetected |
| OTX | `pulse_info` present | pulses |
| ThreatFox | `query_status` present | status (`no_result` vs anything else), result |
| LeakIX | `services`/`summary`/`host` present | services, error |

**Risk weights:**

| Signal | Points |
|---|---:|
| GreyNoise `malicious` | +30 |
| AbuseIPDB score ≥ 80 | +30 |
| AbuseIPDB score ≥ 50 | +15 |
| AbuseIPDB score > 0 | +5 |
| VirusTotal malicious ≥ 10 | +25 |
| VirusTotal malicious > 0 | +15 |
| OTX pulses > 0 | +15 |
| ThreatFox hit | **0** |
| LeakIX services | **0** |

Score is clamped to 0–100. Confidence is HIGH/MEDIUM/LOW for 3/2/1 malicious signals.
`severity` is derived from the risk score (≥80 CRITICAL, ≥50 HIGH, ≥25 MEDIUM, else LOW).
`provider_coverage` is the percentage of providers whose status is `success`,
`no_result` **or `unavailable`**. `provider_failures` is a list of array indices of
providers with `status: "unavailable"`.

**Audit notes.** H-05 (ThreatFox errors → CRITICAL via Severity), M-03 (indices instead of
provider names, `unavailable` counted as checked), M-04 (LeakIX shape/errors), M-09
(provider errors are usually n8n error items, not `data.error`).

---

## 15. TI Normalizer

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 96 |
| Retry | 3 attempts |

**Purpose.** Convert the aggregator's flat result into three nested objects:

- `alert` — original alert, rule ID, raw log, rule level, agent, description, source IP,
  severity, risk score, IOC.
- `threat_intelligence` — six providers with normalized field names. Notably
  `abuseipdb.confidence_score` comes from `abuseipdb.confidence`, and
  `abuseipdb.total_reports` from `abuseipdb.reports`.
- `assessment` — risk score, severity, confidence, malicious evidence, evidence list,
  provider coverage, provider failures.

Also passes through `sources`.

**Audit notes.** This node is a pure reshape with `??` defaults; it does not validate.
The `status` field is preserved, so an `unavailable` LeakIX status flows into the
`Severity` node's `leakixUnavailable` factor.

---

## 16. External Incident

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 47 |
| Retry | 3 attempts |

**Purpose.** Wrap the normalized result into the common `{ incident: ... }` schema so
both branches can feed Merge2.

**Fields:** `original_alert`, `rule_id`, `raw_log`, `source_ip`, `agent_name`,
`rule_level`, `description`, `severity`, `risk_score`, `ioc`, `analysis_type: "external"`,
`internal_analysis: null`, `threat_intelligence`, `assessment`, `summary: null`,
`recommendation: null`.

**Audit notes.** `assessment.verdict` is **not** copied here, so the verdict set later by
`TI Corroboration & Scoring` is the first verdict assigned in the external path.

---

## 17. Internal Analysis

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 52 |
| Retry | 3 attempts |

**Purpose.** Extract host-centric context for the internal branch.

**Reads:** `data.body` (object) or `data.original_alert` or `data`. Then `alert.rule`,
`alert.data`.

**Extracts:** `user` (`srcuser`/`user`), `target_user` (`dstuser`/`target_user`),
`command`, and MITRE arrays (`rule.mitre.id`, `.tactic`, `.technique`), coercing single
values into arrays.

**Output:** spread of the input plus `analysis_type: "internal"`, an `alert` object with
`original_alert`, an `ioc` fallback, and `internal_analysis` with `required: true`,
`rule_id`, user, target user, command and MITRE.

**Audit notes.** `source_ip` defaults to the literal `127.0.0.1`, and `agent_name`
defaults to `blusoc`. Those defaults can appear in the final report and the Laya payload
if the Wazuh alert lacks the fields.

---

## 18. Internal Incident

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 51 |
| Retry | 3 attempts |

**Purpose.** Build the same `{ incident }` schema as the external branch.

**Severity:** `>=15 CRITICAL`, `>=12 HIGH`, `>=8 MEDIUM`, else `LOW`.
**Risk score:** 90 / 70 / 40 / 10 to match.
**Assessment:** confidence `HIGH`, `provider_coverage: 0`, `has_malicious_evidence:
false`, empty malicious sources and failures, one evidence string, and verdict
`INTERNAL_SECURITY_EVENT`.

Also generates a `summary` and a `recommendation` about verifying user authorization,
inspecting audit logs and least privilege.

**Audit notes.** The verdict here is later overwritten by `TI Corroboration & Scoring`
for internal alerts with rule level < 10 (`BENIGN_INTERNAL_EVENT`). The severity here is
later overwritten twice.

---

## 19. Merge2

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.merge` v3.2 |
| Parameters | `{}` |
| Mode | Default (Append), 2 inputs |

**Purpose.** Rejoin the external (input 0) and internal (input 1) incident objects.

**Audit notes.** See the runtime-verification note in
[02 — Architecture](02-architecture.md). Because Append waits for all connected inputs
and no `alwaysOutputData` is set, behaviour when only one IF branch produces data must be
confirmed in the deployed n8n version.

---

## 20. TI Corroboration & Scoring

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 87 |
| Retry | 3 attempts |

**Purpose.** "Secondary determination": assign the assessment verdict and a severity.

**Logic:**

1. If `ruleLevel < 7` and no malicious evidence → `BENIGN_TELEMETRY`, confidence HIGH,
   severity LOW, stop.
2. If `analysis_type === 'internal'` → verdict `INTERNAL_SECURITY_EVENT` when level ≥ 10
   else `BENIGN_INTERNAL_EVENT`; severity CRITICAL ≥12, HIGH ≥10, MEDIUM ≥8, else LOW.
3. External with malicious evidence or risk ≥ 50 → `TRUE_POSITIVE_THREAT`, severity
   CRITICAL if risk ≥ 80 or level ≥ 12, else HIGH; confidence HIGH if ≥2 malicious
   sources.
4. Otherwise → `UNCORROBORATED_OR_TRAINING`, confidence LOW, severity HIGH ≥12,
   MEDIUM ≥8, else LOW; appends an evidence string.

Always writes `incident.laya_verification` with stage, verdict, confidence, rule level,
risk score and timestamp.

**Audit notes.** The node's header comment calls it "LAYA - METRIC & THREAT
VERIFICATION", but it is purely deterministic JavaScript; it does not call the Laya
engine. Its severity output is overwritten by `Severity` downstream.

---

## 21. Incident Summary

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 641 |
| Retry | 3 attempts |

**Purpose.** Rebuild the incident with a consistent, defensive schema using `safeString`,
`safeArray` and `safeNumber` helpers.

**Preserves** severity if the incoming incident already has one; otherwise derives it from
the rule level (≥15 CRITICAL, ≥12 HIGH, ≥8 MEDIUM, else LOW) and raises the risk score to
at least 90/70/40/10. It also builds a `threat_intelligence` object that keeps both
`abuseipdb.confidence_score` and `abuseipdb.score` for compatibility with the Telegram
expression.

**Audit notes.** The returned object declares `rule_id`, `original_alert` and `raw_log`
**twice** (for example lines 581–582 and 609–611). The later declarations overwrite the
earlier ones, discarding the fallback expressions. JavaScript object literals silently
allow duplicate keys; there is no lint rule to catch it. See M-05.

---

## 22. Severity

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 219 |
| Retry | 3 attempts |

**Purpose.** Final severity, overriding `incident.severity` from corroboration.

**Inputs.** `rule_level`, `risk_score`, and six provider objects from
`incident.threat_intelligence`.

**Base:** LOW; ≥15 CRITICAL, ≥12 HIGH, ≥8 MEDIUM.

**Escalations:**

| Rule | Condition | Result |
|---|---|---|
| Strong correlated evidence | risk ≥ 80 and ≥3 malicious sources | CRITICAL |
| Confirmed ThreatFox IOC | `tf.status === "success"` | CRITICAL |
| Malware consensus | VT malicious ≥ 10 and ≥2 sources | CRITICAL |
| Significant TI evidence | not CRITICAL, risk ≥ 50, ≥2 sources | HIGH |
| Single strong signal | severity is LOW and abuse ≥80 / VT ≥1 / grey malicious / OTX >0 | HIGH |
| Trusted ISP | ISP contains Google LLC, Cloudflare, Microsoft, Amazon or Akamai **and** no malicious evidence | HIGH / MEDIUM / LOW by rule level |

It returns `severity` and a `severity_factors` object with rule level, risk score,
abuse score, VT counts, GreyNoise classification/noise, ThreatFox hit, OTX pulses,
corroborating sources, malicious source names, trusted ISP flag and
`leakix_unavailable`.

**Audit notes.** `threatFoxHit` is `tf.status === "success"`, which is set for any
non-`no_result` `query_status`, including errors. A trusted-ISP match can **downgrade**
a CRITICAL rule-level-15 alert to HIGH. The final severity overrides the corroboration
node: an internal level 10–11 alert becomes MEDIUM rather than HIGH, and a level 12–14
alert becomes HIGH rather than CRITICAL. See H-03, H-05.

---

## 23. Final Report

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 246 |
| Retry | 3 attempts |

**Purpose.** Produce the analyst report and the DFIR-IRIS payload.

**`buildSceneLines(a)`** extracts up to ~25 scene lines from the original alert: sensor
and agent, rule ID/level/description/groups, source and destination IP/port/protocol,
Suricata signature and metadata (CVE, tags, MITRE), HTTP request and user agent, flow
byte counts, account, command, process and parent process, command line, file hash, file
path, Office 365 operation, vulnerability, MITRE ATT&CK, log location, and a truncated
raw event (1,400 characters).

**Report object:** agent name, scene lines, raw alert, `srcuser`, Wazuh alert ID, rule ID,
rule level, description, source IP, IOC, severity, risk score, analysis type,
threat intelligence, internal analysis, assessment, summary and recommendation.

**External description** includes a threat-intelligence scorecard (AbuseIPDB,
VirusTotal, GreyNoise, OTX, ThreatFox). **Internal description** includes user, target
user, command and MITRE.

**IRIS payload:**

| Field | Value |
|---|---|
| `alert_title` | `[SOAR {severity}] {description} on {agent}` |
| `alert_description` | full `descriptionText` |
| `alert_source` | `Wazuh-SOAR` |
| `alert_source_ref` | `soar-{ruleId}-{agent}-{sourceIp || (d.srcuser \|\| 'local')}` |
| `alert_severity_id` | CRITICAL 6, HIGH 5, MEDIUM 1, LOW 4 |
| `alert_status_id` | 1 |
| `alert_customer_id` | 1 |
| `alert_tags` | `wazuh,soar_enriched,rule_{id},{type},{severity}` |

**Critical defect.** On line 231 the fallback `d.srcuser` references an undefined
identifier `d`. The `||` short-circuits only when `sourceIp` is truthy; when the source
IP is falsy (very common for internal alerts), evaluating the fallback throws
`ReferenceError: d is not defined`, and report generation fails. The node retries three
times and then fails the execution. See C-03.

**Other audit notes.** IRIS severity IDs are non-monotonic (MEDIUM = 1, LOW = 4);
`alert_customer_id` is hard-coded; `alert_source_ref` has no timestamp, so repeated
alerts for the same rule/agent/IP collide. By contrast, the sample Wazuh alert ID and
`sceneLines` are genuinely detailed and useful.

---

## 24. Laya Decision Gate

| Property | Value |
|---|---|
| Type | Code v2 |
| Lines | 136 |
| Retry | 3 attempts |

**Purpose.** Ask the Laya engine for an authoritative decision, stop non-escalated
incidents, and stamp the IRIS payload with the decision record.

**Helpers.** `firstStr` and `firstNum` pick the first usable value from a list of
fallbacks, rejecting empty strings and the literal strings `undefined` / `null`.

**Triage payload** (14 fields): `timestamp`, `host`, `vendor`, `rule_id`, `rule_level`,
`description`, `source_ip`, `srcuser`, `severity`, `risk_score`, `threat_intelligence`,
`assessment`, `groups`, `raw_alert`.

**Call.** `await fetch('http://REPLACE_WITH_LAYA_HOST:9999/api/triage', { method: POST,
headers: Content-Type: application/json, body: JSON.stringify(triagePayload) })`, with a
fallback to `this.helpers.httpRequest` if `fetch` is unavailable. **No HMAC header, no
authorization header, no timestamp header, no nonce, no timeout.**

**Fail-safe.** On any exception:

```text
action   = ESCALATED if ruleLevel >= 8 or severity HIGH/CRITICAL, else CLOSED_NO_IMPACT
verdict  = ENGINE_UNAVAILABLE
confidence = 0.50
layer    = 4
stage    = "L4 Fail-Safe (engine unreachable)"
correlation_id = "lay-offline"
```

**Escalation path.** Reads `action ?? decision ?? 'ESCALATED'`. If not `ESCALATED`,
returns `[]` — no IRIS, Discord, Telegram, Slack or FortiGate. Otherwise it appends the
Laya decision record to `iris_payload` (title suffix, source ref, tags, description
block) and returns `laya_gate` with correlation ID, layer, verdict, confidence, reason,
stage, latency, model latency, `laya_model_used`, `policy_version` and `evaluated_at`.

**Audit notes.** n8n's official Code node documentation states Code nodes cannot make
HTTP requests. The `fetch` path and the `this.helpers.httpRequest` fallback are both
unsupported in that runtime. Unless the deployment has explicitly enabled an unusual
capability, the call will throw and the fail-safe will run for every alert. `raw_alert`
sends the full Wazuh log to the engine over plain HTTP. Top-level `await` also fails a
plain CommonJS `node --check` (see [04 — Code audit](04-code-audit.md)).

**Findings.** C-02, M-07.

---

## 25. DFIR-IRIS Alert

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| Method | `POST` |
| URL | `https://REPLACE_WITH_IRIS_HOST/alerts/add` |
| Headers | `Authorization: Bearer REPLACE_WITH_DFIR_IRIS_API_TOKEN`, `Content-Type: application/json` |
| Body | `={{ JSON.stringify($json.iris_payload) }}` |
| Options | `allowUnauthorizedCerts: true` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Create the case record. The returned `alert_id` is read by Discord,
Telegram and Slack expressions through `$('DFIR-IRIS Alert').first().json.data.alert_id`.

**Audit notes.** TLS verification is disabled, so the bearer token is exposed to a
man-in-the-middle. The original export used `https://127.0.0.1/alerts/add`, which on a
containerised n8n instance points at the n8n container itself — another likely reason
case creation fails. Sanitisation replaced it with a host placeholder. No idempotency key
is sent, so retries can create duplicate cases.

---

## 26. Discord Alert

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| Method | `POST` |
| URL | `https://discord.com/api/webhooks/REPLACE_WITH_DISCORD_WEBHOOK_ID/REPLACE_WITH_DISCORD_WEBHOOK_TOKEN` |
| Body | JSON embed built in an expression |
| Options | `neverError: true`, `responseFormat: text` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Post a rich embed after IRIS case creation.

**Embed fields.** Severity, Confidence (`gate.confidence * 100` rounded), Decision layer
(`L{layer}` plus stage), Host, Rule with level, Verdict. For internal alerts it adds
Account, Command and MITRE ATT&CK. For external alerts it adds Source IP and TI
scorecard fields. Colours: CRITICAL `0xB91C1C`, HIGH `0xDC2626`, MEDIUM `0xB45309`,
LOW `0x1D4ED8`. An IRIS link is built from the returned `alert_id`.

**Audit notes.** The original expression contained a private IRIS host in the link; the
sanitizer replaced it. `neverError` plus `continueRegularOutput` means a Discord failure
is invisible to the workflow.

---

## 27. Severity Confirmation

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.if` v2.3 |
| Conditions | `$json.severity` equals `HIGH` **or** equals `CRITICAL` |
| Combinator | `or` |
| Options | `caseSensitive: true`, `typeValidation: strict`, `version: 3` |

**Outputs.** True (index 0) → `Is Public IP?`. False (index 1) → **unconnected**.

**Audit notes.** MEDIUM and LOW escalated incidents still get IRIS/Discord/Telegram/Slack,
but they skip the entire containment branch. The condition compares against the severity
set by the `Severity` node (upper-cased by `Final Report`/`Laya Decision Gate`), so the
case-sensitivity setting is consistent.

**Finding.** H-02.

---

## 28. Is Public IP?

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.if` v2 |
| Condition | `$json.report.source_ip` matches regex `^(?!(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.|224\.|::1$|f[cd]|fe80)).+` |
| Operator | string regex |
| Options | `caseSensitive: true`, `typeValidation: strict`, `version: 2` |

**Purpose.** Only public source IPs should reach FortiGate.

**Outputs.** True (index 0) → FortiGate. False (index 1) → **unconnected**.

**Audit notes.** The negative lookahead rejects RFC1918, loopback, link-local, `0/8`,
`224/8` and a few IPv6 prefixes. It does **not** reject CGNAT `100.64/10`, documentation
ranges `192.0.2/24`/`198.51.100/24`/`203.0.113/24`, `198.18/15`, `255.255.255.255`,
or non-IP strings such as `N/A`. A missing source IP will not match (the `.+` requires
at least one character after the negative lookahead, so `'N/A'` actually does match and
would be treated as public). The condition reads `report.source_ip`, which defaults to
the string `N/A` in `Final Report` — so an internal alert with no IP could still pass
this check.

**Finding.** H-02, L-02.

---

## 29. FortiGate HTTP Request node

| Property | Value |
|---|---|
| Type | HTTP Request v4.4 |
| URL | `https://REPLACE_WITH_FORTIGATE_HOST:11443/api/v2/cmdb/firewall/address?vdom=root` |
| Method | **not set → defaults to GET** |
| Headers | `Authorization: Bearer REPLACE_WITH_FORTIGATE_API_TOKEN`, `Content-Type: application/json` |
| Body | `={"name":"SOC_{{$json.report.source_ip}}","subnet":"{{$json.report.source_ip}} 255.255.255.255","comment":"Generated by SOC Automation | Severity: {{$json.report.severity}}"}` |
| Options | `allowUnauthorizedCerts: true` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Intended containment by adding the source IP as a firewall address object.

**What it actually does.** With no `method` parameter, the HTTP Request node defaults to
GET. The configured JSON body is therefore not sent as a POST/PUT. Even if it were, the
workflow only creates an **address object**; it does not add the object to an address
group, create a firewall policy, deny traffic, or verify the result. No deletion or
rollback path exists.

**Audit notes.** The body is assembled as a JSON *string* from alert-derived values
without escaping. A crafted `source_ip` containing quotes could break the JSON or inject
additional fields. TLS verification is disabled. There is no idempotency check, so
repeated alerts attempt to create `SOC_<ip>` repeatedly. The FortiGate credential in the
raw export was a hard-coded bearer token.

**Findings.** H-01, M-09, L-03.

---

## 30. Send a text message (Telegram)

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.telegram` v1.2 |
| Credential | `telegramApi` ("Telegram account") — ID removed by sanitisation |
| `chatId` | `REPLACE_WITH_TELEGRAM_CHAT_ID` |
| `text` | Large `={{ ... }}` expression |
| `additionalFields` | `appendAttribution: false`, `parse_mode: HTML` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Send a detailed HTML report to a Telegram chat. Internal and external
messages are generated by separate template branches. HTML escaping is applied through
an `esc()` helper for `&`, `<` and `>`; arrays are escaped and joined with `join()`.

**Content.** Severity, agent, rule level, description, internal analysis (rule ID, user,
target user, command, MITRE IDs/tactics/techniques) or external TI (AbuseIPDB,
VirusTotal, OTX, GreyNoise, ThreatFox, LeakIX), assessment, risk score, confidence,
summary, recommendation, and an alert-ID line with the Laya correlation ID and IRIS case
number.

**Critical formatting defect.** The internal branch begins with:

```js
return `SOC INCIDENT REPORT' + idLine + '
```

The `' + idLine + '` is **literal text inside the template literal**, not string
interpolation. `idLine` (the Alert ID / IRIS case line) is never rendered, and the
message contains stray quote characters. See M-06.

**Audit notes.** The report heading is `SOC INCIDENT REPORT` in the internal branch, but
`*SOC INCIDENT REPORT*` in Slack and a bold-ish heading in Discord; formatting differs
across channels. `parse_mode: HTML` with only partial escaping means unescaped
user-controlled values can break rendering.

---

## 31. Slack

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.slack` v2.5 |
| Credential | `slackApi` ("Slack account") — ID removed by sanitisation |
| `select` | `channel` |
| `channelId` | `#security-reports` (mode `name`) |
| `text` | Large `={{ ... }}` expression |
| `otherOptions` | `{}` |
| Error behaviour | `continueRegularOutput` |

**Purpose.** Post a Markdown-style report to `#security-reports`.

**Content.** Severity, agent, rule level, description; internal branch adds rule ID,
user, target user, command and MITRE; external branch adds Source IP and a short TI
scorecard; then risk score, confidence, summary and recommended action. A `truncate()`
helper caps fields at 3,500 characters. An `idLine` with the Laya correlation ID and IRIS
case ID is computed and included in the message expression.

**Audit notes.** No Slack mrkdwn escaping is applied to alert-derived values, so `<`,
`&`, `@here` or `@channel` sequences from an alert could change the rendered message or
trigger mentions. The channel name is hard-coded. `truncate()` is defined but only used
on some fields. `continueRegularOutput` hides delivery failures.

---

## 32. Cross-cutting configuration observations

| Observation | Applies to | Impact |
|---|---|---|
| `retryOnFail: true, maxTries: 3, waitBetweenTries: 3000` | All 13 Code nodes | Deterministic logic bugs are retried three times before failing; adds 6–9 s latency on failure |
| `onError: continueRegularOutput` + `continueOnFail: true` | 9 HTTP nodes, Telegram, Slack | Failures become error items; downstream Code nodes may receive unexpected shapes |
| `alwaysOutputData: true` | virus total, OTX | Empty items may reach Merge1/aggregator |
| `allowUnauthorizedCerts: true` | DFIR-IRIS, FortiGate | Bearer tokens exposed to MITM |
| No `notes` on any node | All 31 | No in-canvas documentation |
| No `webhookId` in sanitized export | Webhook | Regenerated on import; safe |
| No credential IDs in sanitized export | Telegram, Slack, HTTP nodes | Must be recreated on import |
| No error workflow in sanitized export | Workflow settings | Unhandled failures have no global handler |

---

## 33. Related documents

- [04 — Code audit](04-code-audit.md) for line-level JavaScript review.
- [05 — Data flow](05-data-flow.md) for item shapes after each node.
- [07 — IOC and threat intelligence](07-ioc-and-threat-intelligence.md) for provider detail.
- [10 — Notifications and response](10-notifications-and-response.md) for payload detail.
- [16 — Audit report](16-audit-report.md) for the findings register.
