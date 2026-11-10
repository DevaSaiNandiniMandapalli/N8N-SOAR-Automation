# 10 — Notifications and Response Actions

| Item | Value |
|---|---|
| Document | DFIR-IRIS, Discord, Telegram, Slack and FortiGate integrations |
| Version | 1.0 |
| Date | 2026-11-10 |
| Nodes covered | DFIR-IRIS Alert, Discord Alert, Send a text message, Slack, Severity Confirmation, Is Public IP?, FortiGate HTTP Request node |

---

## 1. Response fan-out

```mermaid
flowchart TD
    LG["Laya Decision Gate<br/>ESCALATED"] --> IRIS["DFIR-IRIS Alert<br/>POST /alerts/add"]
    LG --> SC["Severity Confirmation"]
    LG --> TG["Send a text message<br/>Telegram"]
    LG --> SL["Slack"]
    IRIS --> DC["Discord Alert<br/>embed with case link"]
    SC -->|"true: HIGH / CRITICAL"| IP{"Is Public IP?"}
    SC -->|"false: unconnected"| X1["branch ends"]
    IP -->|"true"| FGT["FortiGate HTTP Request node"]
    IP -->|"false: unconnected"| X2["branch ends"]
```

| Channel | Trigger | Reads from other nodes | On failure |
|---|---|---|---|
| DFIR-IRIS | Laya escalation | `$json.iris_payload` | `continueRegularOutput` |
| Discord | IRIS completes | `$('DFIR-IRIS Alert')`, `$('Final Report')`, `$json.laya_gate` | `neverError` + `continueRegularOutput` |
| Telegram | Laya escalation | `$('Final Report')`, `$('DFIR-IRIS Alert')`, `$json.laya_gate` | `continueRegularOutput` |
| Slack | Laya escalation | `$('Final Report')`, `$('DFIR-IRIS Alert')`, `$json.laya_gate` | `continueRegularOutput` |
| FortiGate | HIGH/CRITICAL and public IP | `$json.report` | `continueRegularOutput` |

All notification nodes use `onError: continueRegularOutput`. A failed notification does
not stop the workflow, does not create an error case, and does not notify an operator.
Only n8n execution history records it.

---

## 2. DFIR-IRIS Alert

| Property | Value |
|---|---|
| Method | `POST` |
| URL | `https://REPLACE_WITH_IRIS_HOST/alerts/add` |
| Headers | `Authorization: Bearer REPLACE_WITH_DFIR_IRIS_API_TOKEN`, `Content-Type: application/json` |
| Body | `={{ JSON.stringify($json.iris_payload) }}` |
| TLS | `allowUnauthorizedCerts: true` |

### Payload fields

| Field | Source | Notes |
|---|---|---|
| `alert_title` | `[SOAR {severity}] {description} on {agent}` | Laya gate appends `[Laya {verdict}]` |
| `alert_description` | Full report description text | Includes scene lines, TI scorecard and log excerpt |
| `alert_source` | `Wazuh-SOAR` | Constant |
| `alert_source_ref` | `soar-{ruleId}-{agent}-{sourceIp}` | Laya gate appends `|{correlation_id}` |
| `alert_severity_id` | 6 / 5 / 1 / 4 | Non-monotonic; see [08](08-correlation-and-severity.md) |
| `alert_status_id` | `1` | Hard-coded |
| `alert_customer_id` | `1` | Hard-coded |
| `alert_tags` | `wazuh,soar_enriched,rule_{id},{type},{severity}` | Laya gate appends `laya,{layer},{verdict},{cid}` |

### Decision record appended by the Laya gate

```text
[LAYA DECISION RECORD]
Correlation ID : <cid>
Decision layer : L<layer>  <stage>
Verdict        : <verdict>
Confidence     : <percent>%
Decided by     : Laya System 1 decision engine neural model | deterministic guardrail
Engine latency : <ms> ms
Reason         : <reason>
```

### Issues

- **TLS verification disabled.** The bearer token and the full incident description are
  exposed to a man-in-the-middle.
- **No idempotency key.** A retried execution can create duplicate cases.
- **Hard-coded IDs.** Customer, status and severity IDs should come from configuration.
- **Alert ID race.** Telegram and Slack run in parallel with IRIS and read
  `$('DFIR-IRIS Alert').first().json.data.alert_id`. If they evaluate before IRIS
  completes, the case ID is `null` even though the case is created.
- Original export used `https://127.0.0.1/alerts/add`, which from inside a container
  points at the container itself. The sanitized version uses a host placeholder.

---

## 3. Discord Alert

| Property | Value |
|---|---|
| Method | `POST` |
| URL | Discord webhook placeholder |
| Body | Expression-built JSON embed |
| Options | `neverError: true`, `responseFormat: text` |
| Error behaviour | `continueRegularOutput` |

### Embed structure

| Element | Content |
|---|---|
| Colour | CRITICAL `0xB91C1C`, HIGH `0xDC2626`, MEDIUM `0xB45309`, LOW `0x1D4ED8` |
| Field: Severity | upper-cased final severity |
| Field: Confidence | `Math.round(gate.confidence * 100)%` |
| Field: Decision layer | `L{layer}` plus stage, or `n/a` |
| Field: Host | agent name |
| Field: Rule | rule ID and level |
| Field: Verdict | verdict with underscores replaced by spaces |
| Internal-only fields | Account, Command, MITRE ATT&CK IDs |
| External-only fields | Source IP and TI scorecard values |
| Link | IRIS case URL built from `alert_id` |

The expression reads `$('DFIR-IRIS Alert').first()?.json?.data?.alert_id` inside a
`try/catch`, so a missing case ID degrades to the generic IRIS URL. The original
expression contained a private IRIS host; the sanitizer replaced it with
`REPLACE_WITH_IRIS_HOST`.

### Issues

- Webhook URL was hard-coded in the raw export — a credential that must be rotated.
- `neverError` plus `continueRegularOutput` hides delivery failures completely.
- No mention control or rate-limit handling for Discord's 429 responses.
- The IRIS link is a convenience link, not a verified deep link into the case.

---

## 4. Send a text message (Telegram)

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.telegram` v1.2 |
| Credential | `telegramApi` (name retained, ID removed) |
| `chatId` | `REPLACE_WITH_TELEGRAM_CHAT_ID` |
| Parse mode | `HTML` |
| `appendAttribution` | `false` |

### Message structure

Both branches include severity, agent, rule level, description, assessment (risk score,
confidence), summary and recommendation.

| Branch | Additional sections |
|---|---|
| Internal | Rule ID, User, Target User, Command, MITRE ATT&CK IDs, Tactics, Techniques |
| External | Threat-intelligence scorecard (AbuseIPDB, VirusTotal, OTX, GreyNoise, ThreatFox, LeakIX) |

An `esc()` helper escapes `&`, `<` and `>` and a `join()` helper escapes array values.
An `idLine` is computed with the Laya correlation ID and the IRIS case number.

### Defect: literal string instead of interpolation (M-06)

The internal branch starts with:

```js
const idLine = '\nAlert ID: ' + (gate.correlation_id || 'n/a') + (irisId ? ('  |  IRIS case: #' + irisId) : '');
return `SOC INCIDENT REPORT' + idLine + '\n\nSeverity: ...`;
```

`' + idLine + '` is plain text inside a template literal. The computed ID line is never
inserted, and the message begins with stray quote/plus characters. The external branch
uses correct `${...}` interpolation, so only internal Telegram reports are affected.

### Other issues

- `parse_mode: HTML` with partial escaping. Only some fields pass through `esc()`;
  escaped values are used inconsistently across the message.
- Chat ID was hard-coded in the raw export.
- No message-length guard beyond whatever Telegram enforces; a long `full_log` could push
  the report over Telegram's limit.
- `continueRegularOutput` means an invalid chat ID or revoked bot token fails silently.

---

## 5. Slack

| Property | Value |
|---|---|
| Type | `n8n-nodes-base.slack` v2.5 |
| Credential | `slackApi` (name retained, ID removed) |
| Channel | `#security-reports` (mode `name`) |
| `otherOptions` | `{}` |

### Message structure

```text
*SOC INCIDENT REPORT*

*Severity:* ...  *Agent:* ...  *Rule Level:* ...  *Description:* ...

[internal] *INTERNAL ANALYSIS* (rule ID, user, target user, command, MITRE)
[external] *SOURCE IP* + TI scorecard (AbuseIPDB, VirusTotal, GreyNoise, OTX)

*ASSESSMENT* (risk score, confidence)
*SUMMARY* ...
*RECOMMENDED ACTION* ...
```

A `truncate(text, max = 3500)` helper is defined and a `idLine` with the Laya correlation
ID and IRIS case ID is computed. The message is returned from the expression.

### Issues

- No Slack mrkdwn escaping. Alert-derived `<`, `&`, `@here` and `@channel` sequences can
  change rendering or trigger mentions.
- `truncate()` is not applied consistently to all fields.
- Channel is hard-coded.
- `continueRegularOutput` hides delivery failures.
- The `idLine` variable is included in the message expression but its exact placement is
  harder to verify than in Telegram because the full expression is one long string.

---

## 6. Severity Confirmation and Is Public IP?

### Severity Confirmation

Two conditions combined with `or`: `$json.severity` equals `HIGH` or `CRITICAL`.
`typeValidation: strict`, `caseSensitive: true`.

- **True output** → `Is Public IP?`.
- **False output** → **no connection**. MEDIUM and LOW escalated incidents skip the entire
  containment branch with no explicit "containment not required" record.

### Is Public IP?

Regex on `$json.report.source_ip`:

```text
^(?!(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.|224\.|::1$|f[cd]|fe80)).+
```

| Range | Excluded? |
|---|---|
| `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `0/8`, `224/8` | Yes |
| `::1`, `fc00::/7`, `fe80::/10` (string prefix) | Yes |
| `100.64/10` CGNAT | **No** |
| `192.0.2/24`, `198.51.100/24`, `203.0.113/24` documentation | **No** |
| `198.18/15` benchmarking | **No** |
| `255.255.255.255` broadcast | **No** |
| Arbitrary string `N/A` | **No** — `.+` matches |

`Final Report` defaults a missing source IP to the literal string `"N/A"`, which would
pass this check. The regex also does not validate that the value is an IP address at all.

- **True output** → FortiGate.
- **False output** → **no connection**.

---

## 7. FortiGate HTTP Request node

| Property | Value |
|---|---|
| URL | `https://REPLACE_WITH_FORTIGATE_HOST:11443/api/v2/cmdb/firewall/address?vdom=root` |
| Method | **Not set → n8n defaults to GET** |
| Headers | `Authorization: Bearer REPLACE_WITH_FORTIGATE_API_TOKEN`, `Content-Type: application/json` |
| Body (intended) | `{"name":"SOC_{{$json.report.source_ip}}","subnet":"{{$json.report.source_ip}} 255.255.255.255","comment":"Generated by SOC Automation | Severity: {{$json.report.severity}}"}` |
| TLS | `allowUnauthorizedCerts: true` |
| Error behaviour | `continueRegularOutput` |

### What it actually does

1. **GET, not POST/PUT.** Because `method` is absent, the HTTP Request node uses its
   default GET. The configured `jsonBody` is not sent. At best the node retrieves the
   address list.
2. **Address object only.** Even if the method were corrected, the workflow creates a
   firewall address named `SOC_<ip>`. It does not:
   - add the object to an address group,
   - create or modify a firewall policy,
   - set an action of `deny`,
   - install the policy,
   - verify the result,
   - or provide a rollback/removal path.

**Creating an address object does not block traffic.** The advertised containment step is
not implemented. This is finding H-01.

### Additional issues

| Issue | Detail |
|---|---|
| TLS verification disabled | Bearer token exposed to MITM |
| JSON string interpolation | `source_ip` and `severity` inserted into a JSON string without escaping; a crafted value could break or inject fields |
| No idempotency | Repeated alerts attempt to create `SOC_<ip>` repeatedly |
| No result validation | `continueRegularOutput` accepts any response |
| Private IP path | Unconnected false output means private IPs skip containment entirely |
| Hard-coded credential | Bearer token was embedded in the raw export |

---

## 8. Response matrix

| Scenario | IRIS | Discord | Telegram | Slack | FortiGate |
|---|---|---|---|---|---|
| Laya not escalated | No | No | No | No | No |
| Escalated, CRITICAL, public IP | Yes | Yes | Yes | Yes | Attempted (GET) |
| Escalated, HIGH, public IP | Yes | Yes | Yes | Yes | Attempted (GET) |
| Escalated, MEDIUM or LOW | Yes | Yes | Yes | Yes | **No branch** |
| Escalated, HIGH, private/missing IP | Yes | Yes | Yes | Yes | **No branch** |
| Duplicate alert (dedup) | No | No | No | No | No |
| Final Report crash (C-03) | No | No | No | No | No |
| IRIS fails | No case | Discord still runs with generic link | Telegram/Slack may lack case ID | same | independent |

---

## 9. Recommendations

### 9.1 Notifications

1. Replace `continueRegularOutput` with an explicit error branch that records delivery
   failures in IRIS or a monitoring channel.
2. Serialise IRIS before the chat nodes (or use a Wait/Merge) so case IDs are available.
3. Escape all alert-derived values for HTML (Telegram) and mrkdwn (Slack).
4. Add a shared `renderIncident()` helper instead of three separate message templates.
5. Fix the Telegram internal-branch `idLine` interpolation.
6. Use a channel/routing configuration per severity instead of a hard-coded channel.
7. Call out the `@here`/`@channel` injection risk and escape `@` sequences.

### 9.2 Containment

1. Set `method: POST` (or `PUT` for idempotent upsert) on the FortiGate node.
2. Add the address object to a deny policy or quarantine group in a separate, explicit
   node.
3. Verify the response and the resulting policy.
4. Add an approval gate for destructive actions.
5. Add a rollback/removal path with an expiry.
6. Enable TLS verification and store the token in n8n credentials.
7. Use structured body construction rather than string interpolation.
8. Connect the false outputs of `Severity Confirmation` and `Is Public IP?` to an explicit
   "no containment required" logging node.

### 9.3 Idempotency and correlation

- Use `alert_source_ref` with a timestamp or Wazuh alert ID as an idempotency key for IRIS.
- Propagate one `correlation_id` through IRIS, Discord, Telegram, Slack and FortiGate.
- Record the `severity_factors` object in IRIS so analysts can audit why a severity was
  chosen.

---

## 10. Related documents

- [03 — Node reference](03-node-reference.md)
- [04 — Code audit](04-code-audit.md)
- [05 — Data flow](05-data-flow.md)
- [08 — Correlation and severity](08-correlation-and-severity.md)
- [09 — Hermes AI integration](09-hermes-ai-integration.md)
- [13 — Troubleshooting](13-troubleshooting.md)
- [16 — Audit report](16-audit-report.md)
