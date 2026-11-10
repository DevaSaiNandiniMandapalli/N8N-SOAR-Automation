# Test fixtures

This repository uses two kinds of fixtures:

1. **Synthetic alert fixtures** in `workflows/samples/` — a Wazuh alert and the
   equivalent n8n webhook item. Both use RFC 5737 (`203.0.113.0/24`) and RFC 1918
   (`10.0.0.0/8`) documentation addresses. No real hosts, users, tokens or webhook URLs.
2. **Expected-value constants** declared inline in `tests/test_workflow.py` — node count,
   edge count, required node names, placeholder strings and the sanitisation report
   assertions.

No fixture contains credential material. No fixture is copied from the raw export.

To add a provider-response fixture:

- Use synthetic values only (documentation IPs, example domains, made-up pulse counts).
- Never paste a real provider response; it may contain account identifiers.
- Keep the file under `tests/fixtures/` and reference it from a unit test.
- Re-run `python scripts/secret_scan.py --root .` afterwards.
