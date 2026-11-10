# Documentation assets

## Screenshots

No screenshots are included in this release.

Reason: the n8n instance requires authentication, and the workflow canvas and
execution views were not accessible without credentials. The Laya console was
reachable, but capturing it would have published live operational telemetry. No
screenshot was fabricated.

If you add screenshots later:

1. Use a dedicated test workflow and synthetic alerts only.
2. Remove or blur hostnames, usernames, IP addresses, rule IDs, case IDs,
   correlation IDs, webhook URLs and tokens.
3. Crop out the browser address bar and any bookmarks.
4. Re-run `python scripts/secret_scan.py --root .` after adding the image.
5. Prefer PNG or WebP; keep files below 500 KB.
6. Name files descriptively, for example `canvas-overview.png`.

## Diagrams

Mermaid source lives in `docs/diagrams/`. GitHub renders the diagrams embedded in
the Markdown documents. To export SVG locally:

```bash
npx @mermaid-js/mermaid-cli -i docs/diagrams/workflow-pipeline.mmd -o docs/assets/workflow-pipeline.svg
```
