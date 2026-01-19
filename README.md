# JSReconduit

JSReconduit is an offline-first bridge between Burp Suite and VSCode that captures JavaScript assets and surfaces findings for professional penetration testers.

## Components

- **Burp Suite Extension (Python/Jython)**: passively captures JavaScript responses and writes them to disk.
- **VSCode Extension (TypeScript)**: watches the capture directory, performs AST-based analysis, and renders findings in a sidebar panel.

## Repository Layout

- `burp-extension/jsreconduit_burp.py`
- `vscode-extension/`
- `examples/`

## Installation

### Burp Extension

1. In Burp, install Jython and set the Jython path in the Extender settings.
2. (Optional) Install `jsbeautifier` in the Jython environment for beautified output.
3. Load `burp-extension/jsreconduit_burp.py` as a Python extension.
4. Configure the output directory:

```bash
export JSRECONDUIT_BASE_DIR=~/burp-js-capture
```

Once loaded, use the **JSReconduit** tab inside Burp to edit settings and view capture logs. Settings are saved to `~/.jsreconduit/config.json` and override environment defaults on startup.

### Screenshots

<img width="1094" height="736" alt="image" src="https://github.com/user-attachments/assets/60479669-e22c-4cd1-b91b-c02371fe2daf" />

<img width="860" height="806" alt="image" src="https://github.com/user-attachments/assets/3ee49b3b-7adc-4e27-bbe9-f36b0121f3b2" />

<img width="464" height="670" alt="image" src="https://github.com/user-attachments/assets/6731aac9-a87b-43e2-9ab0-9d032a2d3665" />


#### Performance and behavior tuning

The Burp extension supports environment variables to reduce latency and control output:

- `JSRECONDUIT_ASYNC=1` (default): capture on a background worker thread.
- `JSRECONDUIT_QUEUE_MAX=200`: max pending captures before dropping new ones.
- `JSRECONDUIT_DISABLE_BEAUTIFY=1`: skip beautification for faster capture.
- `JSRECONDUIT_ALWAYS_BEAUTIFY=1`: beautify every captured JS file (slower).
- `JSRECONDUIT_ENABLE_SOURCEMAP=0`: disable sourcemap detection/writes.
- `JSRECONDUIT_HEURISTIC_BYTES=4096`: bytes sampled for JS heuristic checks.
- `JSRECONDUIT_PRETTY_INDEX=1`: pretty JSON output (slower).
- `JSRECONDUIT_DEBUG=1`: verbose debug logging in Burp output.
- `JSRECONDUIT_ONLY_IN_SCOPE=1`: only capture URLs that are in Burp scope.
- `JSRECONDUIT_CAPTURE_HTML=1`: capture HTML responses (default on).
- `JSRECONDUIT_ENABLE_CHUNK_DISCOVERY=1`: extract lazy chunk candidates from JS (default on).
- `JSRECONDUIT_ENABLE_CHUNK_FETCH=0`: actively fetch chunk candidates (default off).
- `JSRECONDUIT_CHUNK_FETCH_LIMIT=40`: max chunk fetches per JS asset.
- `JSRECONDUIT_CHUNK_SAME_ORIGIN=1`: only fetch chunks from the same origin.

Example:

```bash
JSRECONDUIT_DISABLE_BEAUTIFY=1 \
JSRECONDUIT_ENABLE_SOURCEMAP=0 \
JSRECONDUIT_HEURISTIC_BYTES=4096 \
java -jar /path/to/burpsuite.jar
```

### VSCode Extension

#### Dev install

1. Open `vscode-extension/` in a terminal.
2. Install dependencies and build:

```bash
npm install
npm run compile
```

3. Launch the extension in VSCode (Run and Debug -> "Run Extension").

#### VSIX install

1. Package the extension:

```bash
npm install -g @vscode/vsce
npm run compile
vsce package
```

2. Install the generated `.vsix`:

```bash
code --install-extension jsreconduit-0.1.0.vsix
```

3. Configure `jsreconduit.baseDir` to match `JSRECONDUIT_BASE_DIR`.

Optional settings:
- `jsreconduit.autoWordlist`: automatically write `wordlists/jsreconduit-wordlist.txt` on refresh (default true).
- `jsreconduit.wordlistPath`: override wordlist output path.
- `jsreconduit.autoDeobfuscate`: automatically deobfuscate assets on refresh (default false).
- `jsreconduit.preferDeobfuscated`: prefer deobfuscated files when available (default true).
- `jsreconduit.exportDir`: override findings export directory.
- `jsreconduit.reportDir`: override report output directory.
- `jsreconduit.signaturePath`: override signature rules path (defaults to `<baseDir>/signatures.json`).
- `jsreconduit.autoWriteSnippet`: automatically write the instrumentation snippet (default true).

## Usage Workflow

1. Start Burp and proxy your target traffic as usual.
2. JSReconduit will write JS assets to the capture directory.
3. Open VSCode and enable the JSReconduit extension.
4. Use the **JSReconduit** sidebar to inspect captured files, HTML assets, routes, drift, diffs, alerts, triage, coverage, endpoint clusters, endpoints, sinks, user sinks, secrets, signatures, frameworks, call graph, traces, sourcemaps, and wordlist entries.
5. Optional: run `JSReconduit: Go To Route`, `JSReconduit: Go To Asset`, `JSReconduit: Deobfuscate All Assets`, `JSReconduit: Export Findings (JSON/CSV/SARIF)`, `JSReconduit: Generate Report (Markdown)`, and `JSReconduit: Write Instrumentation Snippet`.

## Interesting Outputs

The VSCode extension writes curated findings to `interesting/` under the capture directory:

- `interesting/apis/`: HTTP/WebSocket endpoints from AST calls (`fetch`, `XMLHttpRequest.open`, `axios`, `WebSocket`, `EventSource`). Only string literal URLs are captured.
- `interesting/routes/`: referer-to-asset mapping from Burp observations (`Referer` header + URL of the JS file).
- `interesting/drift/`: new findings when the same JS URL changes; compares the most recent two captures for that URL.
- `interesting/clusters/`: endpoints grouped by base path (first 1–2 path segments) plus auth hints inferred from request options (`headers.authorization`, `x-api-key`, `auth`, `credentials`).
- `interesting/flows/`: call graph edges (caller → callee) and source→sink traces built from lightweight taint propagation (URL params/storage/DOM sources into sink calls/assignments).
- `interesting/descriptors/`: static descriptors (paths/URLs/hostnames/extensions/MIME types), regex patterns/matches, GraphQL queries, client behavior (location/cookies/storage/window.open/URLSearchParams), rest-client calls, fetch options, schemas, and dependency package names.
- `interesting/descriptors/feature-flags.*`: feature flag names inferred from config objects, flag helper calls, and flag-related member paths.
- `interesting/assets/`: captured HTML summaries (script counts and srcs).
- `interesting/alerts/`: drift alerts raised when new secrets, user sinks, sinks, or endpoints appear between versions.
- `interesting/triage/`: risk-ranked assets scored by counts of endpoints, sinks, user sinks, secrets, and signature hits.
- `interesting/coverage/`: per-asset totals for endpoints/sinks/user sinks/secrets/signatures.
- `interesting/secrets/`: high-entropy literals or known key prefixes (e.g., `AKIA`, `AIza`, `ghp_`), plus JWT detection. URL/path-looking strings are filtered to reduce noise.
- `interesting/sinks/`: DOM/code execution sinks and user-controlled sink candidates (e.g., `innerHTML`, `setAttribute`, `eval`, `Function`).
- `interesting/signatures/`: signature pack matches (regex rules from `signatures.json`).
- `interesting/sourcemaps/`: sourcemap graph with resolved source stats per file.

These files are regenerated on each refresh.

Coverage legend used in `interesting/coverage/coverage.txt`:
- `T`: total findings for the asset.
- `E`: endpoints.
- `S`: sinks.
- `U`: user-controlled sinks.
- `K`: secrets.
- `G`: signature matches.

## Diff Viewer

Use the **Diffs** node in the JSReconduit sidebar to open a side-by-side diff of the previous and current versions of an asset. Added endpoints and sinks are highlighted in the right-hand editor.

## HTML Capture and Asset Links

HTML responses are stored under `html/` and listed in the **HTML** node of the sidebar. Script `src` references are extracted so you can jump from HTML to captured JavaScript when it’s available.

## Call Graph and Flow Traces

JSReconduit builds a lightweight call graph and source-to-sink traces to surface dataflow paths. Traces are listed in the sidebar and exported under `interesting/flows/`.

## Chunk Discovery

JSReconduit can extract lazy chunk candidates from captured JS and (optionally) fetch them. Enable fetch carefully, because it makes additional HTTP requests to the target.

## Deobfuscation

Deobfuscation uses the optional `javascript-deobfuscator` dependency. Install it via:

```bash
cd vscode-extension
npm install
```

Then enable `jsreconduit.autoDeobfuscate` or run the **JSReconduit: Deobfuscate All Assets** command. Outputs are written to `deobfuscated/`.

## Exports

Use the command palette to export findings:

- **JSReconduit: Export Findings (JSON)**
- **JSReconduit: Export Findings (CSV)**
- **JSReconduit: Export Findings (SARIF)**

Outputs are written under `exports/` unless `jsreconduit.exportDir` is set.

## Reports

Use the command palette to generate a Markdown report:

- **JSReconduit: Generate Report (Markdown)**

Outputs are written under `reports/` unless `jsreconduit.reportDir` is set.

## Instrumentation Snippet

The extension writes `instrumentation/jsreconduit-snippet.js`. Paste it in the browser console to log runtime `fetch`/XHR/WebSocket calls and DOM sink assignments.

## Signature Packs

Provide a JSON signature file (default: `<baseDir>/signatures.json`) to add custom detections. See `examples/signatures.json` for format.

## Deduplication and Observations

JSReconduit deduplicates assets by SHA-256 hash of the response body. If the same JavaScript is seen multiple times, it is only saved once and the index entry is updated with:

- `first_seen` / `last_seen`
- `seen_count`
- `observations`: per-URL/method records with counts and timestamps

## Security Considerations

- JSReconduit is passive and does not alter traffic.
- No data is uploaded; the system is offline-first by design.
- Sourcemap fetching may contact the same target origin when remote sourcemaps are referenced. If this is undesirable, block outbound requests or remove sourcemap URLs before analysis.
- Use only on authorized targets.

## Example Output Structure

See `examples/example-structure.txt`.

## Sample Index

See `examples/sample-index.json`.
