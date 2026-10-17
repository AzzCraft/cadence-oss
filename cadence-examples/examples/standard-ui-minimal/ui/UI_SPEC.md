# Controlled document workspace

This optional synthetic source example supplements the existing setup. It uses
HTML, CSS and JavaScript with no build system or external browser dependency.
It is a domain behavior sample, not a production document service, Task
Completion producer or permission boundary.

| Workflow | User action | Expected result and recovery |
|---|---|---|
| read | Select explicit document A or B | Fetch that exact ID, show full text; obsolete success/error/finally cannot change a newer selection. The full reading region scrolls to its final line. |
| edit | Change document text, then select another document | Keep editing or explicitly discard in a modal. Escape keeps edits; Tab/Shift+Tab stay within the modal, close restores focus. |
| save | Submit one edited revision | Bind the returned receipt to original ID, request ID, base revision, submitted edit version and text. Later edits stay dirty. No automatic retry. |
| history | Inspect explicit history entries | Require object identity and a valid nonduplicate collection. Empty/one/multiple and incomplete collections remain distinct; incomplete does not imply uniqueness. Selecting an ID fetches that precise snapshot. |
| recover | Stop a save or lose its response | Display remote outcome unknown; block another save and navigation. Check the original request ID explicitly. A missing result remains unknown. Read-only history alone cannot settle the request. |

`--action-color` and `--space` are the declared sample tokens. The browser
driver observes computed styles and a token change, intentional overriding
style, and restoration. A variable's presence alone is not consumption proof.
Technical JSON/API prose is valid user content; development instructions and
approval controls do not belong in the document page. Semantic audience review
remains an independent responsibility, beyond the fixed source fixtures.

## Source verification

`verify-browser.mjs` is an independent Node 22+ controller using built-in
anonymous-pipe CDP and the explicitly pinned real Chrome executable. It serves only
three fixed assets plus synthetic document APIs on `127.0.0.1`, runs Chrome with
its normal sandbox and no debugging TCP listener, and observes actual HTTP requests and save receipts outside
the page. There is no production login, trace/HAR/storageState/cookie export,
candidate-provided URL, framework or automatic visual-baseline approval.

Prepare a private external JSON file with exactly four fields: absolute `node`
and `chrome` executable paths and their raw-byte `nodeSha256`/`chromeSha256`.
The Chrome path should identify its actual ELF executable, not a shell wrapper.
The test checks both hashes before launch. These source test pins describe the
selected local tools; final installation must separately freeze actual runtime
dependencies and the approved browser configuration.

From repository root, use the existing test interpreter:

```bash
CADENCE_DAS_V15_UI_REFERENCE_CONFIG=/absolute/private/source-browser-inputs.json \
  python -B -m pytest -q -p no:cacheprovider tests/das_v1_5/test_a27_ui_workflows.py
```

An absent configuration is a visible skip, not an A27 qualification. Direct
driver invocation takes `--case A27.1` through `A27.9`, `--chrome`,
`--chrome-sha256`, `--node-sha256`, and a new absolute `--out` directory. Run it
with the same pinned Node. Output includes the source build/asset hashes, actual
Node/browser identity, request observations, result scope and a synthetic-page
screenshot. Failures retain `failed.json`; all artifacts belong outside Git.
`runtime-attempt-browser-fonts.json` records the native rendered family,
PostScript name, custom-font flag and glyph count for three fixed UI elements,
bound to the original case, Chrome bytes and build digest. It exports no document
text. The source observer keeps the verified producer report as
`report-attempt-ui-browser.json`, using the existing fixture retention names.
Match observed font names to actual font files and their provider artifacts;
CSS declarations or `fc-match` defaults alone do not prove rendered identity.
This sidecar adds no formal UI contract or baseline approval.
Never publish the browser profile. The test owner must retain or remove only
its own completed source-test profile according to the existing retention rule.

The nine original source nodes exercise behavior/rejection mechanisms. They
do **not** prove separate deployed UID/account access, candidate inability to
modify a production runner, real independent baseline approval, authenticated
session export denial or complete human/assistive-technology review. The
source report lists these limits. Final installed A27 results remain not_run;
no full-site WCAG, conformance, qualification or task-completion claim follows.

## Actual loaded runtime materials

The fixed browser driver also retains `runtime-attempt-loaded-materials.json`.
It uses native browser process IDs and kernel start times to observe mapped regular
files and their byte digests; inaccessible/exited processes and deleted mappings
stay explicitly unobserved. This complements the font record and package-material
lock. It does not approve the OS supplier, unexecuted branches, independent baseline
or accessibility review. Raw process/file observations stay in the controlled
evidence directory; document text and authentication traces are not exported.
