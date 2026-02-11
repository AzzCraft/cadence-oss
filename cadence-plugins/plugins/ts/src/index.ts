import * as fs from 'node:fs';

type PluginRequest = any;
type PluginResponse = any;

// Cadence Core spawns the plugin and passes a single JSON request via stdin.
// This is a stub implementation that always returns no violations.
function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

(async () => {
  const raw = await readStdin();
  const req: PluginRequest = raw ? JSON.parse(raw) : {};
  const res: PluginResponse = {
    protocolVersion: req.protocolVersion ?? "1.0",
    ir: { kind: "ts", note: "stub" },
    violations: [],
    metrics: { files: (req.files ?? []).length, parseMs: 0 }
  };
  fs.writeFileSync(1, JSON.stringify(res)); // stdout fd=0 in node? (placeholder)
})();
