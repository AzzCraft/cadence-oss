import fs from 'node:fs';
import path from 'node:path';

type PluginRequest = {
  protocolVersion?: string;
  repoRoot?: string;
  files?: string[];
};

type Violation = {
  ruleId: string;
  severity: 'P1';
  message: string;
  line: number;
  file?: string;
};

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function stableSort<T>(arr: T[], keyFn: (item: T) => string): T[] {
  return [...arr].sort((a, b) => keyFn(a).localeCompare(keyFn(b)));
}

function scanImports(content: string): Violation[] {
  const violations: Violation[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const match = line.match(/\b(from\s+['"]([^'"]+)['"])|\bimport\(['"]([^'"]+)['"]\)/);
    if (!match) continue;
    const imp = match[2] || match[3] || '';
    if (imp.includes('/internal/') || imp.includes('/src/')) {
      violations.push({
        ruleId: 'SDMM_DEEP_IMPORT',
        severity: 'P1',
        message: `Deep import detected: ${imp}`,
        line: i + 1,
      });
    }
  }
  return violations;
}

function buildIR(files: string[]) {
  const modules = new Map<string, { id: string; path: string; type: string; owner: string }>();
  for (const rel of files) {
    const parts = rel.replaceAll('\\', '/').split('/');
    const srcIdx = parts.indexOf('src');
    const mod = srcIdx >= 0 && parts[srcIdx + 1] ? parts[srcIdx + 1] : 'root';
    const id = `ts:${mod}`;
    if (!modules.has(id)) {
      modules.set(id, { id, path: mod, type: 'module', owner: 'unknown' });
    }
  }
  return {
    irVersion: '1',
    modules: stableSort([...modules.values()], (item) => item.id),
    edges: [],
  };
}

(async () => {
  const raw = await readStdin();
  const req: PluginRequest = raw ? JSON.parse(raw) : {};
  const repoRoot = String(req.repoRoot || process.cwd());
  const files = Array.isArray(req.files) ? req.files.map(String) : [];
  const violations: Violation[] = [];

  for (const rel of files) {
    const abs = path.join(repoRoot, rel);
    if (!fs.existsSync(abs)) continue;
    const content = fs.readFileSync(abs, 'utf8');
    violations.push(...scanImports(content).map((item) => ({ ...item, file: rel.replaceAll('\\', '/') })));
  }

  const response = {
    protocolVersion: req.protocolVersion ?? '1.0.0',
    ir: buildIR(files),
    violations: stableSort(violations, (item) => `${item.severity}|${item.ruleId}|${item.file}|${item.line}|${item.message}`),
    metrics: { filesScanned: files.length },
  };
  process.stdout.write(JSON.stringify(response, null, 2) + '\n');
})();
