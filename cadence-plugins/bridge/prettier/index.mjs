#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function stableSort(items, keyFn) {
  return [...items].sort((a, b) => keyFn(a).localeCompare(keyFn(b)));
}

function scan(content) {
  const violations = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/\t/.test(line)) {
      violations.push({ ruleId: 'PRETTIER_NO_TABS', severity: 'P2', message: 'tab indentation detected; expected spaces', line: i + 1 });
    }
    if (/[ \t]+$/.test(line)) {
      violations.push({ ruleId: 'PRETTIER_TRAILING_WHITESPACE', severity: 'P2', message: 'trailing whitespace detected', line: i + 1 });
    }
  }
  if (content.length && !content.endsWith('\n')) {
    violations.push({ ruleId: 'PRETTIER_FINAL_NEWLINE', severity: 'P2', message: 'file must end with a newline', line: lines.length });
  }
  return violations;
}

const raw = await readStdin();
const req = raw ? JSON.parse(raw) : {};
const repoRoot = String(req.repoRoot || process.cwd());
const files = Array.isArray(req.files) ? req.files.map(String) : [];
const violations = [];
for (const rel of files) {
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs)) continue;
  const content = fs.readFileSync(abs, 'utf8');
  violations.push(...scan(content).map((item) => ({ ...item, file: rel.replaceAll('\\', '/') })));
}
const response = {
  protocolVersion: String(req.protocolVersion || '1.0.0'),
  ir: { irVersion: '1', modules: [], edges: [] },
  violations: stableSort(violations, (item) => `${item.severity}|${item.ruleId}|${item.file}|${item.line}`),
  metrics: { filesScanned: files.length, bridge: 'prettier' },
};
process.stdout.write(JSON.stringify(response, null, 2) + '\n');
