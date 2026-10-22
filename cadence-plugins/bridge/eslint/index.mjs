#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

function validateRequest(req) {
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const allowed = new Set(['schemaVersion', 'protocolVersion', 'repoRoot', 'files', 'mode', 'changedFiles', 'config', 'constraints', 'compat']);
  if (!object(req) || Object.keys(req).some(key => !allowed.has(key))) throw new Error('invalid plugin request object');
  if (req.schemaVersion !== '1.0.0' || req.protocolVersion !== '1.0.0' || !['scan', 'verify'].includes(req.mode)) throw new Error('unsupported plugin schema/protocol version or mode');
  if (typeof req.repoRoot !== 'string' || !fs.statSync(req.repoRoot).isDirectory()) throw new Error('repoRoot must identify an existing directory');
  for (const key of ['files', 'changedFiles']) {
    const value = key === 'changedFiles' && !(key in req) ? [] : req[key];
    if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) throw new Error(`${key} must be an array of strings`);
  }
  for (const key of ['config', 'constraints', 'compat']) if (key in req && !object(req[key])) throw new Error(`${key} must be an object`);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function stableSort(items, keyFn) {
  return [...items].sort((a, b) => (keyFn(a) < keyFn(b) ? -1 : keyFn(a) > keyFn(b) ? 1 : 0));
}

function scan(content) {
  const violations = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.includes('console.log(')) {
      violations.push({ ruleId: 'ESLINT_NO_CONSOLE', severity: 'P2', message: 'console.log is not allowed in committed code', line: i + 1 });
    }
    if (line.includes('debugger;')) {
      violations.push({ ruleId: 'ESLINT_NO_DEBUGGER', severity: 'P1', message: 'debugger statements are not allowed', line: i + 1 });
    }
  }
  return violations;
}

const raw = await readStdin();
const req = JSON.parse(raw);
validateRequest(req);
const repoRoot = String(req.repoRoot || process.cwd());
const files = Array.isArray(req.files) ? req.files.map(String) : [];
const violations = [];
for (const rel of files) {
  const abs = path.join(repoRoot, rel);
  const content = fs.readFileSync(abs, 'utf8');
  violations.push(...scan(content).map((item) => ({ ...item, file: rel.replaceAll('\\', '/') })));
}
const response = {
  schemaVersion: '1.0.0',
  protocolVersion: String(req.protocolVersion || '1.0.0'),
  ir: { irVersion: '1', modules: [], edges: [] },
  violations: stableSort(violations, (item) => `${item.severity}|${item.ruleId}|${item.file}|${item.line}`),
  metrics: { filesScanned: files.length, bridge: 'eslint' },
};
process.stdout.write(JSON.stringify(response, null, 2) + '\n');
