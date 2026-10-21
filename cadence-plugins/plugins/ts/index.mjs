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
    process.stdin.on('data', c => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function stableSort(arr, keyFn) {
  return [...arr].sort((a,b) => {
    const ka = keyFn(a);
    const kb = keyFn(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

function scanImports(content) {
  const violations = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(/\b(from\s+['\"]([^'\"]+)['\"])|\bimport\(['\"]([^'\"]+)['\"]\)/);
    if (!m) continue;
    const imp = m[2] || m[3] || '';
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

function buildIR(repoRoot, files) {
  // Minimal IR: group by top-level folder under src/.
  const modulesById = new Map();
  const edges = [];

  for (const rel of files) {
    const norm = rel.replaceAll('\\\\','/');
    const segs = norm.split('/');
    const srcIdx = segs.indexOf('src');
    let mod = 'root';
    if (srcIdx >= 0 && segs.length > srcIdx + 1) mod = segs[srcIdx + 1];
    const modId = `ts:${mod}`;
    if (!modulesById.has(modId)) {
      modulesById.set(modId, { id: modId, path: mod, type: 'module', owner: 'unknown' });
    }
    // No edges computed in this minimal IR.
  }

  return {
    irVersion: '1',
    modules: stableSort([...modulesById.values()], m => m.id),
    edges: stableSort(edges, e => `${e.from}|${e.to}|${e.kind}`),
  };
}

async function main() {
  const raw = await readStdin();
  const req = JSON.parse(raw);
  validateRequest(req);

  const repoRoot = String(req.repoRoot || process.cwd());
  const files = Array.isArray(req.files) ? req.files.map(String) : [];

  const outViolations = [];
  for (const rel of files) {
    const abs = path.join(repoRoot, rel);
    const content = fs.readFileSync(abs, 'utf8');
    const vs = scanImports(content).map(v => ({ ...v, file: rel.replaceAll('\\\\','/') }));
    outViolations.push(...vs);
  }

  const resp = {
    schemaVersion: '1.0.0',
    protocolVersion: String(req.protocolVersion || '1.0.0'),
    ir: buildIR(repoRoot, files),
    violations: stableSort(outViolations, v => `${v.severity}|${v.ruleId}|${v.file}|${v.line}|${v.message}`),
    metrics: { filesScanned: files.length },
  };

  process.stdout.write(JSON.stringify(resp, null, 2) + '\n');
}

main().catch(err => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.exit(2);
});
