import fs from 'node:fs';
import path from 'node:path';

type Violation = {
  ruleId: string;
  severity: 'P1';
  message: string;
  line: number;
  file?: string;
};

function validateRequest(req: any) {
  const object = (value: any) => value !== null && typeof value === 'object' && !Array.isArray(value);
  const allowed = new Set(['schemaVersion', 'protocolVersion', 'repoRoot', 'files', 'mode', 'changedFiles', 'config', 'constraints', 'compat']);
  if (!object(req) || Object.keys(req).some(key => !allowed.has(key))) throw new Error('invalid plugin request object');
  if (req.schemaVersion !== '1.0.0' || req.protocolVersion !== '1.0.0' || !['scan', 'verify'].includes(req.mode)) throw new Error('unsupported plugin schema/protocol version or mode');
  if (typeof req.repoRoot !== 'string' || !fs.statSync(req.repoRoot).isDirectory()) throw new Error('repoRoot must identify an existing directory');
  for (const key of ['files', 'changedFiles']) {
    const value = key === 'changedFiles' && !(key in req) ? [] : req[key];
    if (!Array.isArray(value) || value.some((item: any) => typeof item !== 'string')) throw new Error(`${key} must be an array of strings`);
  }
  for (const key of ['config', 'constraints', 'compat']) if (key in req && !object(req[key])) throw new Error(`${key} must be an object`);
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function stableSort<T>(arr: T[], keyFn: (item: T) => string): T[] {
  return [...arr].sort((a, b) => (keyFn(a) < keyFn(b) ? -1 : keyFn(a) > keyFn(b) ? 1 : 0));
}

function decodeModuleLiteral(literal: string): string {
  // Decode string escapes without evaluating source code or resolving modules.
  return literal.slice(1, -1).replace(/\\(?:u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|[\s\S])/g, escape => {
    const code = escape.slice(1);
    if (['\n', '\r', '\r\n', '\u2028', '\u2029'].includes(code)) return '';
    if (code.startsWith('u{') || code.startsWith('x')) {
      const value = parseInt(code.startsWith('x') ? code.slice(1) : code.slice(2, -1), 16);
      return value <= 0x10ffff ? String.fromCodePoint(value) : escape;
    }
    if (code === 'v') return '\v';
    if (code === '0') return '\0';
    try { return JSON.parse('"' + escape + '"'); } catch { return code; }
  });
}

function scanImports(content: string): Violation[] {
  const violations: Violation[] = [];
  const pattern = /"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'|`(?:\\[\s\S]|[^`\\])*`|\/\*[\s\S]*?\*\/|\/\/[^\n]*|[A-Za-z_$][A-Za-z0-9_$]*|[^\s]/g;
  const tokens = [...content.matchAll(pattern)].map(m => ({value:m[0], index:m.index ?? 0})).filter(t => !t.value.startsWith('//') && !t.value.startsWith('/*'));
  function add(index: number) {
    const literal = tokens[index].value;
    if (!literal.startsWith('"') && !literal.startsWith("'")) return;
    const module = decodeModuleLiteral(literal);
    if (module.includes('/internal/') || module.includes('/src/')) {
      violations.push({ruleId:'SDMM_DEEP_IMPORT', severity:'P1', message:`Deep import detected: ${module}`, line:content.slice(0,tokens[index].index).split('\n').length});
    }
  }
  for (let i=0; i<tokens.length; i++) {
    const current=tokens[i].value;
    if (current!=='import' && current!=='export') continue;
    if (i>0 && tokens[i-1].value==='.') continue;
    if (i+1>=tokens.length) continue;
    const next=tokens[i+1].value;
    if (current==='import' && (next.startsWith('"') || next.startsWith("'"))) {add(i+1); continue;}
    if (current==='import' && next==='(' && i+2<tokens.length) {add(i+2); continue;}
    for (let j=i+1; j+1<tokens.length; j++) {
      if ([';', '=', 'import', 'export'].includes(tokens[j].value)) break;
      if (tokens[j].value==='from' && (tokens[j+1].value.startsWith('"') || tokens[j+1].value.startsWith("'"))) {add(j+1); i=j+1; break;}
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
  const req = JSON.parse(raw);
  validateRequest(req);
  const repoRoot = String(req.repoRoot || process.cwd());
  const files = Array.isArray(req.files) ? req.files.map(String) : [];
  const violations: Violation[] = [];

  for (const rel of files) {
    const abs = path.join(repoRoot, rel);
    const content = fs.readFileSync(abs, 'utf8');
    violations.push(...scanImports(content).map((item) => ({ ...item, file: rel.replaceAll('\\', '/') })));
  }

  const response = {
    schemaVersion: '1.0.0',
    protocolVersion: req.protocolVersion ?? '1.0.0',
    ir: buildIR(files),
    violations: stableSort(violations, (item) => `${item.severity}|${item.ruleId}|${item.file}|${item.line}|${item.message}`),
    metrics: { filesScanned: files.length },
  };
  process.stdout.write(JSON.stringify(response, null, 2) + '\n');
})();
