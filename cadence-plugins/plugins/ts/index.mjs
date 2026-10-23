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

function decodeModuleLiteral(literal) {
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

function tokenizeJS(content) {
  const tokens = [];
  let i = 0;
  const word = c => /[A-Za-z0-9_$]/.test(c);
  const add = (start, end) => tokens.push({value:content.slice(start,end), index:start});
  function template() {
    const start = i, slot = tokens.length;
    tokens.push({value:'<template>', index:start}); i++;
    let interpolated = false;
    while (i < content.length) {
      if (content[i] === '\\') { i += 2; continue; }
      if (content[i] === '`') {
        i++; if (!interpolated) tokens[slot].value = content.slice(start,i); return;
      }
      if (content[i] === '$' && content[i+1] === '{') { interpolated = true; i += 2; code(true); }
      else i++;
    }
  }
  function code(expression) {
    let canRegex = true, previous = '', statementStart = !expression, brackets = 0;
    // A body remembers whether its closing brace ends a declaration or a value.
    const pending = [];
    const parens = [], blocks = [];
    while (i < content.length) {
      const c = content[i];
      if (/\s/.test(c)) { i++; continue; }
      if (c === '}' && expression && blocks.length === 0) { i++; return; }
      const start = i;
      if (c === '/' && i+1 < content.length) {
        if (content[i+1] === '/') { while (i < content.length && content[i] !== '\n') i++; continue; }
        if (content[i+1] === '*') {
          i += 2; while (i+1 < content.length && !(content[i] === '*' && content[i+1] === '/')) i++;
          i = Math.min(i+2,content.length); continue;
        }
        if (canRegex) {
          let j = i+1, inClass = false, closed = false;
          while (j < content.length && !['\n','\r'].includes(content[j])) {
            if (content[j] === '\\') { j += 2; continue; }
            if (content[j] === '[') inClass = true;
            if (content[j] === ']') inClass = false;
            if (content[j] === '/' && !inClass) { j++; closed = true; break; }
            j++;
          }
          if (closed) {
            while (j < content.length && word(content[j])) j++;
            tokens.push({value:'<regexp>',index:start}); i = j; canRegex = false; previous = '<regexp>'; statementStart = false; continue;
          }
        }
      }
      if (c === "'" || c === '"') {
        i++; while (i < content.length) {
          if (content[i] === '\\') { i += 2; continue; }
          if (content[i] === c) { i++; break; } i++;
        }
        add(start,i); canRegex = false; previous = '<string>'; statementStart = false; continue;
      }
      if (c === '`') { template(); canRegex = false; previous = '<template>'; statementStart = false; continue; }
      if (word(c)) {
        while (i < content.length && word(content[i])) i++;
        add(start,i); const value = content.slice(start,i);
        if (['function','class'].includes(value) && previous !== '.') {
          pending.push({kind:value, declaration:statementStart, parens:parens.length, braces:blocks.length, brackets});
        }
        statementStart = ['else','do','try','finally'].includes(value) ||
          (statementStart && ['export','default','async'].includes(value));
        previous = value;
        canRegex = ['return','throw','case','delete','void','typeof','new','in','of','yield','await','else','do','instanceof'].includes(previous); continue;
      }
      i++;
      if (i < content.length && ((c === '+' || c === '-') && content[i] === c || c === '=' && content[i] === '>')) i++;
      const value = content.slice(start,i); add(start,i);
      const body = pending[pending.length-1];
      const atBodyDepth = body && body.parens === parens.length && body.braces === blocks.length && body.brackets === brackets;
      const wasStatementStart = statementStart;
      statementStart = false;
      if (value === '(') { parens.push(['if','while','for','switch','catch','with'].includes(previous)); canRegex = true; }
      else if (value === ')') { canRegex = parens.pop() ?? false; statementStart = canRegex; }
      else if (value === '{') {
        const construct = atBodyDepth && (body.kind === 'class' || previous === ')');
        const statements = construct || wasStatementStart || previous === ')' || previous === '=>';
        const regexAfter = construct ? body.declaration : statements && previous !== '=>';
        if (construct) pending.pop();
        blocks.push({regexAfter, statements:!!statements, parens:parens.length});
        canRegex = true; statementStart = !!statements;
      }
      else if (value === '}') {
        canRegex = blocks.pop()?.regexAfter ?? true; statementStart = canRegex;
        while (pending.length && pending[pending.length-1].braces > blocks.length) pending.pop();
      }
      else {
        canRegex = ![']','.','++','--'].includes(value);
        if (value === '[') brackets++;
        if (value === ']') brackets--;
        const scope = blocks[blocks.length-1];
        if (value === ';' || value === ':') statementStart = scope ? scope.statements && scope.parens === parens.length : !expression && parens.length === 0;
        if (atBodyDepth && [';',':',','].includes(value)) pending.pop();
      }
      previous = value;
    }
  }
  code(false);
  return tokens;
}

function scanImports(content) {
  const violations = [];
  const tokens = tokenizeJS(content);
  function add(index) {
    const literal = tokens[index].value;
    if (!['"', "'", '`'].includes(literal[0])) return;
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
