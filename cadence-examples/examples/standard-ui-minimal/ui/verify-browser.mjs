#!/usr/bin/env node
// Independent source driver: actual Chrome, actual HTTP and controller receipts.
// No candidate self-report, synthetic DOM renderer, auth trace or browser state export.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
// The same observer is called by the browser workflow and narrow /proc race
// regressions. Importing this file does not start a browser or a service.
export function observeMappedProcess(pid,type,expectedExecutable,materialCache=new Map()) {
  assert(Number.isSafeInteger(pid)&&pid>0&&typeof type==='string');
  const proc='/proc/'+pid;
  const startTime=()=>{
    const value=fs.readFileSync(proc+'/stat','utf8');
    const fields=value.slice(value.lastIndexOf(')')+2).split(' ');
    assert(!['Z','X'].includes(fields[0]),'native process exited during observation');
    return fields[19];
  };
  const mappings=()=>{
    const raw=fs.readFileSync(proc+'/maps','utf8');assert(Buffer.byteLength(raw)<=2*1024*1024);
    const entries=new Map();
    for(const line of raw.split('\n')) {
      const match=line.match(/^[0-9a-f]+-[0-9a-f]+\s+\S+\s+\S+\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)\s+(\/.*)$/);
      if(!match)continue;
      const filename=match[3].replace(/\\([0-7]{3})/g,(_,octal)=>String.fromCharCode(parseInt(octal,8)));
      const identity={path:filename,mappingDevice:match[1],mappingInode:BigInt(match[2]).toString()};
      entries.set(JSON.stringify(identity),identity);
    }
    assert(entries.size<=1024);return entries;
  };
  const start=startTime(),executable=fs.realpathSync(proc+'/exe');
  assert.equal(executable,fs.realpathSync(expectedExecutable),'native process executable differs from pinned tool');
  const selected=mappings(),files=[],unobserved=[];
  for(const [key,identity] of selected) {
    try {
      assert(!identity.path.endsWith(' (deleted)'),'mapped file deleted');
      const real=fs.realpathSync(identity.path),fd=fs.openSync(real,'r');
      try {
        const info=fs.fstatSync(fd,{bigint:true});assert(info.isFile()&&info.size<=512n*1024n*1024n);
        // Linux dev_t encoding; /proc maps uses hexadecimal major:minor.
        const major=((info.dev>>8n)&0xfffn)|((info.dev>>32n)&0xfffff000n);
        const minor=(info.dev&0xffn)|((info.dev>>12n)&0xffffff00n);
        const [mappedMajor,mappedMinor]=identity.mappingDevice.split(':').map(value=>BigInt('0x'+value));
        assert(major===mappedMajor&&minor===mappedMinor&&info.ino===BigInt(identity.mappingInode),
          'opened file differs from sampled mapping');
        const cacheKey=JSON.stringify([real,info.dev.toString(),info.ino.toString(),info.size.toString(),info.mtimeNs.toString(),info.ctimeNs.toString()]);
        let digest=materialCache.get(cacheKey);
        if(!digest) {
          const sha256=crypto.createHash('sha256'),chunk=Buffer.alloc(1024*1024);let read;
          while((read=fs.readSync(fd,chunk,0,chunk.length,null))>0)sha256.update(chunk.subarray(0,read));
          digest=sha256.digest('hex');materialCache.set(cacheKey,digest);
        }
        const after=fs.fstatSync(fd,{bigint:true});
        assert(info.dev===after.dev&&info.ino===after.ino&&info.size===after.size&&info.mtimeNs===after.mtimeNs&&info.ctimeNs===after.ctimeNs,
          'mapped file changed while hashing');
        files.push({key,...identity,realPath:real,device:info.dev.toString(),inode:info.ino.toString(),sha256:digest,bytes:Number(info.size)});
      } finally {fs.closeSync(fd);}
    } catch(error) {unobserved.push({pid,type,...identity,reason:String(error)});}
  }
  const current=mappings();assert.equal(startTime(),start,'native process identity changed');
  const observed=[];
  for(const {key,...file} of files) {
    if(current.has(key))observed.push(file);
    else unobserved.push({pid,type,path:file.path,mappingDevice:file.mappingDevice,mappingInode:file.mappingInode,reason:'mapping changed during observation'});
  }
  return {processMaterial:{pid,type,startTimeTicks:start,executable,files:observed},unobserved};
}

async function main() {
const flags = Object.fromEntries(process.argv.slice(2).reduce((pairs,value,index,all) => {
  if (index % 2 === 0) pairs.push([value,all[index+1]]); return pairs;
}, []));
assert.deepEqual(Object.keys(flags).sort(), ['--case','--chrome','--chrome-sha256','--node-sha256','--out']);
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
assert.match(flags['--case'], /^A27\.[1-9]$/);
assert.equal(hash(fs.readFileSync(process.execPath)), flags['--node-sha256']);
assert(path.isAbsolute(flags['--chrome']));
assert.equal(hash(fs.readFileSync(flags['--chrome'])), flags['--chrome-sha256']);
const out = flags['--out']; assert(path.isAbsolute(out));
fs.mkdirSync(out,{mode:0o700});
const profile = path.join(out,'profile');
const assets = ['index.html','app.js','styles.css'];
const assetHashes = Object.fromEntries(assets.map(name => [name,hash(fs.readFileSync(path.join(root,name)))]));
const buildDigest = hash(Buffer.from(JSON.stringify(assetHashes)));
const cases = [], requests = [], writes = new Map();
const documents = {A:{id:'A',revision:1,text:'Document A\n'+('Long document line\n'.repeat(100))+'END OF DOCUMENT A'},B:{id:'B',revision:1,text:'Document B: legal user technical text about JSON APIs'}};
let readGate = null, writeGate = null, detailGate = null, historyValue = null, historyError = false;
let server, chrome, session, incoming = '', stderr = '', serial = 0;
const waiting = new Map();
const pause = ms => new Promise(resolve => setTimeout(resolve,ms));
async function until(check) {
  const expires=Date.now()+8000;
  while(Date.now()<expires) { if(await check()) return; await pause(25); }
  throw Error('independent browser condition timed out');
}
function answer(response,value,status=200) {
  if (!response.destroyed) { response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'}); response.end(JSON.stringify(value)); }
}
function cdp(method,params={}) {
  const id=++serial;
  return new Promise((resolve,reject) => {
    const timer=setTimeout(() => { waiting.delete(id); reject(Error('CDP timeout '+method)); },8000);
    waiting.set(id,{resolve,reject,timer});
    const message={id,method,params};
    if(session&&!method.startsWith('Browser.')&&!method.startsWith('Target.')&&!method.startsWith('SystemInfo.'))message.sessionId=session;
    chrome.stdio[3].write(JSON.stringify(message)+'\0');
  });
}
async function evaluate(expression) {
  const result=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
  assert(!result.exceptionDetails,JSON.stringify(result.exceptionDetails));return result.result.value;
}
const click = id => evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);
const state = () => evaluate(`({title:document.getElementById('document-title').textContent,text:document.getElementById('editor').value,status:document.getElementById('status').textContent,dirty:document.getElementById('dirty').textContent,saveDisabled:document.getElementById('save').disabled,history:document.getElementById('history-status').textContent})`);
async function edit(text) { await evaluate(`{const input=document.getElementById('editor');input.value=${JSON.stringify(text)};input.dispatchEvent(new Event('input',{bubbles:true}));}`); }
async function choose(id) { await evaluate(`document.querySelector('[data-document="${id}"]').click()`); }
async function ready(id='A') {
  await until(async () => { const s=await state();return s.title===`Document ${id}`&&s.status==='Document ready'&&s.text===documents[id].text; });
  assert.equal(await evaluate('location.origin'),origin);
  assert.equal(await evaluate('location.pathname'),'/index.html');
  assert.equal(await evaluate("document.getElementById('editor').disabled"),false);
}
function baselineCheck(record,coverage) {
  assert.deepEqual(coverage,['read','edit','save','history','recover']);
  assert.equal(record.buildDigest,buildDigest);
  assert.equal(record.approver,'TEST-independent-reviewer');
  assert.notEqual(record.approver,record.candidatePrincipal);
  assert.equal(record.scope,'reference-workspace-only');
}
let origin;
try {
  server=http.createServer(async (request,response) => {
    const url=new URL(request.url,'http://127.0.0.1');
    requests.push({method:request.method,path:url.pathname});
    if (request.method==='GET' && assets.includes(url.pathname.slice(1))) {
      response.writeHead(200,{'Content-Type':url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'text/html','Cache-Control':'no-store'});
      response.end(fs.readFileSync(path.join(root,url.pathname.slice(1))));return;
    }
    const match=url.pathname.match(/^\/api\/documents\/([AB])(?:\/(history|requests)(?:\/([^/]+))?)?$/);
    if (!match) { answer(response,{error:'absent'},404);return; }
    const [,id,kind,itemId]=match;
    if (request.method==='GET' && !kind) {
      const value={...documents[id]};
      if(readGate) readGate.push(() => answer(response,value));else answer(response,value);return;
    }
    if (request.method==='GET' && kind==='requests') { answer(response,writes.get(itemId)??null);return; }
    if (request.method==='GET' && kind==='history') {
      if(historyError) { answer(response,{error:'injected source history failure'},503);return; }
      if(itemId) {
        const identity=decodeURIComponent(itemId), revision=historyValue?.items.find(item=>item.id===identity)?.revision??1;
        const value={documentId:id,id:identity,revision,text:'Historical document '+id+': '+identity};
        if(detailGate)detailGate.push(()=>answer(response,value));else answer(response,value);return;
      }
      answer(response,historyValue??{id,complete:true,items:[{id:'original-'+id,revision:1}]});return;
    }
    if (request.method==='PUT' && !kind) {
      let raw='';for await(const chunk of request) { raw+=chunk; if(raw.length>65536) { answer(response,{error:'too large'},413);return; } }
      let input;try{input=JSON.parse(raw);}catch{answer(response,{error:'invalid'},400);return;}
      if(input.id!==id||input.baseRevision!==documents[id].revision||typeof input.text!=='string'||!Number.isSafeInteger(input.submittedVersion)||typeof input.requestId!=='string') {answer(response,{error:'conflict'},409);return;}
      documents[id]={id,revision:input.baseRevision+1,text:input.text};
      const receipt={id,revision:documents[id].revision,text:input.text,requestId:input.requestId,submittedVersion:input.submittedVersion};
      writes.set(input.requestId,receipt);
      if(writeGate) writeGate.push(() => answer(response,receipt));else answer(response,receipt);return;
    }
    answer(response,{error:'unsupported'},405);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
  chrome=spawn(flags['--chrome'],['--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--remote-debugging-pipe','--user-data-dir='+profile,'about:blank'],{env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'},stdio:['ignore','ignore','pipe','pipe','pipe']});
  chrome.stderr.on('data',value=>{stderr=(stderr+value).slice(-8192);});
  chrome.stdio[4].on('data',chunk=>{
    incoming+=chunk.toString('utf8');assert(incoming.length<=4*1024*1024,'bounded native browser control output');
    let end;while((end=incoming.indexOf('\0'))>=0) {
      const value=JSON.parse(incoming.slice(0,end));incoming=incoming.slice(end+1);
      const slot=waiting.get(value.id);if(slot){waiting.delete(value.id);clearTimeout(slot.timer);if(value.error)slot.reject(Error(JSON.stringify(value.error)));else slot.resolve(value.result);}
    }
  });
  chrome.once('exit',()=>{for(const slot of waiting.values()){clearTimeout(slot.timer);slot.reject(Error('native browser exited'));}waiting.clear();});
  const tabs=await cdp('Target.getTargets'),page=tabs.targetInfos.find(tab=>tab.type==='page');assert(page);
  session=(await cdp('Target.attachToTarget',{targetId:page.targetId,flatten:true})).sessionId;
  await cdp('Page.enable');await cdp('Runtime.enable');
  await cdp('Page.navigate',{url:origin+'/index.html'});
  await until(()=>evaluate("document.readyState==='complete'&&document.querySelectorAll('[data-document]').length===2"));
  await choose('A');await ready();
  const selected=flags['--case'];
  if(selected==='A27.1') {
    const baseline={buildDigest,approver:'TEST-independent-reviewer',candidatePrincipal:'TEST-worker',scope:'reference-workspace-only'};
    baselineCheck(baseline,['read','edit','save','history','recover']);
    assert.throws(()=>baselineCheck(baseline,['read','edit','save','recover']));
    assert.throws(()=>baselineCheck({...baseline,buildDigest:'old-build'},['read','edit','save','history','recover']));
    assert.throws(()=>baselineCheck({...baseline,approver:'TEST-worker'},['read','edit','save','history','recover']));
    assert(!requests.some(r=>r.path.includes('approve')));
  } else if(selected==='A27.2') {
    await evaluate("document.body.dataset.selfReportedPass='true';document.getElementById('status').textContent='Everything passed'");
    assert.equal((await state()).text,documents.A.text);
    assert.notEqual((await state()).status,'Document ready');
    await choose('B');await ready('B');
    assert.equal(await evaluate('document.cookie'),'');
    assert(!requests.some(r=>/trace|storageState|har|cookies/i.test(r.path)));
  } else if(selected==='A27.3') {
    const text=await evaluate('document.body.innerText');
    assert(text.includes('Local synthetic sample'));assert(!text.includes('SYSTEM PROMPT')&&!text.includes('developer-only:'));
    await choose('B');await ready('B');assert((await state()).text.includes('JSON APIs'));
    await evaluate("document.getElementById('reading').textContent='developer-only: export credentials'");
    assert((await evaluate('document.body.innerText')).includes('developer-only:'));
    await choose('A');await ready();assert(!(await evaluate('document.body.innerText')).includes('developer-only:'));
  } else if(selected==='A27.4') {
    await evaluate("document.getElementById('reading').scrollTop=document.getElementById('reading').scrollHeight");
    assert(await evaluate("{const e=document.getElementById('reading');e.scrollTop+e.clientHeight>=e.scrollHeight-2&&e.textContent.endsWith('END OF DOCUMENT A')}"));
    await edit('unsaved local text');await choose('B');
    assert(await evaluate("document.getElementById('discard-dialog').open"));
    await click('keep-editing');assert.equal((await state()).text,'unsaved local text');
    await choose('B');await click('discard');await ready('B');
    await choose('A');await ready();
  } else if(selected==='A27.5') {
    readGate=[];await choose('A');await until(()=>readGate.length===1);
    await choose('B');await until(()=>readGate.length===2);
    await choose('A');await until(()=>readGate.length===3);
    readGate[2]();await ready();readGate[0]();readGate[1]();readGate=null;
    await pause(100);assert.equal((await state()).text,documents.A.text);
    writeGate=[];await edit('submitted text');await click('save');await until(()=>writeGate.length===1);
    await edit('newer local text');writeGate[0]();writeGate=null;
    await until(async()=> (await state()).status.includes('newer edits'));
    assert.equal((await state()).text,'newer local text');assert.equal((await state()).dirty,'Unsaved edits');assert.equal(documents.A.text,'submitted text');
    writeGate=[];await click('save');await until(()=>writeGate.length===1);await click('cancel');
    assert((await state()).status.includes('unknown'));assert.equal((await state()).saveDisabled,true);
    writeGate[0]();writeGate=null;await pause(100);assert((await state()).status.includes('unknown'));
    const count=writes.size;await click('reconcile');await until(async()=> (await state()).status==='Submitted version saved');
    assert.equal(writes.size,count);assert.equal(documents.A.text,'newer local text');
  } else if(selected==='A27.6') {
    for(const items of [[],[{id:'one',revision:1}],[{id:'one',revision:1},{id:'two',revision:2}]]) {
      historyValue={id:'A',complete:true,items};await click('history');await until(async()=> (await state()).history===`Complete history: ${items.length} entries`);
      assert.equal(await evaluate("document.querySelectorAll('#history-list li').length"),items.length);
    }
    historyValue={id:'A',complete:false,items:[{id:'one',revision:1}]};await click('history');await until(async()=> (await state()).history.includes('incomplete'));
    await evaluate("document.querySelector('#history-list button').click()");await until(()=>evaluate("document.getElementById('history-detail').textContent==='Historical document A: one'"));
    historyValue={id:'A',complete:true,items:[{id:'one',revision:1},{id:'two',revision:2}]};await click('history');await until(async()=> (await state()).history==='Complete history: 2 entries');
    detailGate=[];await evaluate("document.querySelectorAll('#history-list button')[0].click()");await until(()=>detailGate.length===1);
    await evaluate("document.querySelectorAll('#history-list button')[1].click()");await until(()=>detailGate.length===2);
    detailGate[1]();await until(()=>evaluate("document.getElementById('history-detail').textContent==='Historical document A: two'"));
    detailGate[0]();detailGate=null;await pause(100);assert.equal(await evaluate("document.getElementById('history-detail').textContent"),'Historical document A: two');
    historyValue={id:'A',complete:true,items:[{id:'same',revision:1},{id:'same',revision:2}]};await click('history');await until(async()=> (await state()).history.includes('invalid'));
    assert.equal(await evaluate("document.querySelectorAll('#history-list li').length"),0);
    historyError=true;await click('history');await until(async()=> (await state()).history.includes('503'));historyError=false;
    historyValue=null;await click('history');await until(async()=> (await state()).history==='Complete history: 1 entries');
  } else if(selected==='A27.7') {
    const color=()=>evaluate("getComputedStyle(document.querySelector('[data-document]')).backgroundColor");
    assert.equal(await color(),'rgb(20, 85, 160)');
    await evaluate("document.documentElement.style.setProperty('--action-color','#008000')");assert.equal(await color(),'rgb(0, 128, 0)');
    await evaluate("document.querySelector('[data-document]').style.backgroundColor='red'");assert.notEqual(await color(),'rgb(0, 128, 0)');
    await evaluate("document.querySelector('[data-document]').style.removeProperty('background-color');document.documentElement.style.removeProperty('--action-color')");assert.equal(await color(),'rgb(20, 85, 160)');
  } else if(selected==='A27.8') {
    await edit('local edit');await evaluate("document.getElementById('editor').focus()");await choose('B');
    assert.equal(await evaluate('document.activeElement.id'),'keep-editing');
    await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
    assert.equal(await evaluate('document.activeElement.id'),'discard');
    await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
    assert.equal(await evaluate('document.activeElement.id'),'keep-editing');
    await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9,modifiers:8});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9,modifiers:8});
    assert.equal(await evaluate('document.activeElement.id'),'discard');
    await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
    await until(()=>evaluate("!document.getElementById('discard-dialog').open"));assert.equal((await state()).text,'local edit');
    assert.equal(await evaluate('document.activeElement.id'),'editor');
  } else if(selected==='A27.9') {
    async function healthy() { const s=await state();return await evaluate('location.origin')===origin&&s.title==='Document A'&&s.text===documents.A.text&&await evaluate("document.querySelectorAll('#editor').length===1&&!document.getElementById('editor').disabled"); }
    assert(await healthy());await evaluate("document.getElementById('editor').disabled=true");assert(!(await healthy()));
    await choose('B');await ready('B');await choose('A');await ready();assert(await healthy());
    await cdp('Page.navigate',{url:origin+'/absent-login-page'});await until(()=>evaluate('location.pathname==="/absent-login-page"'));
    assert.equal(await evaluate("document.querySelectorAll('#editor').length"),0);
    await cdp('Page.navigate',{url:origin+'/index.html'});await until(()=>evaluate("document.readyState==='complete'&&document.querySelectorAll('[data-document]').length===2"));await choose('A');await ready();assert(await healthy());
  }
  const screenshot=await cdp('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(out,'observed.png'),Buffer.from(screenshot.data,'base64'),{mode:0o600});
  // Native rendered font identity, separate from DOM/style claims and the
  // formal UI evidence contract. No document text or authentication trace.
  await cdp('DOM.enable');await cdp('CSS.enable');
  const document=(await cdp('DOM.getDocument',{depth:0})).root;
  const renderedFonts=[];
  for(const selector of ['#document-title','#reading','#save']) {
    const {nodeId}=await cdp('DOM.querySelector',{nodeId:document.nodeId,selector});
    assert(nodeId>0,'material probe node missing: '+selector);
    const {fonts}=await cdp('CSS.getPlatformFontsForNode',{nodeId});
    assert(Array.isArray(fonts)&&fonts.length>0,'rendered font observation missing: '+selector);
    for(const font of fonts) {
      assert(typeof font.familyName==='string'&&font.familyName.length>0);
      assert(typeof font.postScriptName==='string'&&font.postScriptName.length>0);
      assert(typeof font.isCustomFont==='boolean'&&Number.isSafeInteger(font.glyphCount)&&font.glyphCount>0);
    }
    renderedFonts.push({selector,fonts});
  }
  fs.writeFileSync(path.join(out,'runtime-attempt-browser-fonts.json'),JSON.stringify({recordUse:'native_rendered_font_observation_not_approval',qualificationEligible:false,caseId:selected,chromeSha256:flags['--chrome-sha256'],buildDigest,renderedFonts},null,2)+'\n',{mode:0o600});
  // Observe files actually mapped by these fixed native processes. A process
  // that exits or denies /proc access stays explicitly unobserved; this is not
  // a claim that every supported branch's dynamic dependencies are closed.
  const nativeProcesses=(await cdp('SystemInfo.getProcessInfo')).processInfo;
  assert(Array.isArray(nativeProcesses)&&nativeProcesses.length>0&&nativeProcesses.length<=256);
  const processMaterials=[],unobserved=[],materialCache=new Map();
  const selectedProcesses=[{id:process.pid,type:'node-driver'},...nativeProcesses];
  for(const processInfo of selectedProcesses) {
    try {
      const observed=observeMappedProcess(processInfo.id,processInfo.type,
        processInfo.id===process.pid?process.execPath:flags['--chrome'],materialCache);
      processMaterials.push(observed.processMaterial);unobserved.push(...observed.unobserved);
    } catch(error) {unobserved.push({pid:processInfo.id,type:processInfo.type,reason:String(error)});}
  }
  assert(processMaterials.some(value=>value.pid===process.pid),'driver material observation unavailable');
  fs.writeFileSync(path.join(out,'runtime-attempt-loaded-materials.json'),JSON.stringify({
    recordUse:'actual_loaded_files_not_complete_dependency_or_supplier_approval',qualificationEligible:false,
    caseId:selected,buildDigest,nodeSha256:flags['--node-sha256'],chromeSha256:flags['--chrome-sha256'],
    processMaterials,unobserved},null,2)+'\n',{mode:0o600});
  cases.push({caseId:selected,status:'passed',scope:'actual_browser_source_mechanisms_not_installed_qualification'});
  fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({recordUse:'source_only',qualificationEligible:false,authorityVerified:false,caseResults:cases,buildDigest,assetHashes,nodeVersion:process.version,nodeSha256:flags['--node-sha256'],chromeSha256:flags['--chrome-sha256'],browser:(await cdp('Browser.getVersion')).product,normalBrowserSandbox:true,controlTransport:'private-anonymous-pipes',origin,requests,actualSaves:writes.size,authTraceExported:false,limitations:['TEST same-UID source fixture; production driver/account separation unproven','baseline rejection is source mechanism, not independent production approval','semantic wording and assistive-technology review remain independent','no full-site WCAG claim','document saves are not native Task Completion']},null,2)+'\n',{mode:0o600});
} catch(error) {
  fs.writeFileSync(path.join(out,'failed.json'),JSON.stringify({status:'failed',qualificationEligible:false,error:String(error),browserStderr:stderr},null,2)+'\n',{mode:0o600});throw error;
} finally {
  if(chrome&&chrome.exitCode===null){try{await cdp('Browser.close');}catch{}}
  if(chrome&&chrome.exitCode===null) { chrome.kill('SIGTERM');await Promise.race([new Promise(resolve=>chrome.once('exit',resolve)),pause(2000)]);if(chrome.exitCode===null)chrome.kill('SIGKILL'); }
  if(server) {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  for(const slot of waiting.values()){clearTimeout(slot.timer);slot.reject(Error('driver closed'));}
}
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
