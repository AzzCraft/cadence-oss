// Display state only. The server owns receipts; this page owns no approval.
const el = id => document.getElementById(id);
let selected = null, generation = 0, editVersion = 0, revision = null;
let dirty = false, busy = false, uncertain = false, active = null, pending = null;
let saveId = 0, historyId = 0, detailId = 0;
let pendingWrite = null;
const message = text => { el('status').textContent = text; };
function controls() {
  el('editor').disabled = !selected || revision === null;
  el('save').disabled = busy || uncertain || !dirty || revision === null;
  el('cancel').disabled = !busy;
  el('reconcile').disabled = !uncertain || !pendingWrite;
  el('history').disabled = !selected || revision === null;
  el('dirty').textContent = dirty ? 'Unsaved edits' : 'No unsaved edits';
}
async function checked(response) {
  if (!response.ok) throw Error(`Request failed (${response.status})`);
  return response.json();
}
async function load(id) {
  const turn = ++generation;
  active?.abort(); active = new AbortController(); const controller = active;
  selected = id; revision = null; dirty = false; uncertain = false; busy = true;
  editVersion = 0; ++historyId;
  el('document-title').textContent = `Document ${id}`;
  el('editor').value = ''; el('reading').textContent = '';
  el('history-list').replaceChildren(); el('history-status').textContent = 'Not loaded';
  el('history-detail').textContent = '';
  message('Loading document'); controls();
  try {
    const value = await checked(await fetch(`/api/documents/${id}`, {signal: controller.signal}));
    if (turn !== generation || selected !== id) return;
    if (value.id !== id || !Number.isSafeInteger(value.revision) || value.revision < 1 || typeof value.text !== 'string') throw Error('Document identity or content is invalid');
    revision = value.revision; el('editor').value = value.text; el('reading').textContent = value.text;
    message('Document ready');
  } catch (error) {
    if (turn === generation) message(error.name === 'AbortError' ? 'Loading stopped' : error.message);
  } finally {
    if (turn === generation) { busy = false; active = null; controls(); }
  }
}
function choose(id) {
  if (busy || uncertain) { message('Resolve the current request before changing documents'); return; }
  if (dirty) { pending = id; el('discard-dialog').showModal(); return; }
  load(id);
}
document.querySelectorAll('[data-document]').forEach(button => button.addEventListener('click', () => {
  // A pending read can be replaced. Saves and unknown outcomes cannot.
  if (busy && revision === null) { load(button.dataset.document); return; }
  choose(button.dataset.document);
}));
el('keep-editing').onclick = () => { pending = null; el('discard-dialog').close(); };
el('discard').onclick = () => { const id = pending; pending = null; el('discard-dialog').close(); if (id) load(id); };
el('discard-dialog').addEventListener('cancel', () => { pending = null; });
el('discard-dialog').addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const first = el('keep-editing'), last = el('discard');
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
});
el('editor').addEventListener('input', () => { ++editVersion; dirty = true; controls(); });
function settle(value, original) {
  if (value.id !== original.id || value.requestId !== original.requestId || value.submittedVersion !== original.version || value.revision !== original.baseRevision + 1 || value.text !== original.text) throw Error('Save receipt does not bind the submitted version');
  revision = value.revision; el('reading').textContent = original.text;
  dirty = editVersion !== original.version; uncertain = false; pendingWrite = null;
  message(dirty ? 'Submitted version saved; newer edits remain unsaved' : 'Submitted version saved');
}
el('save').onclick = async () => {
  if (el('save').disabled) return;
  const id = selected, turn = generation, version = editVersion;
  const text = el('editor').value, baseRevision = revision, operation = ++saveId;
  const requestId = crypto.randomUUID();
  pendingWrite = {id,turn,version,text,baseRevision,requestId}; const original = pendingWrite;
  active = new AbortController(); const controller = active; busy = true;
  message('Saving submitted version'); controls();
  try {
    const value = await checked(await fetch(`/api/documents/${id}`, {method:'PUT',signal:controller.signal,
      headers:{'Content-Type':'application/json'},body:JSON.stringify({id,text,baseRevision,submittedVersion:version,requestId})}));
    if (turn !== generation || selected !== id || operation !== saveId) return;
    settle(value, original);
  } catch (error) {
    if (turn === generation && operation === saveId) {
      // A rejected/lost response does not prove there was no remote effect.
      uncertain = true; message('Save outcome unknown. Inspect history before another save.');
    }
  } finally {
    if (turn === generation && operation === saveId) { busy = false; active = null; controls(); }
  }
};
el('cancel').onclick = () => {
  if (!busy) return;
  active?.abort(); active = null;
  if (revision === null) { ++generation; message('Loading stopped'); }
  else { ++saveId; uncertain = true; message('Request stopped locally; remote outcome unknown. Inspect history before another save.'); }
  busy = false; controls();
};
el('reconcile').onclick = async () => {
  const original = pendingWrite;
  if (!uncertain || !original) return;
  try {
    const value = await checked(await fetch(`/api/documents/${original.id}/requests/${original.requestId}`));
    if (pendingWrite !== original || selected !== original.id || generation !== original.turn) return;
    if (value === null) { message('Original save outcome remains unknown'); return; }
    settle(value, original); controls();
  } catch (error) { if (pendingWrite === original) message('Original save outcome remains unknown'); }
};
el('history').onclick = async () => {
  const id = selected, turn = generation, operation = ++historyId;
  el('history-status').textContent = 'Loading history'; el('history-list').replaceChildren();
  ++detailId; el('history-detail').textContent = '';
  try {
    const value = await checked(await fetch(`/api/documents/${id}/history`));
    if (turn !== generation || selected !== id || operation !== historyId) return;
    if (value.id !== id || !Array.isArray(value.items) || typeof value.complete !== 'boolean') throw Error('History identity or completeness is invalid');
    const ids = new Set();
    for (const item of value.items) {
      if (!item || typeof item.id !== 'string' || !item.id || ids.has(item.id) || !Number.isSafeInteger(item.revision) || item.revision < 1) throw Error('History item is invalid');
      ids.add(item.id);
      const li = document.createElement('li'), button = document.createElement('button');
      button.textContent = `${item.id}: revision ${item.revision}`;
      button.onclick = async () => {
        const detailOperation = ++detailId; el('history-detail').textContent = '';
        try {
          const detail = await checked(await fetch(`/api/documents/${id}/history/${encodeURIComponent(item.id)}`));
          if (turn !== generation || selected !== id || operation !== historyId || detailOperation !== detailId) return;
          if (detail.documentId !== id || detail.id !== item.id || detail.revision !== item.revision || typeof detail.text !== 'string') throw Error('History detail identity is invalid');
          el('history-detail').textContent = detail.text;
        } catch (error) { if (turn === generation && operation === historyId && detailOperation === detailId) el('history-status').textContent = error.message; }
      };
      li.append(button); el('history-list').append(li);
    }
    el('history-status').textContent = value.complete ? `Complete history: ${value.items.length} entries` : 'History incomplete; uniqueness and remote outcome are unknown';
    // A list is historical information, not an exact request settlement.
    // Unknown save remains blocked until installed explicit reconciliation.
  } catch (error) {
    if (turn === generation && operation === historyId) {
      el('history-list').replaceChildren(); el('history-status').textContent = error.message;
    }
  }
};
