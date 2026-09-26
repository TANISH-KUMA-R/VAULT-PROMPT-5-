// DISAULT / Vault Storage & Ingestion Client
// Optimized for Efficiency, Performance, and Strict Input Security

const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

const DANGEROUS_EXTS = new Set(['exe', 'bat', 'cmd', 'sh', 'vbs', 'msi', 'dll', 'com', 'scr', 'ps1']);
const MAX_CLIENT_FILE_SIZE = 50 * 1024 * 1024; // 50MB

let state = null;
let currentFilter = 'all';

// Pending file storage for upload dropzones
const pendingFiles = {
  doc: null,
  pay: null,
  det: null,
  allDoc: null,
  allPay: null
};

// Centralized API Client with Timeout & AbortController
async function api(path, options = {}) {
  const base = location.protocol === 'file:' ? 'http://localhost:4173/api' : '/api';
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 35000);

  try {
    const res = await fetch(base + path, {
      ...options,
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        ...(options.headers || {})
      }
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error('The API returned an unreadable response format.');
    }

    if (!res.ok) {
      throw new Error(data.error || `Request failed with HTTP status ${res.status}`);
    }

    return data;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Network request timed out. Please check cluster connectivity.');
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Formatters & Sanitizers
function humanBytes(n) {
  const num = Number(n);
  if (!num || isNaN(num) || num <= 0) return '0 B';
  if (num < 1024) return `${num} B`;
  if (num < 1048576) return `${(num / 1024).toFixed(1)} KB`;
  return `${(num / 1048576).toFixed(1)} MB`;
}

function ago(iso) {
  if (!iso) return 'just now';
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso)) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : `${Math.floor(s / 3600)}h ago`;
}

function esc(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function escAttr(s = '') {
  return esc(s);
}

function eventIcon(k) {
  return ({
    write: '↗',
    read: '✓',
    failure: '!',
    repair: '⤴',
    verify: '◉',
    policy: '⌘',
    delete: '×',
    corruption: '⚠'
  })[k] || '·';
}

function toast(message, error = false) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = message;
  el.style.color = error ? '#c3614b' : '#597e53';
  el.classList.add('visible');
  setTimeout(() => el.classList.remove('visible'), 4800);
}

// Client-side file validation and Base64 reading
function readFileAsData(file) {
  return new Promise((resolve, reject) => {
    if (!file) return reject(new Error('No file provided.'));

    // File size guard
    if (file.size > MAX_CLIENT_FILE_SIZE) {
      return reject(new Error(`File size (${humanBytes(file.size)}) exceeds the 50MB limit.`));
    }

    // Dangerous extension check
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (DANGEROUS_EXTS.has(ext)) {
      return reject(new Error(`Executable files ('.${ext}') are prohibited for security reasons.`));
    }

    const reader = new FileReader();
    reader.onload = () => {
      resolve({
        name: file.name.replace(/[\0\r\n\t\\/:*?"<>|]+/g, '_').slice(0, 120),
        size: file.size,
        type: file.type || 'application/octet-stream',
        data: reader.result
      });
    };
    reader.onerror = () => reject(new Error(`Failed to read file ${file.name}`));
    reader.readAsDataURL(file);
  });
}

// Dropzones Setup
function setupDropzones() {
  const zones = [
    { zone: $('#doc-dropzone'), input: $('#doc-file'), chip: $('#doc-file-chip'), key: 'doc' },
    { zone: $('#pay-dropzone'), input: $('#pay-file'), chip: $('#pay-file-chip'), key: 'pay' },
    { zone: $('#det-dropzone'), input: $('#det-file'), chip: $('#det-file-chip'), key: 'det' },
    { zone: $('#all-doc-dropzone'), input: $('#all-doc-file'), status: $('#all-doc-status'), key: 'allDoc' },
    { zone: $('#all-pay-dropzone'), input: $('#all-pay-file'), status: $('#all-pay-status'), key: 'allPay' }
  ];

  zones.forEach(({ zone, input, chip, status, key }) => {
    if (!zone || !input) return;

    zone.addEventListener('click', e => {
      if (e.target.closest('.chip-remove')) return;
      input.click();
    });

    zone.addEventListener('dragover', e => {
      e.preventDefault();
      zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));

    zone.addEventListener('drop', async e => {
      e.preventDefault();
      zone.classList.remove('dragover');
      if (e.dataTransfer?.files?.[0]) {
        await handleFileSelection(e.dataTransfer.files[0], key, chip, status, zone);
      }
    });

    input.addEventListener('change', async e => {
      if (e.target.files?.[0]) {
        await handleFileSelection(e.target.files[0], key, chip, status, zone);
      }
    });
  });

  // Event delegation for chip remove
  document.addEventListener('click', e => {
    const rm = e.target.closest('.chip-remove');
    if (!rm) return;
    const key = rm.dataset.remove;
    if (key && pendingFiles[key] !== undefined) {
      pendingFiles[key] = null;
      const chip = $(`#${key}-file-chip`);
      if (chip) chip.style.display = 'none';
      const prompt = $(`#${key}-dropzone .dropzone-prompt`);
      if (prompt) prompt.style.display = 'flex';
      const input = $(`#${key}-file`);
      if (input) input.value = '';
      toast(`Removed attachment.`);
    }
  });
}

async function handleFileSelection(file, key, chip, status, zone) {
  try {
    const fileData = await readFileAsData(file);
    pendingFiles[key] = fileData;

    if (chip) {
      const nameEl = chip.querySelector('.chip-name');
      const sizeEl = chip.querySelector('.chip-size');
      if (nameEl) nameEl.textContent = fileData.name;
      if (sizeEl) sizeEl.textContent = humanBytes(fileData.size);
      chip.style.display = 'flex';
      const prompt = zone.querySelector('.dropzone-prompt');
      if (prompt) prompt.style.display = 'none';
    }

    if (status) {
      status.textContent = `✓ ${fileData.name.slice(0, 16)}… (${humanBytes(fileData.size)})`;
      status.style.color = '#52752b';
    }

    toast(`File attached: ${fileData.name} (${humanBytes(fileData.size)})`);
  } catch (err) {
    toast(err.message, true);
  }
}

// Render Submissions Stream with high-performance fragment
function renderSubmissions(submissions = []) {
  const listEl = $('#submissions-list');
  if (!listEl) return;

  // Update counters
  const total = submissions.length;
  const docCount = submissions.filter(s => s.type === 'document').length;
  const payCount = submissions.filter(s => s.type === 'payment').length;
  const detCount = submissions.filter(s => s.type === 'details').length;
  const allCount = submissions.filter(s => s.type === 'everything').length;

  if ($('#count-all')) $('#count-all').textContent = total;
  if ($('#count-doc')) $('#count-doc').textContent = docCount;
  if ($('#count-pay')) $('#count-pay').textContent = payCount;
  if ($('#count-det')) $('#count-det').textContent = detCount;
  if ($('#count-allinone')) $('#count-allinone').textContent = allCount;

  const filtered = currentFilter === 'all'
    ? submissions
    : submissions.filter(s => s.type === currentFilter);

  if (!filtered.length) {
    listEl.innerHTML = `<div class="empty-state">No ${currentFilter === 'all' ? '' : currentFilter} submissions in the vault yet. Use the upload forms above to submit your first record.</div>`;
    return;
  }

  const badgeClassMap = {
    document: 'badge-doc',
    payment: 'badge-pay',
    details: 'badge-det',
    everything: 'badge-all'
  };

  const typeLabelMap = {
    document: 'DOCUMENT',
    payment: 'PAYMENT',
    details: 'DETAILS',
    everything: 'ALL-IN-ONE'
  };

  listEl.innerHTML = filtered.map(s => {
    const title = s.title || s.reference || s.fullName || 'Untitled Submission';
    let fileMeta = '';
    let downloadPart = '';

    if (s.file) {
      fileMeta = `📎 ${esc(s.file.name)} (${humanBytes(s.file.size)})`;
    } else if (s.document?.file) {
      fileMeta = `📄 ${esc(s.document.file.name)}`;
      downloadPart = 'document';
    } else if (s.payment?.file) {
      fileMeta = `💳 ${esc(s.payment.file.name)}`;
      downloadPart = 'payment';
    }

    const badgeClass = badgeClassMap[s.type] || 'badge-doc';
    const typeLabel = typeLabelMap[s.type] || s.type;

    return `
      <div class="submission-card-item">
        <div class="sub-meta-group">
          <span class="sub-badge ${badgeClass}">${typeLabel}</span>
          <div class="sub-details">
            <span class="sub-title">${esc(title)}</span>
            <div class="sub-specs">
              ${fileMeta ? `<span>${fileMeta}</span> ·` : ''}
              <span>${s.replicas || 3}× replicas</span> ·
              <span class="sub-checksum" title="SHA-256 Checksum">sha ${esc(s.checksum || 'valid')}</span> ·
              <span>${ago(s.createdAt)}</span>
            </div>
          </div>
        </div>
        <div class="sub-actions">
          <button class="btn-sub-action" data-inspect="${escAttr(s.id)}" title="Inspect details and preview">👁 View</button>
          <a class="btn-sub-action" href="${(location.protocol==='file:'?'http://localhost:4173/api':'/api')}/submissions/${escAttr(s.id)}/file${downloadPart ? `?part=${downloadPart}` : ''}" target="_blank" rel="noopener noreferrer" download title="Download raw file attachment">⬇ File</a>
          <button class="btn-sub-del" data-delete-sub="${escAttr(s.id)}" title="Delete submission">&times;</button>
        </div>
      </div>
    `;
  }).join('');
}

// Modal Inspector
async function openInspectionModal(id) {
  try {
    const res = await api(`/submissions/${encodeURIComponent(id)}`);
    const sub = res.submission;
    if (!sub) return;

    const modal = $('#preview-modal');
    $('#modal-title').textContent = sub.title || sub.reference || sub.fullName || 'Submission Details';
    $('#modal-type-badge').textContent = sub.type.toUpperCase();

    const attachedFile = sub.file || sub.document?.file || sub.payment?.file || sub.details?.file;
    const downloadBtn = $('#modal-download-btn');

    if (attachedFile?.data) {
      downloadBtn.style.display = 'inline-flex';
      downloadBtn.href = `${(location.protocol==='file:'?'http://localhost:4173/api':'/api')}/submissions/${encodeURIComponent(sub.id)}/file`;
      downloadBtn.download = attachedFile.name || 'submission-file';
      downloadBtn.textContent = `⬇ Download ${attachedFile.name || 'file'}`;
    } else {
      downloadBtn.style.display = 'none';
    }

    let previewHTML = '';
    if (attachedFile?.data && typeof attachedFile.data === 'string') {
      if (attachedFile.data.startsWith('data:image/')) {
        previewHTML = `
          <div class="modal-preview-box">
            <img src="${escAttr(attachedFile.data)}" alt="${escAttr(attachedFile.name)}" />
          </div>
        `;
      } else if (attachedFile.data.startsWith('data:application/pdf')) {
        previewHTML = `
          <div class="modal-preview-box">
            <div>
              <div style="font-size:32px;margin-bottom:8px;">📄</div>
              <b>${esc(attachedFile.name)}</b>
              <p style="font-size:11px;color:#777;margin:4px 0 10px;">PDF Document (${humanBytes(attachedFile.size)})</p>
              <a href="${escAttr(attachedFile.data)}" target="_blank" rel="noopener noreferrer" class="button button-dark" style="padding:6px 12px;font-size:10px;">Open in viewer ↗</a>
            </div>
          </div>
        `;
      }
    }

    const rows = [
      ['SUBMISSION ID', sub.id],
      ['CHANNEL TYPE', sub.type.toUpperCase()],
      ['SHA-256 HASH', sub.checksum || 'N/A'],
      ['CLUSTER REPLICAS', `${sub.replicas} copies placed across independent zones`],
      ['INTEGRITY STATUS', sub.healthy ? '✓ Verified clean' : '⚠ Check needed'],
      ['TIMESTAMP', new Date(sub.createdAt).toLocaleString()]
    ];

    if (sub.category) rows.push(['CATEGORY', sub.category]);
    if (sub.reference) rows.push(['TRANSACTION REF', sub.reference]);
    if (sub.amount) rows.push(['PAYMENT AMOUNT', `${sub.amount} ${sub.currency || 'USD'} via ${sub.method || 'Credit Card'}`]);
    if (sub.fullName) rows.push(['FULL NAME / ORG', sub.fullName]);
    if (sub.email) rows.push(['EMAIL', sub.email]);
    if (sub.accountNumber) rows.push(['ACCOUNT #', sub.accountNumber]);
    if (sub.details || sub.notes) rows.push(['NOTES / SPEC', sub.details || sub.notes]);

    const tableHTML = `
      <table class="modal-meta-table">
        <tbody>
          ${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}
        </tbody>
      </table>
    `;

    $('#modal-body').innerHTML = previewHTML + tableHTML;
    modal.style.display = 'flex';
  } catch (err) {
    toast(`Failed to load submission: ${err.message}`, true);
  }
}

function closeModal() {
  const modal = $('#preview-modal');
  if (modal) modal.style.display = 'none';
}

// Master Render
function render() {
  if (!state) return;
  const { nodes, objects, events, policy, stats, submissions } = state;

  $('#connection-label').textContent = 'API connected';
  $('#lab-status').textContent = 'Live cluster · in sync';
  $('#hero-nodes').textContent = stats.healthyNodes;
  $('#hero-objects').textContent = stats.totalObjects;
  if ($('#hero-submissions')) $('#hero-submissions').textContent = stats.totalSubmissions || (submissions?.length || 0);
  $('#hero-replicas').textContent = `${policy.replicas}×`;

  $('#fleet-count').textContent = `${stats.healthyNodes} / ${stats.totalNodes} ONLINE`;
  $('#write-policy').textContent = `${policy.replicas} replicas`;
  $('#replicas').value = policy.replicas;
  $('#replica-value').textContent = policy.replicas;
  $('#write-quorum').max = policy.replicas;
  $('#write-quorum').value = Math.min(policy.writeQuorum, policy.replicas);
  $('#quorum-value').textContent = $('#write-quorum').value;
  $('#space-amplification').textContent = `${policy.replicas}.0×`;

  // Render Storage nodes
  $('#node-list').innerHTML = nodes.map(n => `
    <div class="node-row ${n.state === 'offline' ? 'offline' : ''}">
      <div class="node-identity">
        <span class="node-glyph">▤</span>
        <div class="node-details">
          <b>${esc(n.id)}</b>
          <small>${esc(n.zone)} · ${n.latency} ms</small>
        </div>
      </div>
      <span class="node-health"><i></i>${n.state === 'healthy' ? 'healthy' : 'offline'}</span>
      <button class="node-toggle" data-node="${escAttr(n.id)}">${n.state === 'healthy' ? 'Take offline' : 'Bring online'}</button>
    </div>
  `).join('');

  $('#nodes-map').innerHTML = nodes.map(n => `
    <div class="node-chip">${esc(n.id)} <i style="background:${n.state === 'healthy' ? '#80b579' : '#e87957'}"></i></div>
  `).join('');

  // Render Low-level raw objects
  $('#object-list').innerHTML = objects.length ? objects.slice(0, 8).map(o => `
    <div class="object-row">
      <div class="object-info">
        <span class="object-key">${esc(o.key)}</span>
        <span class="object-meta">v${o.version} · ${humanBytes(o.size)} · ${o.replicas} replicas · ${ago(o.updatedAt)}</span>
      </div>
      <div class="object-actions">
        <span class="object-health">${o.healthy ? '✓ verified' : '! check needed'}</span>
        <button class="object-btn" title="Read and verify object" data-read="${escAttr(o.id)}">↗</button>
        <button class="object-btn" title="Delete object" data-delete="${escAttr(o.id)}">×</button>
      </div>
    </div>
  `).join('') : '<div class="empty-state">Nothing stored yet. Write an object or submit a document/payment above.</div>';

  // Render Journal events
  $('#event-list').innerHTML = events.length ? events.slice(0, 8).map(e => `
    <div class="event-item">
      <span class="event-kind">${eventIcon(e.kind)}</span>
      <div>
        <div class="event-text">${esc(e.message)}</div>
        <div class="event-time">${ago(e.time)}</div>
      </div>
    </div>
  `).join('') : '<div class="empty-state">The journal is quiet. That’s a good sign.</div>';

  $('#connection-label').style.color = '#688f62';
  renderSubmissions(submissions || []);
}

// API Refresh
async function refresh() {
  try {
    state = await api('/state');
    render();
  } catch (e) {
    $('#connection-label').textContent = 'API offline';
    $('#lab-status').textContent = 'Could not reach DISAULT API';
    $('#connection-label').style.color = '#d26f52';
  }
}

// ----------------------------------------------------
// Setup Submission Forms
// ----------------------------------------------------
function setupSubmissionForms() {
  // 1. Document Submit (Button 1)
  $('#form-doc')?.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#btn-submit-doc');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Submitting to Vault…';

    try {
      const payload = {
        title: $('#doc-title').value.trim(),
        category: $('#doc-category').value,
        notes: $('#doc-notes').value.trim(),
        file: pendingFiles.doc
      };

      const res = await api('/submissions/document', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      toast(`Document submitted: “${res.submission.title}” · SHA ${res.submission.checksum}`);
      $('#form-doc').reset();
      pendingFiles.doc = null;
      if ($('#doc-file-chip')) $('#doc-file-chip').style.display = 'none';
      if ($('#doc-dropzone .dropzone-prompt')) $('#doc-dropzone .dropzone-prompt').style.display = 'flex';
      await refresh();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>📄</span> Upload &amp; Submit Document <span>↗</span>';
    }
  });

  // 2. Payment Submit (Button 2)
  $('#form-pay')?.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#btn-submit-pay');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Submitting Payment…';

    try {
      const payload = {
        reference: $('#pay-ref').value.trim(),
        amount: $('#pay-amount').value.trim(),
        currency: $('#pay-currency').value,
        method: $('#pay-method').value,
        notes: $('#pay-notes').value.trim(),
        file: pendingFiles.pay
      };

      const res = await api('/submissions/payment', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      toast(`Payment submitted: ${res.submission.reference} (${res.submission.amount} ${res.submission.currency}) · SHA ${res.submission.checksum}`);
      $('#form-pay').reset();
      pendingFiles.pay = null;
      if ($('#pay-file-chip')) $('#pay-file-chip').style.display = 'none';
      if ($('#pay-dropzone .dropzone-prompt')) $('#pay-dropzone .dropzone-prompt').style.display = 'flex';
      await refresh();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>💳</span> Upload &amp; Submit Payment <span>↗</span>';
    }
  });

  // 3. Details Submit (Button 3)
  $('#form-det')?.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#btn-submit-det');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Submitting Details…';

    try {
      const payload = {
        fullName: $('#det-name').value.trim(),
        email: $('#det-email').value.trim(),
        accountNumber: $('#det-account').value.trim(),
        category: $('#det-category').value,
        details: $('#det-notes').value.trim(),
        file: pendingFiles.det
      };

      const res = await api('/submissions/details', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      toast(`Details submitted: ${res.submission.fullName || res.submission.email} · SHA ${res.submission.checksum}`);
      $('#form-det').reset();
      pendingFiles.det = null;
      if ($('#det-file-chip')) $('#det-file-chip').style.display = 'none';
      if ($('#det-dropzone .dropzone-prompt')) $('#det-dropzone .dropzone-prompt').style.display = 'flex';
      await refresh();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>📋</span> Upload &amp; Submit Details <span>↗</span>';
    }
  });

  // 4. Everything Submit (Button 4)
  $('#form-all')?.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#btn-submit-all');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Sealing &amp; Submitting Everything…';

    try {
      const payload = {
        title: 'Comprehensive Package Submission',
        document: {
          title: $('#all-doc-title').value.trim() || 'Attached Document',
          category: 'Package Document',
          file: pendingFiles.allDoc || pendingFiles.doc
        },
        payment: {
          reference: $('#all-pay-ref').value.trim() || `TX-${Math.floor(100000 + Math.random() * 900000)}`,
          amount: $('#all-pay-amount').value.trim() || '0.00',
          currency: 'USD',
          method: 'Credit Card',
          file: pendingFiles.allPay || pendingFiles.pay
        },
        details: {
          fullName: $('#all-det-name').value.trim(),
          email: $('#all-det-email').value.trim(),
          notes: $('#all-det-notes').value.trim()
        }
      };

      const res = await api('/submissions/everything', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      toast(`Everything submitted: Complete package sealed · SHA ${res.submission.checksum}`);
      $('#form-all').reset();
      pendingFiles.allDoc = null;
      pendingFiles.allPay = null;
      if ($('#all-doc-status')) { $('#all-doc-status').textContent = '📎 Attach Doc'; $('#all-doc-status').style.color = ''; }
      if ($('#all-pay-status')) { $('#all-pay-status').textContent = '🧾 Attach Receipt'; $('#all-pay-status').style.color = ''; }
      await refresh();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>⚡</span> Submit Everything (All-in-One) <span>↗</span>';
    }
  });

  // Generate Reference Button
  $('#btn-gen-ref')?.addEventListener('click', () => {
    const ref = `TX-${Math.floor(100000 + Math.random() * 900000)}`;
    $('#pay-ref').value = ref;
    toast(`Generated reference: ${ref}`);
  });

  // Sync bundle values
  $('#btn-sync-bundle')?.addEventListener('click', () => {
    $('#all-doc-title').value = $('#doc-title').value;
    $('#all-pay-ref').value = $('#pay-ref').value;
    $('#all-pay-amount').value = $('#pay-amount').value;
    $('#all-det-name').value = $('#det-name').value;
    $('#all-det-email').value = $('#det-email').value;
    $('#all-det-notes').value = $('#det-notes').value;

    if (pendingFiles.doc) {
      pendingFiles.allDoc = pendingFiles.doc;
      $('#all-doc-status').textContent = `✓ ${pendingFiles.doc.name.slice(0, 16)}…`;
      $('#all-doc-status').style.color = '#52752b';
    }
    if (pendingFiles.pay) {
      pendingFiles.allPay = pendingFiles.pay;
      $('#all-pay-status').textContent = `✓ ${pendingFiles.pay.name.slice(0, 16)}…`;
      $('#all-pay-status').style.color = '#52752b';
    }

    toast('Synced fields into Everything package.');
  });

  // Demo Data Generator
  $('#demo-data-btn')?.addEventListener('click', () => {
    $('#doc-title').value = 'International Passport - Verification Copy';
    $('#doc-category').value = 'Identification';
    $('#doc-notes').value = 'High-resolution scan verified against government database';
    pendingFiles.doc = {
      name: 'passport_scan.pdf',
      size: 245100,
      type: 'application/pdf',
      data: 'data:application/pdf;base64,' + btoa('%PDF-1.4 demo passport content verification')
    };
    if ($('#doc-file-chip')) {
      $('#doc-file-chip').querySelector('.chip-name').textContent = 'passport_scan.pdf';
      $('#doc-file-chip').querySelector('.chip-size').textContent = '239.4 KB';
      $('#doc-file-chip').style.display = 'flex';
      $('#doc-dropzone .dropzone-prompt').style.display = 'none';
    }

    $('#pay-ref').value = `TX-${Math.floor(100000 + Math.random() * 900000)}`;
    $('#pay-amount').value = '1450.00';
    $('#pay-currency').value = 'USD';
    $('#pay-method').value = 'Wire Transfer';
    $('#pay-notes').value = 'Annual infrastructure licensing retainer';
    pendingFiles.pay = {
      name: 'wire_receipt.png',
      size: 89300,
      type: 'image/png',
      data: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkWPjfDwAEeQHzk4tHlwAAAABJRU5ErkJggg=='
    };
    if ($('#pay-file-chip')) {
      $('#pay-file-chip').querySelector('.chip-name').textContent = 'wire_receipt.png';
      $('#pay-file-chip').querySelector('.chip-size').textContent = '87.2 KB';
      $('#pay-file-chip').style.display = 'flex';
      $('#pay-dropzone .dropzone-prompt').style.display = 'none';
    }

    $('#det-name').value = 'Elena Rostova';
    $('#det-email').value = 'elena.rostova@acme-systems.org';
    $('#det-account').value = 'ACC-2026-GLOBAL';
    $('#det-category').value = 'Customer KYC';
    $('#det-notes').value = 'Enterprise Tier 1 verified client. All compliance documents vetted.';

    $('#all-doc-title').value = 'Articles of Association';
    $('#all-pay-ref').value = `TX-${Math.floor(100000 + Math.random() * 900000)}`;
    $('#all-pay-amount').value = '5000.00';
    $('#all-det-name').value = 'Acme Holdings Ltd';
    $('#all-det-email').value = 'corp@acme-holdings.ltd';
    $('#all-det-notes').value = 'Full corporate onboarding bundle with legal and payment proof';
    pendingFiles.allDoc = pendingFiles.doc;
    pendingFiles.allPay = pendingFiles.pay;
    if ($('#all-doc-status')) { $('#all-doc-status').textContent = '✓ passport_scan.pdf'; $('#all-doc-status').style.color = '#52752b'; }
    if ($('#all-pay-status')) { $('#all-pay-status').textContent = '✓ wire_receipt.png'; $('#all-pay-status').style.color = '#52752b'; }

    toast('Filled all 4 channels with realistic demo data.');
  });

  // View Switcher Tabs
  $$('.sub-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.sub-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const view = tab.dataset.view;
      const cards = {
        doc: $('#card-doc'),
        pay: $('#card-pay'),
        det: $('#card-det'),
        all: $('#card-all')
      };

      if (view === 'grid') {
        Object.values(cards).forEach(c => { if (c) c.style.display = 'flex'; });
        $('#submissions-grid').style.gridTemplateColumns = 'repeat(2, 1fr)';
      } else {
        Object.entries(cards).forEach(([k, c]) => {
          if (!c) return;
          c.style.display = k === view ? 'flex' : 'none';
        });
        $('#submissions-grid').style.gridTemplateColumns = '1fr';
      }
    });
  });

  // Stream filter pills
  $$('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      $$('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.dataset.filter || 'all';
      if (state) renderSubmissions(state.submissions || []);
    });
  });

  // Stream action delegation
  $('#submissions-list')?.addEventListener('click', async e => {
    const inspectBtn = e.target.closest('[data-inspect]');
    const delBtn = e.target.closest('[data-delete-sub]');

    if (inspectBtn) {
      openInspectionModal(inspectBtn.dataset.inspect);
    } else if (delBtn) {
      if (!confirm('Are you sure you want to delete this submission from the vault?')) return;
      try {
        await api(`/submissions/${encodeURIComponent(delBtn.dataset.deleteSub)}`, { method: 'DELETE' });
        toast('Submission removed from vault.');
        await refresh();
      } catch (err) {
        toast(err.message, true);
      }
    }
  });

  // Modal handlers
  $('#modal-close-btn')?.addEventListener('click', closeModal);
  $('#modal-dismiss-btn')?.addEventListener('click', closeModal);
  $('#preview-modal')?.addEventListener('click', e => {
    if (e.target.id === 'preview-modal') closeModal();
  });
  window.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
  });

  $('#refresh-submissions-btn')?.addEventListener('click', refresh);
}

// ----------------------------------------------------
// Cluster Controls Setup
// ----------------------------------------------------
function setupClusterControls() {
  $('#object-form')?.addEventListener('submit', async e => {
    e.preventDefault();
    const formElement = e.currentTarget;
    const form = new FormData(formElement);
    const btn = formElement.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const r = await api('/objects', {
        method: 'POST',
        body: JSON.stringify({ key: form.get('key'), value: form.get('value') })
      });
      toast(`Saved v${r.object.version} · SHA ${r.object.checksum}`);
      formElement.reset();
      await refresh();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  $('#node-list')?.addEventListener('click', async e => {
    const b = e.target.closest('[data-node]');
    if (!b) return;
    try {
      state = await api(`/nodes/${encodeURIComponent(b.dataset.node)}/failure`, { method: 'POST', body: '{}' });
      render();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $('#replicas')?.addEventListener('input', e => {
    const n = +e.target.value;
    $('#replica-value').textContent = n;
    $('#write-quorum').max = n;
    if (+$('#write-quorum').value > n) $('#write-quorum').value = n;
    $('#quorum-value').textContent = $('#write-quorum').value;
    $('#space-amplification').textContent = `${n}.0×`;
  });

  $('#write-quorum')?.addEventListener('input', e => {
    $('#quorum-value').textContent = e.target.value;
  });

  $('#save-policy')?.addEventListener('click', async () => {
    try {
      state = await api('/policy', {
        method: 'PUT',
        body: JSON.stringify({ replicas: +$('#replicas').value, writeQuorum: +$('#write-quorum').value })
      });
      render();
      toast('Durability policy saved.');
    } catch (e) {
      toast(e.message, true);
    }
  });

  $('#object-list')?.addEventListener('click', async e => {
    const read = e.target.closest('[data-read]');
    const del = e.target.closest('[data-delete]');
    try {
      if (read) {
        const r = await api(`/objects/${encodeURIComponent(read.dataset.read)}`);
        toast(`Read verified · ${r.key} · SHA ${r.checksum}`);
      }
      if (del) {
        await api(`/objects/${encodeURIComponent(del.dataset.delete)}`, { method: 'DELETE' });
        await refresh();
      }
    } catch (err) {
      toast(err.message, true);
    }
  });

  $('#verify-btn')?.addEventListener('click', async () => {
    try {
      const r = await api('/verify', { method: 'POST', body: '{}' });
      $('#integrity-result').innerHTML = `Last sweep <span>${r.checked} checked · ${r.corrupt} mismatches</span>`;
      toast(r.corrupt ? `${r.corrupt} checksum mismatch detected.` : `${r.checked} objects verified clean.`, !!r.corrupt);
      state = r;
      render();
    } catch (e) {
      toast(e.message, true);
    }
  });

  $('#repair-btn')?.addEventListener('click', async () => {
    try {
      const r = await api('/repair', { method: 'POST', body: '{}' });
      $('#integrity-result').innerHTML = `Last repair <span>${r.repaired} objects healed</span>`;
      toast(`Repair pass complete · ${r.repaired} objects healed.`);
      state = r;
      render();
    } catch (e) {
      toast(e.message, true);
    }
  });

  $('#refresh-btn')?.addEventListener('click', refresh);
  $('#theme-toggle')?.addEventListener('click', () => document.body.classList.toggle('dark'));
}

// Initialize Application
setupDropzones();
setupSubmissionForms();
setupClusterControls();
refresh();
setInterval(refresh, 8000);
