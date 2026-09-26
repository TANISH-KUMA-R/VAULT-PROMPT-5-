import http from 'node:http';
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(root, 'data');
const dbPath = path.join(dataDir, 'vault.json');
const PORT = Number(process.env.PORT || 4173);

// Whitelists & Security Configuration
const ALLOWED_CURRENCIES = new Set(['USD', 'EUR', 'GBP', 'INR', 'CAD', 'AUD', 'BTC', 'ETH', 'JPY', 'CHF']);
const DANGEROUS_EXTENSIONS = new Set(['exe', 'bat', 'cmd', 'sh', 'vbs', 'msi', 'dll', 'com', 'scr', 'ps1']);
const MAX_PAYLOAD_BYTES = 50_000_000; // 50MB
const REQUEST_TIMEOUT_MS = 30_000; // 30s

const SECURITY_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Access-Control-Allow-Origin': '*',
  'Cache-Control': 'no-store'
});

const defaults = () => ({
  policy: { replicas: 3, writeQuorum: 2, readQuorum: 2, failureDomain: 'zone', repairMode: 'balanced' },
  nodes: [
    { id: 'osd-01', zone: 'west-1a', state: 'healthy', capacity: 18, used: 11.2, latency: 12 },
    { id: 'osd-02', zone: 'west-1b', state: 'healthy', capacity: 18, used: 9.6, latency: 18 },
    { id: 'osd-03', zone: 'east-1a', state: 'healthy', capacity: 24, used: 13.1, latency: 24 },
    { id: 'osd-04', zone: 'east-1b', state: 'healthy', capacity: 24, used: 8.7, latency: 31 },
    { id: 'osd-05', zone: 'north-1a', state: 'healthy', capacity: 32, used: 17.4, latency: 16 },
    { id: 'osd-06', zone: 'north-1b', state: 'healthy', capacity: 32, used: 14.3, latency: 21 }
  ],
  objects: [],
  events: [],
  submissions: []
});

await mkdir(dataDir, { recursive: true });
let db;
try {
  db = JSON.parse(await readFile(dbPath, 'utf8'));
} catch {
  db = defaults();
}
if (!Array.isArray(db.submissions)) db.submissions = [];

// Atomic persistence with crash-resilient temporary file swapping
let writeQueue = Promise.resolve();
function persist() {
  const tempPath = `${dbPath}.${randomUUID()}.tmp`;
  writeQueue = writeQueue.then(async () => {
    await writeFile(tempPath, JSON.stringify(db, null, 2), 'utf8');
    await rename(tempPath, dbPath);
  });
  return writeQueue;
}

function event(kind, message) {
  db.events.unshift({
    id: randomUUID(),
    kind: String(kind || 'info').slice(0, 32),
    message: String(message || '').slice(0, 300),
    time: new Date().toISOString()
  });
  db.events = db.events.slice(0, 60);
}

function checksum(body) {
  return createHash('sha256').update(body || '').digest('hex').slice(0, 16);
}

// Sanitization & Validation Utilities
function sanitizeFilename(name, fallback = 'file.dat') {
  if (typeof name !== 'string') return fallback;
  const cleaned = name.replace(/[\0\r\n\t\\/:*?"<>|]+/g, '_').trim();
  const ext = cleaned.split('.').pop()?.toLowerCase();
  if (ext && DANGEROUS_EXTENSIONS.has(ext)) {
    throw new Error(`File extension '.${ext}' is restricted for security reasons.`);
  }
  return cleaned.slice(0, 120) || fallback;
}

function sanitizeText(val, maxLen = 300, fallback = '') {
  if (val == null) return fallback;
  return String(val).trim().slice(0, maxLen);
}

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim()) && email.length <= 120;
}

function parseValidAmount(amt) {
  if (amt == null) return '0.00';
  const n = Number(amt);
  if (isNaN(n) || !isFinite(n) || n < 0 || n > 1_000_000_000) {
    throw new Error('Payment amount must be a positive number up to 1,000,000,000.');
  }
  return n.toFixed(2);
}

function stripFileData(s) {
  if (!s) return null;
  const copy = structuredClone(s);
  const strip = f => (f?.data ? { name: f.name, size: f.size, type: f.type, checksum: f.checksum } : f);
  if (copy.file) copy.file = strip(copy.file);
  if (copy.document?.file) copy.document.file = strip(copy.document.file);
  if (copy.payment?.file) copy.payment.file = strip(copy.payment.file);
  if (copy.details?.file) copy.details.file = strip(copy.details.file);
  return copy;
}

const json = (res, code, body) => {
  res.writeHead(code, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8'
  });
  res.end(JSON.stringify(body));
};

// Stream-based Request Body Parser with timeout & memory optimization
const bodyOf = (req, maxBytes = MAX_PAYLOAD_BYTES, timeoutMs = REQUEST_TIMEOUT_MS) => new Promise((resolve, reject) => {
  let size = 0;
  const chunks = [];
  const timer = setTimeout(() => {
    req.destroy();
    reject(new Error('Request timed out.'));
  }, timeoutMs);

  req.on('data', chunk => {
    size += chunk.length;
    if (size > maxBytes) {
      clearTimeout(timer);
      req.destroy();
      reject(new Error(`Payload too large (max ${(maxBytes / (1024 * 1024)).toFixed(0)}MB).`));
    } else {
      chunks.push(chunk);
    }
  });

  req.on('end', () => {
    clearTimeout(timer);
    try {
      const raw = Buffer.concat(chunks).toString('utf8');
      resolve(raw ? JSON.parse(raw) : {});
    } catch {
      reject(new Error('Invalid JSON payload.'));
    }
  });

  req.on('error', err => {
    clearTimeout(timer);
    reject(err);
  });
});

function storeObject(key, value) {
  const alive = db.nodes.filter(n => n.state === 'healthy').length;
  if (alive < db.policy.writeQuorum) {
    throw new Error(`Write quorum unavailable: ${alive}/${db.policy.writeQuorum} healthy nodes.`);
  }
  const hash = checksum(value);
  const old = db.objects.find(o => o.key === key);
  const obj = {
    id: old?.id || randomUUID(),
    key,
    size: Buffer.byteLength(value),
    checksum: hash,
    version: (old?.version || 0) + 1,
    replicas: Math.min(db.policy.replicas, alive),
    healthy: true,
    updatedAt: new Date().toISOString(),
    body: value
  };
  if (old) Object.assign(old, obj);
  else db.objects.unshift(obj);
  return obj;
}

const summary = () => ({
  policy: db.policy,
  nodes: db.nodes,
  objects: db.objects.map(o => ({ ...o, body: undefined })),
  submissions: (db.submissions || []).map(stripFileData),
  events: db.events,
  stats: {
    totalObjects: db.objects.length,
    totalSubmissions: (db.submissions || []).length,
    logicalBytes: db.objects.reduce((n, o) => n + o.size, 0),
    healthyNodes: db.nodes.filter(n => n.state === 'healthy').length,
    totalNodes: db.nodes.length,
    availableNodes: db.nodes.filter(n => n.state === 'healthy').length,
    replicaFactor: db.policy.replicas
  }
});

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      ...SECURITY_HEADERS,
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'content-type'
    });
    return res.end();
  }

  try {
    // ----------------------------------------------------
    // Health & Cluster State
    // ----------------------------------------------------
    if (url.pathname === '/api/health' && req.method === 'GET') {
      return json(res, 200, { ok: true, service: 'vault-lab-api', time: new Date().toISOString() });
    }
    if (url.pathname === '/api/state' && req.method === 'GET') {
      return json(res, 200, summary());
    }

    // ----------------------------------------------------
    // Policy Configuration
    // ----------------------------------------------------
    if (url.pathname === '/api/policy' && req.method === 'PUT') {
      const p = await bodyOf(req);
      const replicas = Number(p.replicas), quorum = Number(p.writeQuorum);
      if (!Number.isInteger(replicas) || replicas < 1 || replicas > 6 || !Number.isInteger(quorum) || quorum < 1 || quorum > replicas) {
        return json(res, 400, { error: 'Replica count must be 1–6 and write quorum must be within that count.' });
      }
      db.policy = { ...db.policy, ...p, replicas, writeQuorum: quorum };
      event('policy', `Policy updated · ${replicas} replicas · write quorum ${quorum}`);
      await persist();
      return json(res, 200, summary());
    }

    // ----------------------------------------------------
    // Submissions: Document Submit
    // ----------------------------------------------------
    if (url.pathname === '/api/submissions/document' && req.method === 'POST') {
      const input = await bodyOf(req);
      const title = sanitizeText(input.title, 120) || sanitizeFilename(input.file?.name, 'Untitled Document');
      const category = sanitizeText(input.category, 60, 'General Document');
      const notes = sanitizeText(input.notes, 500);

      const file = input.file && input.file.name ? {
        name: sanitizeFilename(input.file.name),
        size: Number(input.file.size) || Buffer.byteLength(input.file.data || ''),
        type: sanitizeText(input.file.type, 80, 'application/octet-stream'),
        checksum: checksum(input.file.data || ''),
        data: String(input.file.data || '')
      } : null;

      const subId = `sub-doc-${randomUUID().slice(0, 8)}`;
      const payloadString = JSON.stringify({ subId, type: 'document', title, category, notes, file });
      const obj = storeObject(`docs/${subId}/${file?.name || 'document.dat'}`, payloadString);

      const submission = {
        id: subId,
        type: 'document',
        title,
        category,
        notes,
        file,
        checksum: obj.checksum,
        replicas: obj.replicas,
        healthy: true,
        objectId: obj.id,
        createdAt: new Date().toISOString()
      };

      db.submissions.unshift(submission);
      event('write', `Document submitted: “${title}” · ${file ? file.name + ' · ' : ''}${obj.replicas} replicas · sha ${obj.checksum}`);
      await persist();
      return json(res, 201, { ok: true, submission: stripFileData(submission), object: { ...obj, body: undefined } });
    }

    // ----------------------------------------------------
    // Submissions: Payment Submit
    // ----------------------------------------------------
    if (url.pathname === '/api/submissions/payment' && req.method === 'POST') {
      const input = await bodyOf(req);
      const reference = sanitizeText(input.reference, 60) || `TX-${Math.floor(100000 + Math.random() * 900000)}`;
      const amount = parseValidAmount(input.amount);
      const curr = String(input.currency || 'USD').trim().toUpperCase();
      const currency = ALLOWED_CURRENCIES.has(curr) ? curr : 'USD';
      const method = sanitizeText(input.method, 50, 'Credit Card');
      const notes = sanitizeText(input.notes, 500);

      const file = input.file && input.file.name ? {
        name: sanitizeFilename(input.file.name),
        size: Number(input.file.size) || Buffer.byteLength(input.file.data || ''),
        type: sanitizeText(input.file.type, 80, 'application/octet-stream'),
        checksum: checksum(input.file.data || ''),
        data: String(input.file.data || '')
      } : null;

      const subId = `sub-pay-${randomUUID().slice(0, 8)}`;
      const payloadString = JSON.stringify({ subId, type: 'payment', reference, amount, currency, method, notes, file });
      const obj = storeObject(`payments/${subId}/${reference}`, payloadString);

      const submission = {
        id: subId,
        type: 'payment',
        reference,
        amount,
        currency,
        method,
        notes,
        file,
        checksum: obj.checksum,
        replicas: obj.replicas,
        healthy: true,
        objectId: obj.id,
        createdAt: new Date().toISOString()
      };

      db.submissions.unshift(submission);
      event('write', `Payment submitted: ${reference} (${amount} ${currency} via ${method}) · ${file ? file.name + ' · ' : ''}${obj.replicas} replicas · sha ${obj.checksum}`);
      await persist();
      return json(res, 201, { ok: true, submission: stripFileData(submission), object: { ...obj, body: undefined } });
    }

    // ----------------------------------------------------
    // Submissions: Details Submit
    // ----------------------------------------------------
    if (url.pathname === '/api/submissions/details' && req.method === 'POST') {
      const input = await bodyOf(req);
      const fullName = sanitizeText(input.fullName || input.name, 120);
      const email = sanitizeText(input.email, 120);
      const accountNumber = sanitizeText(input.accountNumber, 60);
      const category = sanitizeText(input.category, 60, 'General');
      const details = sanitizeText(input.details || input.notes, 2000);

      if (!fullName && !email && !details) {
        return json(res, 400, { error: 'At least Name, Email, or Details notes are required.' });
      }
      if (email && !isValidEmail(email)) {
        return json(res, 400, { error: 'Invalid email address format.' });
      }

      const file = input.file && input.file.name ? {
        name: sanitizeFilename(input.file.name),
        size: Number(input.file.size) || Buffer.byteLength(input.file.data || ''),
        type: sanitizeText(input.file.type, 80, 'application/octet-stream'),
        checksum: checksum(input.file.data || ''),
        data: String(input.file.data || '')
      } : null;

      const subId = `sub-det-${randomUUID().slice(0, 8)}`;
      const payloadString = JSON.stringify({ subId, type: 'details', fullName, email, accountNumber, category, details, file });
      const obj = storeObject(`details/${subId}/profile.json`, payloadString);

      const submission = {
        id: subId,
        type: 'details',
        fullName,
        email,
        accountNumber,
        category,
        details,
        file,
        checksum: obj.checksum,
        replicas: obj.replicas,
        healthy: true,
        objectId: obj.id,
        createdAt: new Date().toISOString()
      };

      db.submissions.unshift(submission);
      event('write', `Details submitted: ${fullName || email || 'Profile'} · ${category} · ${obj.replicas} replicas · sha ${obj.checksum}`);
      await persist();
      return json(res, 201, { ok: true, submission: stripFileData(submission), object: { ...obj, body: undefined } });
    }

    // ----------------------------------------------------
    // Submissions: Everything Submit (All-in-One Master)
    // ----------------------------------------------------
    if ((url.pathname === '/api/submissions/everything' || url.pathname === '/api/submissions/all') && req.method === 'POST') {
      const input = await bodyOf(req);
      const title = sanitizeText(input.title, 140, 'Comprehensive Submission Package');
      const docInput = input.document || {};
      const payInput = input.payment || {};
      const detInput = input.details || {};

      const docFile = docInput.file && docInput.file.name ? {
        name: sanitizeFilename(docInput.file.name),
        size: Number(docInput.file.size) || Buffer.byteLength(docInput.file.data || ''),
        type: sanitizeText(docInput.file.type, 80, 'application/octet-stream'),
        checksum: checksum(docInput.file.data || ''),
        data: String(docInput.file.data || '')
      } : null;

      const payFile = payInput.file && payInput.file.name ? {
        name: sanitizeFilename(payInput.file.name),
        size: Number(payInput.file.size) || Buffer.byteLength(payInput.file.data || ''),
        type: sanitizeText(payInput.file.type, 80, 'application/octet-stream'),
        checksum: checksum(payInput.file.data || ''),
        data: String(payInput.file.data || '')
      } : null;

      const detFile = detInput.file && detInput.file.name ? {
        name: sanitizeFilename(detInput.file.name),
        size: Number(detInput.file.size) || Buffer.byteLength(detInput.file.data || ''),
        type: sanitizeText(detInput.file.type, 80, 'application/octet-stream'),
        checksum: checksum(detInput.file.data || ''),
        data: String(detInput.file.data || '')
      } : null;

      const document = {
        title: sanitizeText(docInput.title, 120, 'Attached Document'),
        category: sanitizeText(docInput.category, 60, 'General'),
        notes: sanitizeText(docInput.notes, 500),
        file: docFile
      };

      const curr = String(payInput.currency || 'USD').trim().toUpperCase();
      const payment = {
        reference: sanitizeText(payInput.reference, 60) || `TX-${Math.floor(100000 + Math.random() * 900000)}`,
        amount: parseValidAmount(payInput.amount),
        currency: ALLOWED_CURRENCIES.has(curr) ? curr : 'USD',
        method: sanitizeText(payInput.method, 50, 'Credit Card'),
        notes: sanitizeText(payInput.notes, 500),
        file: payFile
      };

      const details = {
        fullName: sanitizeText(detInput.fullName || detInput.name, 120),
        email: sanitizeText(detInput.email, 120),
        accountNumber: sanitizeText(detInput.accountNumber, 60),
        category: sanitizeText(detInput.category, 60, 'Comprehensive Bundle'),
        details: sanitizeText(detInput.details || detInput.notes, 2000),
        file: detFile
      };

      const subId = `sub-all-${randomUUID().slice(0, 8)}`;
      const bundlePayload = JSON.stringify({ subId, type: 'everything', title, document, payment, details });
      const obj = storeObject(`bundles/${subId}/package.json`, bundlePayload);

      const submission = {
        id: subId,
        type: 'everything',
        title,
        document,
        payment,
        details,
        checksum: obj.checksum,
        replicas: obj.replicas,
        healthy: true,
        objectId: obj.id,
        createdAt: new Date().toISOString()
      };

      db.submissions.unshift(submission);
      event('write', `Complete package submitted: “${title}” (Doc + Payment + Details) · ${obj.replicas} replicas · sha ${obj.checksum}`);
      await persist();
      return json(res, 201, { ok: true, submission: stripFileData(submission), object: { ...obj, body: undefined } });
    }

    // ----------------------------------------------------
    // Submissions: List
    // ----------------------------------------------------
    if (url.pathname === '/api/submissions' && req.method === 'GET') {
      const typeFilter = url.searchParams.get('type');
      let list = db.submissions || [];
      if (typeFilter) list = list.filter(s => s.type === typeFilter);
      return json(res, 200, { submissions: list.map(stripFileData) });
    }

    // ----------------------------------------------------
    // Submissions: Download/View raw file attachment
    // ----------------------------------------------------
    const fileMatch = url.pathname.match(/^\/api\/submissions\/([^/]+)\/file$/);
    if (fileMatch && req.method === 'GET') {
      const id = fileMatch[1];
      const sub = (db.submissions || []).find(s => s.id === id);
      if (!sub) return json(res, 404, { error: 'Submission not found' });
      const part = url.searchParams.get('part');

      let fileObj = null;
      if (part === 'document') fileObj = sub.document?.file || (sub.type === 'document' ? sub.file : null);
      else if (part === 'payment') fileObj = sub.payment?.file || (sub.type === 'payment' ? sub.file : null);
      else if (part === 'details') fileObj = sub.details?.file || (sub.type === 'details' ? sub.file : null);
      else fileObj = sub.file || sub.document?.file || sub.payment?.file || sub.details?.file;

      if (!fileObj || !fileObj.data) {
        return json(res, 404, { error: 'No attached file found for this submission/part.' });
      }

      const safeName = sanitizeFilename(fileObj.name, 'attachment');
      const match = String(fileObj.data).match(/^data:([^;]+);base64,(.+)$/);
      if (match) {
        const mime = match[1] || fileObj.type || 'application/octet-stream';
        const buf = Buffer.from(match[2], 'base64');
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': mime,
          'Content-Length': buf.length,
          'Content-Disposition': `inline; filename="${encodeURIComponent(safeName)}"`,
          'Content-Security-Policy': "default-src 'none'; sandbox" // Prevents SVG/HTML XSS execution on direct views
        });
        return res.end(buf);
      }
      const buf = Buffer.from(String(fileObj.data), 'utf8');
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': fileObj.type || 'text/plain; charset=utf-8',
        'Content-Length': buf.length,
        'Content-Disposition': `inline; filename="${encodeURIComponent(safeName)}"`,
        'Content-Security-Policy': "default-src 'none'; sandbox"
      });
      return res.end(buf);
    }

    // ----------------------------------------------------
    // Submissions: Single Inspection & Delete
    // ----------------------------------------------------
    const subItemMatch = url.pathname.match(/^\/api\/submissions\/([^/]+)$/);
    if (subItemMatch && req.method === 'GET') {
      const id = subItemMatch[1];
      const sub = (db.submissions || []).find(s => s.id === id);
      if (!sub) return json(res, 404, { error: 'Submission not found' });
      return json(res, 200, { submission: sub });
    }

    if (subItemMatch && req.method === 'DELETE') {
      const id = subItemMatch[1];
      const idx = (db.submissions || []).findIndex(s => s.id === id);
      if (idx < 0) return json(res, 404, { error: 'Submission not found.' });
      const [removed] = db.submissions.splice(idx, 1);
      if (removed.objectId) {
        const objIdx = db.objects.findIndex(o => o.id === removed.objectId);
        if (objIdx >= 0) db.objects.splice(objIdx, 1);
      }
      event('delete', `Deleted submission “${removed.id}” (${removed.type})`);
      await persist();
      return json(res, 200, { ok: true });
    }

    // ----------------------------------------------------
    // Raw Objects API (Backward Compatible)
    // ----------------------------------------------------
    if (url.pathname === '/api/objects' && req.method === 'GET') {
      return json(res, 200, { objects: summary().objects });
    }
    if (url.pathname === '/api/objects' && req.method === 'POST') {
      const input = await bodyOf(req);
      const key = sanitizeText(input.key, 160);
      const value = String(input.value ?? '');
      if (!key) {
        return json(res, 400, { error: 'Object key is required and must be at most 160 characters.' });
      }
      const alive = db.nodes.filter(n => n.state === 'healthy').length;
      if (alive < db.policy.writeQuorum) {
        return json(res, 503, { error: `Write quorum unavailable: ${alive}/${db.policy.writeQuorum} healthy nodes.` });
      }
      const hash = checksum(value);
      const old = db.objects.find(o => o.key === key);
      const obj = {
        id: old?.id || randomUUID(),
        key,
        size: Buffer.byteLength(value),
        checksum: hash,
        version: (old?.version || 0) + 1,
        replicas: Math.min(db.policy.replicas, alive),
        healthy: true,
        updatedAt: new Date().toISOString(),
        body: value
      };
      if (old) Object.assign(old, obj);
      else db.objects.unshift(obj);
      event('write', `${old ? 'Updated' : 'Stored'} “${key}” · ${obj.replicas} replicas · sha ${hash}`);
      await persist();
      return json(res, old ? 200 : 201, { object: { ...obj, body: undefined } });
    }

    const objectMatch = url.pathname.match(/^\/api\/objects\/([^/]+)$/);
    if (objectMatch && req.method === 'GET') {
      let targetId = objectMatch[1];
      try { targetId = decodeURIComponent(targetId); } catch { /* ignore malformed decode */ }
      const o = db.objects.find(x => x.id === targetId || x.key === targetId);
      if (!o) return json(res, 404, { error: 'Object not found.' });
      if (checksum(o.body) !== o.checksum) {
        o.healthy = false;
        event('corruption', `Checksum mismatch detected for “${o.key}”`);
        await persist();
        return json(res, 500, { error: 'Integrity check failed.', object: { ...o, body: undefined } });
      }
      event('read', `Read “${o.key}” · checksum verified`);
      await persist();
      return json(res, 200, { key: o.key, value: o.body, checksum: o.checksum, version: o.version });
    }

    if (objectMatch && req.method === 'DELETE') {
      let targetId = objectMatch[1];
      try { targetId = decodeURIComponent(targetId); } catch { /* ignore malformed decode */ }
      const i = db.objects.findIndex(x => x.id === targetId || x.key === targetId);
      if (i < 0) return json(res, 404, { error: 'Object not found.' });
      const [o] = db.objects.splice(i, 1);
      event('delete', `Deleted “${o.key}”`);
      await persist();
      return json(res, 200, { ok: true });
    }

    // ----------------------------------------------------
    // Node Management & Fault Injection
    // ----------------------------------------------------
    const nodeMatch = url.pathname.match(/^\/api\/nodes\/([^/]+)\/failure$/);
    if (nodeMatch && req.method === 'POST') {
      const n = db.nodes.find(x => x.id === nodeMatch[1]);
      if (!n) return json(res, 404, { error: 'Node not found.' });
      n.state = n.state === 'healthy' ? 'offline' : 'healthy';
      event('failure', `${n.id} ${n.state === 'offline' ? 'went offline' : 'rejoined the cluster'}`);
      await persist();
      return json(res, 200, summary());
    }

    // ----------------------------------------------------
    // Repair & Verify
    // ----------------------------------------------------
    if (url.pathname === '/api/repair' && req.method === 'POST') {
      let repaired = 0;
      for (const o of db.objects) {
        if (o.replicas < db.policy.replicas || !o.healthy) {
          if (checksum(o.body) === o.checksum) {
            o.healthy = true;
            o.replicas = Math.min(db.policy.replicas, db.nodes.filter(n => n.state === 'healthy').length);
            repaired++;
          }
        }
      }
      event('repair', repaired ? `Repair complete · ${repaired} object${repaired === 1 ? '' : 's'} verified and healed` : 'Repair scan complete · all objects healthy');
      await persist();
      return json(res, 200, { ok: true, repaired, ...summary() });
    }

    if (url.pathname === '/api/verify' && req.method === 'POST') {
      let checked = 0, corrupt = 0;
      for (const o of db.objects) {
        checked++;
        if (checksum(o.body) !== o.checksum) {
          o.healthy = false;
          corrupt++;
        }
      }
      event(corrupt ? 'corruption' : 'verify', `Integrity scan · ${checked} checked · ${corrupt} mismatch${corrupt === 1 ? '' : 'es'}`);
      await persist();
      return json(res, 200, { ok: !corrupt, checked, corrupt, ...summary() });
    }

    // ----------------------------------------------------
    // Static Asset Serving (Hardened & Fallback-aware)
    // ----------------------------------------------------
    if (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/index.html.html') {
      let content;
      try {
        content = await readFile(path.join(root, 'index.html'));
      } catch {
        content = await readFile(path.join(root, 'index.html.html'));
      }
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(content);
    }
    if (url.pathname === '/app.js') {
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/javascript; charset=utf-8' });
      return res.end(await readFile(path.join(root, 'app.js')));
    }
    if (url.pathname === '/style.css') {
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/css; charset=utf-8' });
      return res.end(await readFile(path.join(root, 'style.css')));
    }
    if (url.pathname === '/logo.svg') {
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'image/svg+xml' });
      return res.end(await readFile(path.join(root, 'logo.svg')));
    }

    json(res, 404, { error: 'Route not found.' });
  } catch (e) {
    const status = e.message && e.message.includes('quorum') ? 503 : 400;
    json(res, status, { error: e.message || 'Request failed.' });
  }
});

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(PORT, () => console.log(`Vault lab listening on http://localhost:${PORT}`));
}

export { server, db, defaults, checksum, sanitizeFilename, isValidEmail, parseValidAmount };
