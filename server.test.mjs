import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { server, db, defaults, checksum, sanitizeFilename, isValidEmail, parseValidAmount } from './server.mjs';

test('checksum is stable and changes with content', () => {
  assert.equal(checksum('vault'), checksum('vault'));
  assert.notEqual(checksum('vault'), checksum('Vault'));
});

test('default cluster has independent zones and a safe quorum', () => {
  const d = defaults();
  assert.equal(d.nodes.length, 6);
  assert.equal(new Set(d.nodes.map(n => n.zone)).size, 6);
  assert.ok(d.policy.writeQuorum <= d.policy.replicas);
  assert.ok(Array.isArray(d.submissions));
});

test('Sanitization and validation helpers enforce security constraints', () => {
  // Filename sanitization
  assert.equal(sanitizeFilename('my/secret/doc.pdf'), 'my_secret_doc.pdf');
  assert.equal(sanitizeFilename('../../../etc/passwd.txt'), '.._.._.._etc_passwd.txt');
  assert.throws(() => sanitizeFilename('payload.exe'), /restricted for security reasons/);
  assert.throws(() => sanitizeFilename('script.bat'), /restricted for security reasons/);
  assert.throws(() => sanitizeFilename('malware.vbs'), /restricted for security reasons/);

  // Email validation
  assert.equal(isValidEmail('user@company.com'), true);
  assert.equal(isValidEmail('invalid-email'), false);
  assert.equal(isValidEmail('user@com'), false);

  // Amount validation
  assert.equal(parseValidAmount('120.5'), '120.50');
  assert.throws(() => parseValidAmount('-50'), /positive number/);
  assert.throws(() => parseValidAmount('not_a_number'), /positive number/);
  assert.throws(() => parseValidAmount('2000000000'), /up to 1,000,000,000/);
});

test('API health, object write/read, quorum guard, failure, repair, and invalid policy', async t => {
  server.listen(0);
  await once(server, 'listening');
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, method = 'GET', body) => {
    const r = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    return { status: r.status, headers: r.headers, body: await r.json() };
  };

  const health = await request('/api/health');
  assert.equal(health.status, 200);
  assert.equal(health.body.ok, true);

  // Verify Security Headers on API responses
  assert.equal(health.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(health.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(health.headers.get('x-xss-protection'), '1; mode=block');

  const created = await request('/api/objects', 'POST', { key: 'test-object', value: 'hello resilience' });
  assert.equal(created.status, 201);
  assert.equal(created.body.object.version, 1);
  assert.equal(created.body.object.replicas, 3);

  const read = await request(`/api/objects/${created.body.object.id}`);
  assert.equal(read.status, 200);
  assert.equal(read.body.value, 'hello resilience');

  const updated = await request('/api/objects', 'POST', { key: 'test-object', value: 'version two' });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.object.version, 2);

  const invalid = await request('/api/policy', 'PUT', { replicas: 2, writeQuorum: 3 });
  assert.equal(invalid.status, 400);

  for (const n of db.nodes.slice(0, 5)) await request(`/api/nodes/${n.id}/failure`, 'POST', {});
  const denied = await request('/api/objects', 'POST', { key: 'should-fail', value: 'x' });
  assert.equal(denied.status, 503);

  for (const n of db.nodes) if (n.state === 'offline') await request(`/api/nodes/${n.id}/failure`, 'POST', {});
  const repair = await request('/api/repair', 'POST', {});
  assert.equal(repair.status, 200);
  assert.equal(repair.body.ok, true);

  const verify = await request('/api/verify', 'POST', {});
  assert.equal(verify.body.ok, true);
  assert.ok(verify.body.checked >= 1);

  const deleted = await request(`/api/objects/${created.body.object.id}`, 'DELETE');
  assert.equal(deleted.status, 200);
});

test('Backend submissions: Security validations, file sandbox, quorum, and delete', async t => {
  server.listen(0);
  await once(server, 'listening');
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, method = 'GET', body) => {
    const r = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    return { status: r.status, headers: r.headers, body: await r.json() };
  };

  // 1. Submit Document (Valid)
  const docFileContent = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 sample passport content').toString('base64');
  const docRes = await request('/api/submissions/document', 'POST', {
    title: 'Passport Verification',
    category: 'Identification',
    notes: 'Government issued passport',
    file: {
      name: 'passport.pdf',
      type: 'application/pdf',
      data: docFileContent
    }
  });
  assert.equal(docRes.status, 201);
  assert.equal(docRes.body.ok, true);
  assert.equal(docRes.body.submission.type, 'document');
  assert.equal(docRes.body.submission.title, 'Passport Verification');
  assert.equal(docRes.body.submission.file.name, 'passport.pdf');
  const docId = docRes.body.submission.id;

  // Security test: Malicious file extension blocked
  const malRes = await request('/api/submissions/document', 'POST', {
    title: 'Malicious Upload',
    file: {
      name: 'payload.exe',
      type: 'application/x-msdownload',
      data: 'data:application/x-msdownload;base64,AAAA'
    }
  });
  assert.equal(malRes.status, 400);
  assert.ok(malRes.body.error.includes('restricted for security'));

  // Verify file download endpoint has CSP sandbox
  const fileRes = await fetch(`${base}/api/submissions/${docId}/file?part=document`);
  assert.equal(fileRes.status, 200);
  assert.equal(fileRes.headers.get('content-type'), 'application/pdf');
  assert.ok(fileRes.headers.get('content-security-policy')?.includes('sandbox'));
  const fileBytes = await fileRes.text();
  assert.ok(fileBytes.includes('%PDF-1.4'));

  // 2. Submit Payment
  const receiptImg = 'data:image/png;base64,' + Buffer.from('fake-png-binary-data').toString('base64');
  const payRes = await request('/api/submissions/payment', 'POST', {
    reference: 'TX-778899',
    amount: '450.00',
    currency: 'USD',
    method: 'Wire Transfer',
    notes: 'Invoice #204 verified',
    file: {
      name: 'receipt.png',
      type: 'image/png',
      data: receiptImg
    }
  });
  assert.equal(payRes.status, 201);
  assert.equal(payRes.body.submission.type, 'payment');
  assert.equal(payRes.body.submission.amount, '450.00');
  const payId = payRes.body.submission.id;

  // Security test: Negative/invalid payment amount rejected
  const badPayRes = await request('/api/submissions/payment', 'POST', {
    reference: 'TX-BAD',
    amount: '-999.00'
  });
  assert.equal(badPayRes.status, 400);

  // 3. Submit Details
  const detRes = await request('/api/submissions/details', 'POST', {
    fullName: 'Robert Vance',
    email: 'robert@vance-refrig.com',
    accountNumber: 'ACC-9921',
    category: 'Client Profile',
    details: 'New enterprise client onboarding form'
  });
  assert.equal(detRes.status, 201);
  assert.equal(detRes.body.submission.fullName, 'Robert Vance');
  const detId = detRes.body.submission.id;

  // Security test: Malformed email rejected
  const badEmailRes = await request('/api/submissions/details', 'POST', {
    fullName: 'Test User',
    email: 'not-an-email'
  });
  assert.equal(badEmailRes.status, 400);
  assert.ok(badEmailRes.body.error.includes('email'));

  // 4. Submit Everything (All-in-One combined submission)
  const allRes = await request('/api/submissions/everything', 'POST', {
    title: 'Complete Onboarding Package',
    document: {
      title: 'Company Articles of Incorporation',
      category: 'Legal',
      file: {
        name: 'incorporation.pdf',
        type: 'application/pdf',
        data: docFileContent
      }
    },
    payment: {
      reference: 'TX-ALL-001',
      amount: '12000.00',
      currency: 'USD',
      method: 'ACH Transfer',
      file: {
        name: 'payment_slip.png',
        type: 'image/png',
        data: receiptImg
      }
    },
    details: {
      fullName: 'Acme Global Corp',
      email: 'admin@acmeglobal.com',
      accountNumber: 'CORP-0012',
      category: 'Enterprise',
      details: 'All corporate documents verified and signed'
    }
  });
  assert.equal(allRes.status, 201);
  assert.equal(allRes.body.submission.type, 'everything');
  const allId = allRes.body.submission.id;

  // List all submissions
  const listRes = await request('/api/submissions');
  assert.equal(listRes.status, 200);
  assert.ok(listRes.body.submissions.length >= 4);

  // Inspect single submission
  const inspectRes = await request(`/api/submissions/${allId}`);
  assert.equal(inspectRes.status, 200);
  assert.equal(inspectRes.body.submission.id, allId);

  // Quorum failure check for submissions
  for (const n of db.nodes.slice(0, 5)) await request(`/api/nodes/${n.id}/failure`, 'POST', {});
  const deniedSub = await request('/api/submissions/document', 'POST', { title: 'Should Fail Quorum' });
  assert.equal(deniedSub.status, 503);

  // Restore nodes
  for (const n of db.nodes) if (n.state === 'offline') await request(`/api/nodes/${n.id}/failure`, 'POST', {});

  // Clean deletion
  assert.equal((await request(`/api/submissions/${docId}`, 'DELETE')).status, 200);
  assert.equal((await request(`/api/submissions/${payId}`, 'DELETE')).status, 200);
  assert.equal((await request(`/api/submissions/${detId}`, 'DELETE')).status, 200);
  assert.equal((await request(`/api/submissions/${allId}`, 'DELETE')).status, 200);
});
