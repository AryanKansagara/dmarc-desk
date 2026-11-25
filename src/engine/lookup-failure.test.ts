import { test } from 'node:test'
import assert from 'node:assert/strict'
import { dohResolver, fakeResolver, type Resolver } from './dns.ts'
import { expandSpf } from './spf.ts'
import { checkDomain, gradeOf, type Section } from './checks.ts'

// ---------- DNS: a lookup that fails is not a lookup that found nothing (RFC 7208 temperror vs void) ----------

/** A zone where the names (or `name TYPE`) in `bad` fail the way an HTTP 502 from both providers does. */
const flaky = (zone: Parameters<typeof fakeResolver>[0], ...bad: string[]): Resolver => {
  const base = fakeResolver(zone)
  return (n, t) => bad.includes(n) || bad.includes(`${n} ${t}`) ? Promise.reject(new Error('Google DoH returned HTTP 502')) : base(n, t)
}
const KEY = 'v=DKIM1; k=rsa; p=' + 'A'.repeat(400)
const MIDWAY = {
  'midway.test': { MX: ['10 aspmx.l.google.com.'], TXT: ['v=spf1 include:_spf.google.com include:spf.vendor.test -all'] },
  '_spf.google.com': { TXT: ['v=spf1 ip4:35.190.247.0/24 ~all'] },
  'spf.vendor.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 ~all'] },
  '_dmarc.midway.test': { TXT: ['v=DMARC1; p=quarantine; pct=50; rua=mailto:d@midway.test'] },
  'google._domainkey.midway.test': { TXT: [KEY] },
}

test('SPF: a failed lookup of the domain itself is "could not check", not a missing record', async () => {
  const r = await expandSpf('midway.test', flaky(MIDWAY, 'midway.test TXT'))
  assert.equal(r.record, null)
  assert.equal(r.failed.length, 1)
  assert.ok(r.issues.some(i => /^Lookup failed: Google DoH returned HTTP 502/.test(i.msg)))
  assert.ok(!r.issues.some(i => i.level === 'error' || /No SPF record/.test(i.msg)), JSON.stringify(r.issues))
  // The same name genuinely missing, empty, or without an SPF record is still a missing record.
  for (const zone of [{}, { 'x.test': { TXT: [] } }, { 'x.test': { TXT: ['google-site-verification=abc'] } }] as Parameters<typeof fakeResolver>[0][]) {
    const m = await expandSpf('x.test', fakeResolver(zone))
    assert.equal(m.failed.length, 0)
    assert.ok(m.issues.some(i => i.level === 'error' && /No SPF record/.test(i.msg)))
  }
})

test('SPF: an include whose lookup fails is not reported as having no record, at any depth', async () => {
  const zone = {
    'd.test': { TXT: ['v=spf1 include:l1.test -all'] },
    'l1.test': { TXT: ['v=spf1 include:l2.test ~all'] },
    'l2.test': { TXT: ['v=spf1 include:l3.test ~all'] },
    'l3.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 ~all'] },
  }
  for (const [name, depth] of [['l1.test', 1], ['l2.test', 2], ['l3.test', 3]] as const) {
    const r = await expandSpf('d.test', flaky(zone, name))
    assert.deepEqual(r.failed.map(f => f.name), [name], `depth ${depth}`)
    assert.ok(r.issues.some(i => i.level === 'warn' && i.msg.startsWith(`${name}: lookup failed (Google DoH returned HTTP 502)`)), `depth ${depth}`)
    assert.ok(!r.issues.some(i => /no SPF record|permerror|void/i.test(i.msg)), `depth ${depth}: ${JSON.stringify(r.issues)}`)
    assert.equal(r.voidLookups, 0, `depth ${depth}`)
  }
  const ok = await expandSpf('d.test', flaky(zone))
  assert.equal(ok.failed.length, 0)
  assert.deepEqual(ok.ip4, ['192.0.2.0/24'])
})

test('SPF: void lookups are counted across include depths and a failed lookup is never one of them', async () => {
  const zone = {
    'd.test': { TXT: ['v=spf1 include:a.test include:b.test -all'] },
    'a.test': { TXT: ['v=spf1 include:gone1.test ~all'] },
    'b.test': { TXT: ['v=spf1 include:c.test ~all'] },
    'c.test': { TXT: ['v=spf1 include:gone2.test include:gone3.test ~all'] },
  }
  const three = await expandSpf('d.test', fakeResolver(zone))
  assert.equal(three.voidLookups, 3)
  assert.ok(three.issues.some(i => i.level === 'error' && /3 void lookups/.test(i.msg)))
  // One of the three is a failure instead: two voids stay within the limit and the failure is reported as one.
  const two = await expandSpf('d.test', flaky(zone, 'gone3.test'))
  assert.equal(two.voidLookups, 2)
  assert.ok(!two.issues.some(i => /void lookups/.test(i.msg)))
  assert.deepEqual(two.failed.map(f => f.name), ['gone3.test'])
  // NOERROR with no data is void too, wherever it happens.
  const nodata = await expandSpf('d.test', fakeResolver({ ...zone, 'gone1.test': { TXT: [] }, 'gone2.test': { TXT: [] }, 'gone3.test': { TXT: [] } }))
  assert.equal(nodata.voidLookups, 3)
  // A failure beside three real voids does not hide them.
  const both = await expandSpf('d.test', flaky({ ...zone, 'a.test': { TXT: ['v=spf1 include:gone1.test include:gone4.test ~all'] } }, 'gone4.test'))
  assert.equal(both.voidLookups, 3)
  assert.ok(both.issues.some(i => /3 void lookups/.test(i.msg)))
  assert.equal(both.failed.length, 1)
})

test('SPF: a/mx lookups that fail are reported, not counted as void or as empty', async () => {
  const zone = { 'd.test': { TXT: ['v=spf1 a mx:mail.d.test a:h.d.test -all'], A: ['192.0.2.5'] }, 'mail.d.test': { MX: ['10 m.d.test.'] }, 'm.d.test': { A: ['192.0.2.6'] } }
  const ok = await expandSpf('d.test', fakeResolver(zone))
  assert.equal(ok.voidLookups, 1) // h.d.test does not exist
  assert.deepEqual(ok.ip4.sort(), ['192.0.2.5', '192.0.2.6'])
  const mx = await expandSpf('d.test', flaky(zone, 'mail.d.test MX'))
  assert.equal(mx.voidLookups, 1)
  assert.deepEqual(mx.failed.map(f => f.name), ['mail.d.test MX'])
  const host = await expandSpf('d.test', flaky(zone, 'm.d.test AAAA'))
  assert.equal(host.voidLookups, 1)
  assert.deepEqual(host.failed.map(f => f.name), ['m.d.test AAAA'])
  const a = await expandSpf('d.test', flaky(zone, 'h.d.test A'))
  assert.equal(a.voidLookups, 0) // the A lookup errored, so h.d.test was not shown to be empty
  assert.equal(a.failed.length, 1)
})

test('domain check: a failed SPF lookup is not graded, scored or called missing', async () => {
  const good = await checkDomain('midway.test', fakeResolver(MIDWAY))
  assert.equal(good.grade, 'C')
  assert.equal(good.score, 65)
  assert.deepEqual(good.unchecked, [])
  const own = await checkDomain('midway.test', flaky(MIDWAY, 'midway.test TXT'))
  const spf = own.sections.find(s => s.id === 'spf')!
  assert.deepEqual([spf.status, spf.summary, spf.points, spf.max, spf.unchecked], ['info', 'Could not check', 0, 0, true])
  assert.ok(spf.details.some(d => d.includes('Lookup failed')))
  assert.deepEqual(own.unchecked, ['SPF'])
  assert.notEqual(own.score, 45) // the score the missing record gave before
  const inc = await checkDomain('midway.test', flaky(MIDWAY, 'spf.vendor.test'))
  const ispf = inc.sections.find(s => s.id === 'spf')!
  assert.equal(ispf.status, 'info')
  assert.ok(ispf.details.some(d => d.includes('spf.vendor.test: lookup failed')))
  assert.ok(!ispf.details.some(d => d.includes('has no SPF record')))
  const missing = await checkDomain('midway.test', fakeResolver({ ...MIDWAY, 'midway.test': { MX: ['10 aspmx.l.google.com.'], TXT: [] } }))
  assert.equal(missing.sections.find(s => s.id === 'spf')!.summary, 'Missing')
  assert.equal(missing.sections.find(s => s.id === 'spf')!.max, 20)
})

test('domain check: an unchecked section can never lift the grade to A', () => {
  const sec = (id: string, status: Section['status'], points: number, max: number, extra: Partial<Section> = {}): Section => ({ id, title: id.toUpperCase(), status, summary: '', details: [], points, max, ...extra })
  const g = gradeOf([sec('spf', 'info', 0, 0, { unchecked: true }), sec('dmarc', 'pass', 30, 30, { summary: 'p=reject' })])
  assert.equal(g.score, 100)
  assert.equal(g.grade, 'B')
  assert.match(g.capped!, /SPF could not be checked/)
})

test('domain check: optional records and DKIM selectors that fail are "could not check", not "not set up"', async () => {
  const ids = ['mta-sts', 'tls-rpt', 'bimi'] as const
  const names = { 'mta-sts': '_mta-sts.midway.test', 'tls-rpt': '_smtp._tls.midway.test', bimi: 'default._bimi.midway.test' }
  for (const id of ids) {
    const c = await checkDomain('midway.test', flaky(MIDWAY, names[id]))
    const sec = c.sections.find(s => s.id === id)!
    assert.deepEqual([sec.status, sec.summary, sec.max, sec.unchecked], ['info', 'Could not check', 0, true], id)
    assert.deepEqual(c.unchecked, [sec.title])
  }
  const ok = await checkDomain('midway.test', fakeResolver(MIDWAY))
  assert.equal(ok.sections.find(s => s.id === 'mta-sts')!.summary, 'Not set up')
  const noKeys = { ...MIDWAY }; delete (noKeys as Record<string, unknown>)['google._domainkey.midway.test']
  const lost = await checkDomain('midway.test', flaky(noKeys, 'selector1._domainkey.midway.test'))
  assert.equal(lost.sections.find(s => s.id === 'dkim')!.summary, 'Could not check')
  const some = await checkDomain('midway.test', flaky(MIDWAY, 'selector1._domainkey.midway.test'))
  assert.equal(some.sections.find(s => s.id === 'dkim')!.status, 'pass')
  assert.ok(some.sections.find(s => s.id === 'dkim')!.details.some(d => /1 other selector could not be looked up/.test(d)))
})

test('domain check: a failed lookup of the parent DMARC record or of a report authorisation is not "missing"', async () => {
  const zone = { 'mail.midway.test': { MX: ['10 mx.midway.test.'], TXT: ['v=spf1 -all'] }, '_dmarc.midway.test': { TXT: ['v=DMARC1; p=reject; rua=mailto:r@reports.vendor.test'] } }
  await assert.rejects(checkDomain('mail.midway.test', flaky(zone, '_dmarc.midway.test')), /HTTP 502/)
  const inherited = await checkDomain('mail.midway.test', fakeResolver(zone))
  assert.equal(inherited.dmarc!.inherited, 'midway.test')
  const auth = await checkDomain('mail.midway.test', flaky(zone, 'mail.midway.test._report._dmarc.reports.vendor.test'))
  assert.ok(auth.dmarc!.issues.some(i => i.level === 'info' && /Could not check whether/.test(i.msg)))
  assert.ok(!auth.dmarc!.issues.some(i => i.level === 'warn' && /has no "v=DMARC1" record/.test(i.msg)))
})

// ---------- DNS-over-HTTPS: what counts as an answer ----------

const json = (body: unknown, status = 200) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status })
const answer = { Status: 0, AD: true, Answer: [{ name: 'x.test', type: 16, TTL: 60, data: '"v=spf1 -all"' }] }

test('DoH resolver: NXDOMAIN and NOERROR without data are answers; everything else is a failed lookup', async () => {
  const nx = await dohResolver(async () => json({ Status: 3 }))('x.test', 'TXT')
  assert.deepEqual([nx.status, nx.answers.length], [3, 0])
  const nodata = await dohResolver(async () => json({ Status: 0 }))('x.test', 'TXT')
  assert.deepEqual([nodata.status, nodata.answers.length], [0, 0])
  const ok = await dohResolver(async () => json(answer))('x.test', 'TXT')
  assert.deepEqual([ok.status, ok.ad, ok.answers.length], [0, true, 1])

  const bad: [string, () => Promise<Response>][] = [
    ['HTTP 502', async () => json('upstream', 502)],
    ['HTTP 429', async () => json('slow down', 429)],
    ['SERVFAIL', async () => json({ Status: 2 })],
    ['REFUSED', async () => json({ Status: 5 })],
    ['FORMERR', async () => json({ Status: 1 })],
    ['RCODE 9', async () => json({ Status: 9 })],
    ['unreadable', async () => json('<html>captive portal</html>')],
    ['unreadable (empty)', async () => json('')],
    ['unreadable (null)', async () => json('null')],
    ['unreadable (no status)', async () => json({ Answer: [] })],
    ['unreadable (status as text)', async () => json({ Status: 'NXDOMAIN' })],
    ['unreadable (answers not a list)', async () => json({ Status: 0, Answer: 'x' })],
    ['unreadable (answer without data)', async () => json({ Status: 0, Answer: [{ name: 'x.test', type: 16 }] })],
    ['network', async () => { throw new TypeError('Failed to fetch') }],
  ]
  for (const [what, fetchFn] of bad) await assert.rejects(dohResolver(fetchFn as typeof fetch)('x.test', 'TXT'), new RegExp(what.startsWith('HTTP') ? what : what.startsWith('unreadable') ? 'unreadable|Failed' : what === 'network' ? 'Failed to fetch' : what), what)

  // The second provider is asked when the first fails, and a bad answer from the first does not hide a good one.
  const urls: string[] = []
  const fb = await dohResolver(async (u) => { urls.push(String(u)); return urls.length === 1 ? json({ Status: 5 }) : json(answer) })('x.test', 'TXT')
  assert.equal(fb.answers.length, 1)
  assert.equal(urls.length, 2)
})

test('DoH resolver: a provider that never answers is a failed lookup after the timeout', async () => {
  const hang = ((_u: unknown, init?: RequestInit) => new Promise((_, rej) => init?.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError'))))) as typeof fetch
  await assert.rejects(dohResolver(hang, 20)('x.test', 'TXT'), /no answer for x\.test within/)
  // The body can stall after the headers arrived.
  const stall = ((_u: unknown, init?: RequestInit) => Promise.resolve({ ok: true, json: () => new Promise((_, rej) => init?.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')))) })) as unknown as typeof fetch
  await assert.rejects(dohResolver(stall, 20)('x.test', 'TXT'), /no answer for x\.test within/)
})
