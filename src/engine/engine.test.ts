import { test } from 'node:test'
import assert from 'node:assert/strict'
import { gzipSync, deflateRawSync } from 'node:zlib'
import { readFileSync } from 'node:fs'
import { parseXml } from './xml.ts'
import { parseAggregate, reportKey, type Report } from './aggregate.ts'
import { aligned, inCidr, netOf, orgDomain, ptrName } from './domain.ts'
import { analyze, compareSnapshots, identify, isoWeek, snapshot, weekStart } from './analyze.ts'
import { fakeResolver, txtData } from './dns.ts'
import { buildSpf, expandSpf, parseSpf, txtQuote } from './spf.ts'
import { externalDestinations, generateDmarc, parseDmarc } from './dmarc.ts'
import { checkDomain, gradeOf, parseDkim, type Section } from './checks.ts'
import { planRollout, stageIndex } from './rollout.ts'
import { mtaStsPolicy, zoneSnippet } from './records.ts'
import { unpack } from './unpack.ts'
import { SAMPLE_PTR, sampleXml, sampleZone } from './sample.ts'

const xml = (records: string, extra = '') => `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>x@google.com</email><report_id>r1</report_id>
    <date_range><begin>1790000000</begin><end>1790086399</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct>${extra}</policy_published>
${records}
</feedback>`

const rec = (ip: string, count: number, dkim: [string, string][], spf: [string, string], evalD = 'fail', evalS = 'fail', from = 'example.com', reason = '') => `<record>
  <row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition><dkim>${evalD}</dkim><spf>${evalS}</spf>${reason ? `<reason><type>${reason}</type></reason>` : ''}</policy_evaluated></row>
  <identifiers><header_from>${from}</header_from></identifiers>
  <auth_results>${dkim.map(([d, r]) => `<dkim><domain>${d}</domain><selector>s</selector><result>${r}</result></dkim>`).join('')}<spf><domain>${spf[0]}</domain><scope>mfrom</scope><result>${spf[1]}</result></spf></auth_results>
</record>`

const parse = (x: string) => { const r = parseAggregate(x); assert.ok(r.report, JSON.stringify(r.issues)); return r.report! }

// ---------- XML + aggregate parsing ----------

test('xml parser handles namespaces, entities, comments and CDATA, and tracks lines', () => {
  const n = parseXml('<?xml version="1.0"?>\n<!-- c -->\n<a:feedback xmlns:a="x">\n  <a:org_name>AT&amp;T <![CDATA[<x>]]></a:org_name>\n</a:feedback>')
  const fb = n.children[0]
  assert.equal(fb.name, 'feedback')
  assert.equal(fb.line, 3)
  assert.equal(fb.children[0].text, 'AT&T <x>')
  assert.equal(fb.children[0].line, 4)
})

test('aggregate parser reads metadata, policy and rows', () => {
  const r = parse(xml(rec('209.85.220.41', 12, [['example.com', 'pass']], ['example.com', 'pass'], 'pass', 'pass')))
  assert.equal(r.org, 'google.com')
  assert.equal(r.domain, 'example.com')
  assert.equal(r.begin, 1790000000000)
  assert.equal(r.policy.p, 'none')
  assert.equal(r.rows.length, 1)
  assert.equal(r.rows[0].count, 12)
  assert.deepEqual(r.rows[0].dkim, [{ domain: 'example.com', selector: 's', result: 'pass' }])
})

test('validation report: bad IP and count rows are skipped with line numbers; malformed XML is an error', () => {
  const r = parseAggregate(xml(rec('999.1.1.1', 3, [], ['x.com', 'pass']) + '\n' + rec('192.0.2.1', -2, [], ['x.com', 'pass']) + '\n' + rec('192.0.2.2', 4, [], ['x.com', 'pass'])))
  assert.equal(r.report!.rows.length, 1)
  const errs = r.issues.filter(i => i.level === 'error')
  assert.equal(errs.length, 2)
  assert.ok(errs[0].line > 5 && errs[1].line > errs[0].line)
  const bad = parseAggregate('<feedback><record></feedback>')
  assert.equal(bad.report, null)
  assert.match(bad.issues[0].msg, /Not well-formed/)
  assert.match(parseAggregate('<html></html>').issues[0].msg, /not look like a DMARC/)
})

test('report key deduplicates the same report imported twice', () => {
  const a = parse(xml(rec('192.0.2.1', 1, [], ['example.com', 'pass'])))
  const b = parse(xml(rec('192.0.2.1', 1, [], ['example.com', 'pass'])))
  assert.equal(reportKey(a), reportKey(b))
})

test('unpack: plain xml, gzip and zip (stored + deflate) all decompress', async () => {
  const x = xml(rec('192.0.2.1', 1, [], ['example.com', 'pass']))
  const gz = await unpack('a.xml.gz', new Uint8Array(gzipSync(x)))
  assert.equal(gz[0].text, x)
  assert.equal(gz[0].name, 'a.xml')
  const zip = makeZip([{ name: 'one.xml', data: Buffer.from(x), deflate: true }, { name: 'two.xml', data: Buffer.from(x), deflate: false }])
  const z = await unpack('r.zip', zip)
  assert.deepEqual(z.map(f => f.name), ['one.xml', 'two.xml'])
  assert.equal(z[1].text, x)
})

// ---------- Domain helpers ----------

test('organizational domain and relaxed/strict alignment', () => {
  assert.equal(orgDomain('mail.news.example.co.uk'), 'example.co.uk')
  assert.equal(orgDomain('em123.example.com'), 'example.com')
  assert.ok(aligned('em123.example.com', 'example.com', 'r'))
  assert.ok(!aligned('em123.example.com', 'example.com', 's'))
  assert.ok(!aligned('sendgrid.net', 'example.com'))
  assert.ok(!aligned('example.co.uk', 'other.co.uk'))
})

test('CIDR matching for IPv4 and IPv6, PTR names and network labels', () => {
  assert.ok(inCidr('209.85.220.41', '209.85.128.0/17'))
  assert.ok(!inCidr('209.86.0.1', '209.85.128.0/17'))
  assert.ok(inCidr('2607:f8b0:4864:20::a2f', '2607:f8b0::/32'))
  assert.ok(!inCidr('2a00:1450::1', '2607:f8b0::/32'))
  assert.equal(ptrName('192.0.2.10'), '10.2.0.192.in-addr.arpa')
  assert.equal(ptrName('2001:db8::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
  assert.equal(netOf('203.0.113.77'), '203.0.113.0/24')
})

// ---------- Alignment analysis ----------

test('ESP identification: auth domain beats netblock, rDNS used as fallback', () => {
  assert.equal(identify('192.0.2.1', null, ['sendgrid.net'])?.id, 'sendgrid')
  assert.equal(identify('40.107.22.51', null, [])?.id, 'm365')
  assert.equal(identify('192.0.2.1', 'o1.ptr1234.mtasv.net.', [])?.id, 'postmark')
  assert.equal(identify('192.0.2.1', 'host.example.net', []), null)
})

test('alignment reasons: unaligned ESP DKIM, missing DKIM, SPF failing for own domain', () => {
  const r = parse(xml([
    rec('167.89.12.34', 100, [['sendgrid.net', 'pass']], ['sendgrid.net', 'pass']),
    rec('209.85.220.41', 300, [['example.com', 'pass']], ['example.com', 'pass'], 'pass', 'pass'),
  ].join('\n')))
  const a = analyze([r], { domain: 'example.com' })
  const sg = a.senders.find(s => s.key === 'esp:sendgrid')!
  assert.equal(sg.pass, 0)
  assert.equal(sg.why.dkim.unaligned, 100)
  assert.equal(sg.why.spf.unaligned, 100)
  assert.match(sg.fixes[0], /signed by sendgrid\.net/)
  assert.match(sg.fixes[0], /Authenticate Your Domain/)
  const g = a.senders.find(s => s.key === 'esp:google')!
  assert.equal(g.pass, 300)
  assert.equal(g.share, 0.75)
})

test('strict alignment (adkim=s) fails a subdomain signature that relaxed would accept', () => {
  const x = xml(rec('167.89.12.34', 10, [['em.example.com', 'pass']], ['sendgrid.net', 'pass']))
  const relaxed = analyze([parse(x)], { domain: 'example.com' })
  assert.equal(relaxed.pass, 10)
  const strict = parse(x.replace('<adkim>r</adkim>', '<adkim>s</adkim>'))
  const s = analyze([strict], { domain: 'example.com' })
  assert.equal(s.pass, 0)
})

test('forwarding detection: DKIM intact vs broken, separated from spoofing', () => {
  const r = parse(xml([
    rec('198.51.100.23', 40, [['example.com', 'pass']], ['example.com', 'fail'], 'pass', 'fail'),
    rec('198.51.100.24', 10, [['example.com', 'fail']], ['example.com', 'softfail']),
    rec('203.0.113.77', 500, [], ['example.com', 'fail']),
    rec('209.85.220.41', 450, [['example.com', 'pass']], ['example.com', 'pass'], 'pass', 'pass'),
  ].join('\n')))
  const a = analyze([r], { domain: 'example.com' })
  const fwd = a.senders.filter(s => s.verdict === 'forwarder')
  assert.equal(fwd.reduce((t, s) => t + s.volume, 0), 50)
  assert.equal(fwd.reduce((t, s) => t + s.forwardedBroken, 0), 10)
  const spoof = a.senders.find(s => s.verdict === 'suspicious')!
  assert.equal(spoof.volume, 500)
  assert.equal(a.suspiciousVolume, 500)
})

test('readiness = aligned legitimate mail; spoofing and broken forwards are excluded', () => {
  const r = parse(xml([
    rec('209.85.220.41', 900, [['example.com', 'pass']], ['example.com', 'pass'], 'pass', 'pass'),
    rec('167.89.12.34', 100, [['sendgrid.net', 'pass']], ['sendgrid.net', 'pass']),
    rec('203.0.113.77', 5000, [], ['example.com', 'fail']),
    rec('198.51.100.24', 10, [['example.com', 'fail']], ['example.com', 'fail']),
  ].join('\n')))
  const a = analyze([r], { domain: 'example.com' })
  assert.equal(a.legitVolume, 1000)
  assert.equal(a.readiness, 0.9)
  assert.equal(a.atRisk, 100)
})

test('user overrides change verdicts and readiness', () => {
  const r = parse(xml([
    rec('209.85.220.41', 900, [['example.com', 'pass']], ['example.com', 'pass'], 'pass', 'pass'),
    rec('192.0.2.50', 100, [], ['example.com', 'fail']),
  ].join('\n')))
  const before = analyze([r], { domain: 'example.com' })
  assert.equal(before.readiness, 1)
  const key = before.senders.find(s => s.verdict === 'suspicious')!.key
  const after = analyze([r], { domain: 'example.com', overrides: { [key]: 'legit' } })
  assert.equal(after.readiness, 0.9)
  assert.ok(after.senders.find(s => s.key === key)!.overridden)
})

test('"fixed but reports still show failures": fixedSince marks the day a sender became aligned', () => {
  const day = (d: number, ok: boolean) => parse(xml(ok
    ? rec('167.89.12.34', 50, [['example.com', 'pass']], ['sendgrid.net', 'pass'], 'pass')
    : rec('167.89.12.34', 50, [['sendgrid.net', 'pass']], ['sendgrid.net', 'pass'])).replace('<begin>1790000000', `<begin>${1790000000 + d * 86400}`).replace('<report_id>r1', `<report_id>r${d}`))
  const a = analyze([day(0, false), day(1, false), day(2, true), day(3, true)], { domain: 'example.com' })
  const s = a.senders[0]
  assert.equal(s.fixedSince, new Date((1790000000 + 2 * 86400) * 1000).toISOString().slice(0, 10))
  assert.ok(s.fixes.some(f => /Looks fixed/.test(f)))
})

test('ISO weeks, week start and weekly snapshot compare', () => {
  assert.equal(isoWeek(Date.UTC(2026, 0, 1)), '2026-W01')
  assert.equal(isoWeek(Date.UTC(2027, 0, 1)), '2026-W53')
  assert.equal(new Date(weekStart('2026-W44')).toISOString().slice(0, 10), '2026-10-26')
  const reports = sampleXml('northwind').map(f => parse(f.xml))
  const opts = { domain: 'example.com', ptr: SAMPLE_PTR }
  const w1 = snapshot(reports, opts, '2026-W39', 'a'), w6 = snapshot(reports, opts, '2026-W44', 'b')
  const d = compareSnapshots(w1, w6)
  assert.ok(d.readiness > 0.2, `readiness should improve after the SendGrid fix, got ${d.readiness}`)
  assert.ok(d.changed.some(c => c.key === 'esp:sendgrid' && c.after > 0.95 && c.before < 0.05))
})

// ---------- DNS: SPF ----------

test('SPF term parsing with qualifiers, cidr suffixes and modifiers', () => {
  const t = parseSpf('v=spf1 +a/24 mx:mail.example.com -ip4:192.0.2.0/24 ~include:x.com redirect=_spf.example.com ?all')
  assert.deepEqual(t.map(x => [x.qualifier, x.kind, x.value]), [['+', 'a', '/24'], ['+', 'mx', 'mail.example.com'], ['-', 'ip4', '192.0.2.0/24'], ['~', 'include', 'x.com'], ['+', 'redirect', '_spf.example.com'], ['?', 'all', '']])
})

test('SPF expansion counts nested lookups, flags >10, +all, duplicates and void lookups', async () => {
  const zone = sampleZone('northwind')
  const r = await expandSpf('example.com', fakeResolver(zone))
  assert.equal(r.lookups, 13)
  assert.ok(r.issues.some(i => i.level === 'error' && /13 DNS lookups/.test(i.msg)))
  assert.ok(r.ip4.includes('192.0.2.10'))
  const bad = await expandSpf('bad.test', fakeResolver({ 'bad.test': { TXT: ['v=spf1 include:gone1.test include:gone2.test include:gone3.test include:x.test include:x.test +all'] }, 'x.test': { TXT: ['v=spf1 -all'] } }))
  assert.equal(bad.voidLookups, 3)
  assert.ok(bad.issues.some(i => /void lookups/.test(i.msg)))
  assert.ok(bad.issues.some(i => /\+all/.test(i.msg)))
  assert.ok(bad.issues.some(i => /Duplicate/.test(i.msg)))
})

test('SPF: multiple records and include loops are errors; a/mx resolve to addresses', async () => {
  const r = await expandSpf('d.test', fakeResolver({
    'd.test': { TXT: ['v=spf1 a mx include:loop.test -all', 'v=spf1 -all'], A: ['192.0.2.5'], MX: ['10 mx.d.test.'] },
    'mx.d.test': { A: ['192.0.2.6'] },
    'loop.test': { TXT: ['v=spf1 include:d.test -all'] },
  }))
  assert.ok(r.issues.some(i => /2 SPF records/.test(i.msg)))
  assert.ok(r.issues.some(i => /loop/.test(i.msg)))
  assert.deepEqual(r.ip4.sort(), ['192.0.2.5', '192.0.2.6'])
})

test('SPF builder flattens the heaviest includes to get under 10 lookups', async () => {
  const zone = sampleZone('northwind')
  const res = fakeResolver(zone)
  const incs = ['_spf.google.com', 'sendgrid.net', 'servers.mcsv.net', 'mail.zendesk.com', 'spf.protection.outlook.com', '_spf.salesforce.com']
  const expanded: Record<string, Awaited<ReturnType<typeof expandSpf>>['tree'] & object> = {}
  for (const i of incs) expanded[i] = (await expandSpf(i, res)).tree!
  const out = buildSpf({ domain: 'example.com', includes: incs, ip4: ['192.0.2.10'], all: '~all', expanded })
  assert.ok(out.lookups <= 10, `lookups ${out.lookups}`)
  assert.deepEqual(out.flattened, ['_spf.google.com'])
  const root = out.records.find(r => r.host === 'example.com')!.value
  assert.ok(root.startsWith('v=spf1 ') && root.endsWith(' ~all'))
  assert.ok(!root.includes('include:_spf.google.com'))
  assert.ok(out.records.every(r => r.value.length <= 450))
  assert.ok(out.warnings.some(w => /monthly/.test(w)))
})

test('TXT helpers: joining DoH strings and quoting long values into 255-char chunks', () => {
  assert.equal(txtData('"v=spf1 include:a" " -all"'), 'v=spf1 include:a -all')
  assert.equal(txtData('v=spf1 -all'), 'v=spf1 -all')
  const q = txtQuote('x'.repeat(300))
  assert.equal(q, `"${'x'.repeat(255)}" "${'x'.repeat(45)}"`)
})

// ---------- DNS: DMARC, DKIM, grade ----------

test('DMARC parsing validates tags, policy, pct and URIs', () => {
  const d = parseDmarc('v=DMARC1; p=quarantine; pct=25; rua=mailto:a@example.com,mailto:b@vendor.net!10m; adkim=s')
  assert.equal(d.p, 'quarantine')
  assert.equal(d.pct, 25)
  assert.equal(d.rua.length, 2)
  assert.equal(d.adkim, 's')
  assert.ok(!d.issues.some(i => i.level === 'error'))
  const bad = parseDmarc('p=block; v=DMARC1; pct=150; rua=a@example.com')
  assert.equal(bad.p, null)
  assert.ok(bad.issues.filter(i => i.level === 'error').length >= 4)
})

test('external rua destinations need the _report._dmarc authorisation record', async () => {
  const ext = externalDestinations('example.com', ['mailto:dmarc@example.com', 'mailto:x@reports.vendor.net!10m'])
  assert.equal(ext[0].external, false)
  assert.equal(ext[1].checkName, 'example.com._report._dmarc.reports.vendor.net')
  const c = await checkDomain('example.com', fakeResolver(sampleZone('northwind')))
  assert.ok(c.dmarc!.issues.some(i => i.level === 'warn' && /example\.com\._report\._dmarc\.dmarc\.example\.net/.test(i.msg)))
})

test('DKIM key size estimate and revoked keys', () => {
  const k2048 = parseDkim('s', 'v=DKIM1; k=rsa; p=' + 'A'.repeat(392))
  assert.equal(k2048.bits, 2048)
  assert.equal(parseDkim('s', 'v=DKIM1; p=' + 'A'.repeat(216)).bits, 1024)
  assert.ok(parseDkim('s', 'v=DKIM1; p=').revoked)
})

test('domain check and grade: sample domains, caps for missing DMARC and p=none', async () => {
  const nw = await checkDomain('example.com', fakeResolver(sampleZone('northwind')))
  assert.equal(nw.spf.lookups, 13)
  assert.equal(nw.sections.find(s => s.id === 'spf')!.status, 'fail')
  assert.ok(nw.dkim.some(k => k.selector === 'google'))
  assert.ok(['D', 'F'].includes(nw.grade))
  const fs = await checkDomain('example.org', fakeResolver(sampleZone('fieldstone'), { ad: ['example.org'] }))
  assert.equal(fs.sections.find(s => s.id === 'dnssec')!.status, 'pass')
  assert.equal(fs.dmarc!.p, 'quarantine')
  const sec = (id: string, status: Section['status'], points: number, max: number, summary = ''): Section => ({ id, title: id, status, summary, details: [], points, max })
  assert.equal(gradeOf([sec('spf', 'pass', 20, 20), sec('dmarc', 'fail', 0, 10)]).grade, 'D')
  assert.equal(gradeOf([sec('spf', 'pass', 20, 20), sec('dmarc', 'warn', 30, 30, 'p=none')]).grade, 'B')
  assert.equal(gradeOf([sec('spf', 'pass', 20, 20), sec('dmarc', 'pass', 30, 30, 'p=reject')]).grade, 'A')
})

// ---------- Rollout and records ----------

test('rollout planner: blocked below threshold, ready above it, dates step by stage length', () => {
  const now = Date.UTC(2026, 10, 2)
  const base = { domain: 'example.com', rua: ['dmarc@example.com'], reporters: 3, unreviewed: 0, now, since: now - 21 * 86400000 }
  const low = planRollout({ ...base, current: { p: 'none', pct: 100 }, weekly: [{ week: 'a', readiness: 0.9, volume: 10 }, { week: 'b', readiness: 0.95, volume: 10 }] })
  assert.equal(low.stages[1].status, 'blocked')
  assert.ok(low.stages[1].blockers.some(b => /below 98%/.test(b)))
  const ok = planRollout({ ...base, current: { p: 'none', pct: 100 }, weekly: [{ week: 'a', readiness: 0.99, volume: 10 }, { week: 'b', readiness: 0.995, volume: 10 }] })
  assert.equal(ok.stages[1].status, 'ready')
  assert.equal(ok.stages[1].start, now)
  assert.equal(ok.stages[2].start - ok.stages[1].start, 7 * 86400000)
  assert.equal(ok.stages[1].record, 'v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc@example.com')
  assert.equal(stageIndex({ p: 'quarantine', pct: 50 }), 2)
  assert.equal(stageIndex({ p: 'reject', pct: 100 }), 5)
})

test('generated records: DMARC string, MTA-STS policy and BIND snippet', () => {
  assert.equal(generateDmarc({ p: 'reject', rua: ['d@example.com'], adkim: 's' }), 'v=DMARC1; p=reject; rua=mailto:d@example.com; adkim=s')
  assert.equal(mtaStsPolicy(['smtp.google.com.']), 'version: STSv1\nmode: testing\nmx: smtp.google.com\nmax_age: 604800\n')
  const z = zoneSnippet([{ host: '_dmarc.example.com', type: 'TXT', value: 'v=DMARC1; p=none', note: 'DMARC' }])
  assert.equal(z, '; DMARC\n_dmarc.example.com.\t3600\tIN\tTXT\t"v=DMARC1; p=none"')
})

test('sample end to end: Northwind readiness reflects the SendGrid fix; Fieldstone flags Zendesk and lookalike spoofing', () => {
  const nw = sampleXml('northwind').map(f => parse(f.xml))
  assert.equal(nw.length, 42 * 3)
  const a = analyze(nw, { domain: 'example.com', ptr: SAMPLE_PTR })
  const names = a.senders.map(s => s.key)
  for (const k of ['esp:google', 'esp:sendgrid']) assert.ok(names.includes(k), k)
  assert.ok(a.senders.some(s => s.verdict === 'forwarder'))
  assert.ok(a.senders.some(s => s.verdict === 'suspicious'))
  assert.ok(a.senders.find(s => s.key === 'esp:sendgrid')!.fixedSince)
  assert.ok(a.readiness > 0.5 && a.readiness < 0.98)
  const fs = analyze(sampleXml('fieldstone').map(f => parse(f.xml)), { domain: 'example.org', ptr: SAMPLE_PTR })
  const zd = fs.senders.find(s => s.key === 'esp:zendesk')!
  assert.equal(zd.pass, 0)
  assert.ok(zd.disposition.quarantine > 0)
  assert.ok(fs.senders.find(s => s.key === 'esp:ses')!.pass === fs.senders.find(s => s.key === 'esp:ses')!.volume)
})

// ---------- helpers ----------

function makeZip(files: { name: string; data: Buffer; deflate: boolean }[]): Uint8Array {
  const locals: Buffer[] = [], centrals: Buffer[] = []
  let offset = 0
  for (const f of files) {
    const body = f.deflate ? deflateRawSync(f.data) : f.data
    const name = Buffer.from(f.name)
    const lh = Buffer.alloc(30)
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(f.deflate ? 8 : 0, 8)
    lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26)
    const ch = Buffer.alloc(46)
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(f.deflate ? 8 : 0, 10)
    ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42)
    locals.push(lh, name, body); centrals.push(ch, name)
    offset += 30 + name.length + body.length
  }
  const cd = Buffer.concat(centrals)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10)
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16)
  return new Uint8Array(Buffer.concat([...locals, cd, end]))
}

export type { Report }

// ---------- Real-world report files (fixtures/, from parsedmarc, Apache-2.0) ----------

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)))
const fromFile = async (n: string) => {
  const files = await unpack(n, fixture(n))
  assert.equal(files.length, 1, n)
  return parseAggregate(files[0].text)
}

test('real reports: Outlook.com, Fastmail (.xml.gz), Mexican government (.zip) and RFC 9990 (DMARCbis) samples parse', async () => {
  const ol = (await fromFile('outlook-com.xml')).report!
  assert.equal(ol.org, 'Outlook.com')
  assert.equal(ol.rows[0].ip, '100.24.188.149')
  assert.deepEqual(ol.rows[0].spf, [{ domain: 'example.com', scope: 'mfrom', result: 'fail' }])
  const fm = (await fromFile('fastmail.xml.gz')).report!
  assert.equal(fm.org, 'FastMail Pty Ltd')
  assert.equal(fm.id, '102675056')
  const mx = (await fromFile('gob-mx.xml.zip')).report!
  assert.equal(mx.id, '2940')
  const bis = await fromFile('rfc9990-sample.xml')
  assert.equal(bis.issues.filter(i => i.level === 'error').length, 0)
  assert.equal(bis.report!.policy.p, 'quarantine')
  assert.equal(bis.report!.policy.pct, 100) // DMARCbis drops pct
  assert.equal(bis.report!.rows[0].count, 123)
  assert.equal(bis.report!.rows[0].dkim[0].selector, 'abc123')
})

test('real reports: an unclosed wrapper element (IKEA) is salvaged with a warning, not rejected', async () => {
  const r = await fromFile('ikea-unclosed-wrapper.xml')
  assert.ok(r.report)
  assert.equal(r.report.org, 'ikea.com')
  assert.equal(r.report.domain, 'example.de')
  assert.ok(r.issues.some(i => i.level === 'warn' && /<feedback> element itself is intact/.test(i.msg)))
  assert.equal(r.report.rows[0].dkim[0].result, 'pass')
})

test('real reports: unescaped "<" in text (<email><x@y></email>, bad<xml.net) is read as text', async () => {
  const r = await fromFile('unescaped-lt.xml')
  assert.ok(r.report, JSON.stringify(r.issues))
  assert.equal(r.report.email, '<bad-xml@bad-xml.net>')
  assert.equal(r.report.rows.length, 1)
  // real structural errors are still caught
  assert.equal(parseAggregate('<feedback><a></b></feedback>').report, null)
})

test('empty <org_name> falls back to the reporter email domain', async () => {
  const r = (await fromFile('empty-org-name.xml')).report!
  assert.equal(r.org, 'accurateplastics.com')
})

test('report emails: .eml with a multipart zip (Google) and single-part gzip with trailing CRLF (Mimecast)', async () => {
  const g = await unpack('google-multipart-zip.eml', fixture('google-multipart-zip.eml'))
  assert.equal(g.length, 1)
  const gr = parseAggregate(g[0].text).report!
  assert.equal(gr.org, 'google.com')
  assert.equal(gr.domain, 'twlnet.com')
  const m = await unpack('mimecast-gzip-trailing-crlf.eml', fixture('mimecast-gzip-trailing-crlf.eml'))
  assert.match(m[0].name, /^mimecast\.org!ab\.id\.au!.*\.xml$/)
  const mr = parseAggregate(m[0].text).report!
  assert.equal(mr.org, 'Mimecast')
  assert.equal(mr.policy.p, 'reject')
})

test('mbox (Google Takeout): every message in the file is unpacked; an email without a report is an error', async () => {
  const enc = new TextEncoder(), dec = new TextDecoder()
  const mbox = `From 1 Mon Feb 11 10:00:00 2019\n${dec.decode(fixture('google-multipart-zip.eml'))}\nFrom 2 Thu Aug 31 10:00:00 2023\n${dec.decode(fixture('mimecast-gzip-trailing-crlf.eml'))}\n`
  const out = await unpack('Takeout.mbox', enc.encode(mbox))
  assert.deepEqual(out.map(o => parseAggregate(o.text).report?.domain), ['twlnet.com', 'ab.id.au'])
  await assert.rejects(unpack('note.eml', enc.encode('From: a@example.com\nContent-Type: text/plain\n\nhello\n')), /no report attachment/)
  // a bare XML report is never mistaken for an email
  assert.equal((await unpack('r.xml', enc.encode(xml('')))).length, 1)
})

test('organizational domain uses the Public Suffix List (id.au, gob.mx, com.au) and alignment follows it', () => {
  assert.equal(orgDomain('mail.ab.id.au'), 'ab.id.au')
  assert.equal(orgDomain('estadocuenta1.infonacot.gob.mx'), 'infonacot.gob.mx')
  assert.equal(orgDomain('bounce.shop.com.au'), 'shop.com.au')
  assert.equal(orgDomain('a.b.example.io'), 'example.io')
  assert.ok(!aligned('other.id.au', 'ab.id.au'))
  assert.ok(aligned('em.ab.id.au', 'ab.id.au'))
})

test('SPF: the same include reached through two branches is not a loop and its lookups count twice', async () => {
  const r = await expandSpf('d.test', fakeResolver({
    'd.test': { TXT: ['v=spf1 include:v1.test include:v2.test -all'] },
    'v1.test': { TXT: ['v=spf1 include:_spf.shared.test ~all'] },
    'v2.test': { TXT: ['v=spf1 include:_spf.shared.test ~all'] },
    '_spf.shared.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 include:deep.test ~all'] },
    'deep.test': { TXT: ['v=spf1 ip4:198.51.100.0/24 ~all'] },
  }))
  assert.ok(!r.issues.some(i => /loop/.test(i.msg)), JSON.stringify(r.issues))
  // v1, v2, shared twice, deep twice
  assert.equal(r.lookups, 6)
  assert.deepEqual(r.ip4.sort(), ['192.0.2.0/24', '198.51.100.0/24'])
})

test('rollout blockers print a slider threshold like 96.5% without float noise', () => {
  const now = Date.UTC(2026, 10, 2)
  const p = planRollout({ domain: 'example.com', rua: ['dmarc@example.com'], reporters: 3, unreviewed: 0, now, since: now, threshold: 0.965, current: { p: 'none', pct: 100 }, weekly: [{ week: 'a', readiness: 0.9, volume: 10 }, { week: 'b', readiness: 0.95, volume: 10 }] })
  const b = p.stages[1].blockers.join(' ')
  assert.match(b, /below 96\.5%/)
  assert.doesNotMatch(b, /\d\.\d{3,}/)
})

test('DMARC parsing rejects an invalid np= (DMARCbis) as it does sp=', () => {
  assert.ok(parseDmarc('v=DMARC1; p=reject; np=block').issues.some(i => i.level === 'error' && /np=block/.test(i.msg)))
  assert.ok(!parseDmarc('v=DMARC1; p=reject; np=reject; rua=mailto:d@example.com').issues.some(i => i.level === 'error'))
})
