// Live domain checks over DoH and the grade card: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, DNSSEC.
import { ofType, txtOf, type Resolver } from './dns.ts'
import { externalDestinations, isDmarc, parseDmarc, type Dmarc } from './dmarc.ts'
import { normDomain, orgDomain } from './domain.ts'
import { expandSpf, type SpfResult } from './spf.ts'

export const COMMON_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'default', 'dkim', 'mail', 'mandrill', 'mxvault',
  'smtp', 'sig1', 'zendesk1', 'zendesk2', 'hs1', 'hs2', 'mailjet', 'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'zoho', 'cm', 'krs', 'mx', 'pic', 'key1', 'everlytickey1', 'brevo1', 'kl', 'intercom', 'scph0920']

export type Status = 'pass' | 'warn' | 'fail' | 'info'
export interface Section { id: string; title: string; status: Status; summary: string; details: string[]; points: number; max: number; record?: string }

export interface DkimKey { selector: string; record: string; keyType: string; bits: number | null; revoked: boolean; testing: boolean }

export interface DomainCheck {
  domain: string
  at: number
  via: string
  mx: string[]
  nullMx: boolean
  spf: SpfResult
  dmarc: (Dmarc & { record: string; inherited: string | null }) | null
  dkim: DkimKey[]
  sections: Section[]
  score: number
  grade: string
  capped: string | null
}

export function parseDkim(selector: string, record: string): DkimKey {
  const tags = Object.fromEntries(record.split(';').map(p => p.trim()).filter(Boolean).map(p => { const i = p.indexOf('='); return [p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).replace(/\s+/g, '')] }))
  const p = tags.p ?? ''
  const keyType = (tags.k ?? 'rsa').toLowerCase()
  let bits: number | null = null
  if (p) {
    const bytes = Math.floor(p.replace(/=+$/, '').length * 3 / 4)
    if (keyType === 'ed25519') bits = 256
    else bits = bytes < 100 ? 512 : bytes < 200 ? 1024 : bytes < 330 ? 2048 : bytes < 600 ? 4096 : Math.round(bytes * 8 / 1024) * 1024
  }
  return { selector, record, keyType, bits, revoked: !p, testing: /\by\b/.test(tags.t ?? '') }
}

const MX_PROVIDERS: [RegExp, string][] = [
  [/(^|\.)google(mail)?\.com$|aspmx\.l\.google\.com$|smtp\.google\.com$/, 'Google Workspace'],
  [/mail\.protection\.outlook\.com$/, 'Microsoft 365'],
  [/(^|\.)mx\.cloudflare\.net$/, 'Cloudflare Email Routing'],
  [/(^|\.)pphosted\.com$/, 'Proofpoint'], [/(^|\.)mimecast\.com$/, 'Mimecast'], [/(^|\.)zoho\.(com|eu|in)$/, 'Zoho Mail'],
  [/(^|\.)messagingengine\.com$/, 'Fastmail'], [/(^|\.)protonmail\.ch$/, 'Proton Mail'], [/(^|\.)secureserver\.net$/, 'GoDaddy'],
]
export const mxProvider = (host: string) => MX_PROVIDERS.find(([re]) => re.test(host.toLowerCase()))?.[1] ?? null

export async function checkDomain(input: string, resolve: Resolver, opts: { selectors?: string[]; fetchPolicy?: (domain: string) => Promise<string | null> } = {}): Promise<DomainCheck> {
  const domain = normDomain(input)
  const selectors = [...new Set([...(opts.selectors ?? []).map(s => s.trim().toLowerCase()).filter(Boolean), ...COMMON_SELECTORS])]
  const [mxA, dmarcA, stsA, tlsA, bimiA, spf, dk] = await Promise.all([
    resolve(domain, 'MX'),
    resolve(`_dmarc.${domain}`, 'TXT'),
    resolve(`_mta-sts.${domain}`, 'TXT').catch(() => null),
    resolve(`_smtp._tls.${domain}`, 'TXT').catch(() => null),
    resolve(`default._bimi.${domain}`, 'TXT').catch(() => null),
    expandSpf(domain, resolve),
    Promise.all(selectors.map(async s => {
      const a = await resolve(`${s}._domainkey.${domain}`, 'TXT').catch(() => null)
      const rec = a ? txtOf(a).find(t => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(t)) : undefined
      return rec !== undefined ? parseDkim(s, rec) : null
    })),
  ])
  const mxRecs = ofType(mxA, 'MX').map(x => { const [pref, host] = x.split(/\s+/); return { pref: +pref, host: (host ?? '').replace(/\.$/, '') } }).sort((a, b) => a.pref - b.pref)
  const nullMx = mxRecs.length === 1 && mxRecs[0].host === ''
  const mx = nullMx ? [] : mxRecs.map(m => m.host)

  let dmarcRecs = txtOf(dmarcA).filter(isDmarc)
  let inherited: string | null = null
  const org = orgDomain(domain)
  if (!dmarcRecs.length && org !== domain) {
    const o = await resolve(`_dmarc.${org}`, 'TXT').catch(() => null)
    const recs = o ? txtOf(o).filter(isDmarc) : []
    if (recs.length) { dmarcRecs = recs; inherited = org }
  }
  const dmarc = dmarcRecs.length ? { ...parseDmarc(dmarcRecs[0]), record: dmarcRecs[0], inherited } : null
  if (dmarc && dmarcRecs.length > 1) dmarc.issues.unshift({ level: 'error', msg: `${dmarcRecs.length} DMARC records published; receivers ignore all of them. Keep one.` })
  if (dmarc) {
    for (const d of externalDestinations(domain, [...dmarc.rua, ...dmarc.ruf]).filter(x => x.external)) {
      const a = await resolve(d.checkName!, 'TXT').catch(() => null)
      const ok = !!a && txtOf(a).some(t => /^v=DMARC1/i.test(t))
      dmarc.issues.push(ok
        ? { level: 'info', msg: `${d.host} authorises reports for ${domain} (${d.checkName}).` }
        : { level: 'warn', msg: `${d.uri} is on another domain and ${d.checkName} has no "v=DMARC1" record, so receivers will not send reports there. Most report services publish this for you once you add the domain in their dashboard.` })
    }
  }

  const sts = stsA ? txtOf(stsA).find(t => /^v=STSv1/i.test(t)) ?? null : null
  let stsPolicy: string | null = null
  if (sts && opts.fetchPolicy) stsPolicy = await opts.fetchPolicy(domain).catch(() => null)
  const tlsRpt = tlsA ? txtOf(tlsA).find(t => /^v=TLSRPTv1/i.test(t)) ?? null : null
  const bimi = bimiA ? txtOf(bimiA).find(t => /^v=BIMI1/i.test(t)) ?? null : null
  const dkim = dk.filter((x): x is DkimKey => !!x)
  const ad = mxA.ad || dmarcA.ad

  const sections = buildSections({ domain, mx, nullMx, spf, dmarc, dkim, sts, stsPolicy, tlsRpt, bimi, dnssec: ad })
  const g = gradeOf(sections)
  return { domain, at: Date.now(), via: mxA.via ?? 'DoH', mx, nullMx, spf, dmarc, dkim, sections, ...g }
}

interface SectionInput {
  domain: string; mx: string[]; nullMx: boolean; spf: SpfResult; dmarc: (Dmarc & { record: string; inherited: string | null }) | null; dkim: DkimKey[]
  sts: string | null; stsPolicy: string | null; tlsRpt: string | null; bimi: string | null; dnssec: boolean
}

const msgs = (l: { level: string; msg: string }[]) => l.map(i => (i.level === 'error' ? 'Error: ' : i.level === 'warn' ? 'Warning: ' : '') + i.msg)

export function buildSections(i: SectionInput): Section[] {
  const out: Section[] = []
  const providers = [...new Set(i.mx.map(mxProvider).filter(Boolean))]
  out.push(i.nullMx
    ? { id: 'mx', title: 'MX', status: 'pass', summary: 'Null MX: this domain does not receive mail', details: ['If it also sends no mail, publish "v=spf1 -all" and "v=DMARC1; p=reject" so nobody can send as it.'], points: 5, max: 5 }
    : i.mx.length
      ? { id: 'mx', title: 'MX', status: 'pass', summary: `${i.mx.length} mail server${i.mx.length > 1 ? 's' : ''}${providers.length ? ` (${providers.join(', ')})` : ''}`, details: i.mx, points: 5, max: 5 }
      : { id: 'mx', title: 'MX', status: 'warn', summary: 'No MX records', details: ['Without MX (or a null MX) receivers fall back to the A record. If the domain receives no mail, publish "0 ." as a null MX.'], points: 2, max: 5 })

  const s = i.spf
  const spfErr = s.issues.some(x => x.level === 'error')
  const spfWarn = s.issues.some(x => x.level === 'warn')
  const spfPts = !s.record ? 0 : spfErr ? 4 : spfWarn ? 14 : 20
  const mxNeeds = providers.includes('Google Workspace') && s.record && !JSON.stringify(s.tree).includes('_spf.google.com') ? ['Warning: MX points to Google Workspace but SPF does not include _spf.google.com.']
    : providers.includes('Microsoft 365') && s.record && !JSON.stringify(s.tree).includes('spf.protection.outlook.com') ? ['Warning: MX points to Microsoft 365 but SPF does not include spf.protection.outlook.com.'] : []
  out.push({ id: 'spf', title: 'SPF', status: !s.record || spfErr ? 'fail' : spfWarn || mxNeeds.length ? 'warn' : 'pass', record: s.record ?? undefined,
    summary: s.record ? `${s.lookups}/10 lookups, ${s.all ?? 'no all'}${s.voidLookups ? `, ${s.voidLookups} void` : ''}` : 'Missing',
    details: [...msgs(s.issues), ...mxNeeds], points: mxNeeds.length ? Math.min(spfPts, 14) : spfPts, max: 20 })

  const d = i.dmarc
  if (!d) out.push({ id: 'dmarc', title: 'DMARC', status: 'fail', summary: 'Missing', details: ['No record at _dmarc.' + i.domain + '. Gmail, Yahoo and Outlook.com require one for bulk senders. Start with "v=DMARC1; p=none; rua=mailto:dmarc@' + i.domain + '".'], points: 0, max: 30 })
  else {
    const err = d.issues.some(x => x.level === 'error')
    const pts = err ? 4 : d.p === 'reject' ? (d.pct === 100 ? 30 : 26) : d.p === 'quarantine' ? (d.pct === 100 ? 24 : 20) : d.rua.length ? 12 : 6
    out.push({ id: 'dmarc', title: 'DMARC', status: err ? 'fail' : d.p === 'none' || d.issues.some(x => x.level === 'warn') ? 'warn' : 'pass', record: d.record,
      summary: `p=${d.p ?? '?'}${d.pct < 100 ? ` pct=${d.pct}` : ''}${d.rua.length ? ', reports on' : ', no reports'}${d.inherited ? ` (inherited from ${d.inherited})` : ''}`,
      details: msgs(d.issues), points: pts, max: 30 })
  }

  const good = i.dkim.filter(k => !k.revoked)
  const weak = good.filter(k => k.bits !== null && k.bits < 2048 && k.keyType === 'rsa')
  out.push(good.length
    ? { id: 'dkim', title: 'DKIM', status: weak.length === good.length ? 'warn' : 'pass', summary: `${good.length} key${good.length > 1 ? 's' : ''}: ${good.map(k => `${k.selector}${k.bits ? ` (${k.bits}-bit)` : ''}`).join(', ')}`,
      details: [...weak.map(k => `Warning: ${k.selector} is a ${k.bits}-bit key. Rotate to 2048-bit.`), ...good.filter(k => k.testing).map(k => `${k.selector} is in testing mode (t=y).`), ...i.dkim.filter(k => k.revoked).map(k => `${k.selector} is revoked (empty p=).`), 'Only common selectors are checked; add yours in the domain settings. Aggregate reports show the selectors actually in use.'],
      points: weak.length === good.length ? 15 : 20, max: 20 }
    : { id: 'dkim', title: 'DKIM', status: 'warn', summary: 'No keys at common selectors', details: ['DKIM may still be set up with a selector we did not try (e.g. a dated Postmark or SES token selector). Import reports to see the selectors in use, or add them in settings.'], points: 4, max: 20 })

  const mode = i.stsPolicy?.match(/mode:\s*(\w+)/)?.[1]
  out.push(i.sts
    ? { id: 'mta-sts', title: 'MTA-STS', status: mode === 'enforce' ? 'pass' : 'warn', record: i.sts, summary: mode ? `mode: ${mode}` : 'TXT published', details: i.stsPolicy ? [i.stsPolicy.trim()] : ['Policy file could not be fetched from the browser. Check https://mta-sts.' + i.domain + '/.well-known/mta-sts.txt'], points: mode === 'enforce' ? 7 : 4, max: 7 }
    : { id: 'mta-sts', title: 'MTA-STS', status: 'info', summary: 'Not set up', details: ['Optional. Forces TLS for mail sent to you. The generated records include a policy file you can host on a Cloudflare Worker or Pages.'], points: 0, max: 7 })
  out.push(i.tlsRpt
    ? { id: 'tls-rpt', title: 'TLS-RPT', status: 'pass', record: i.tlsRpt, summary: 'Reporting on', details: [], points: 5, max: 5 }
    : { id: 'tls-rpt', title: 'TLS-RPT', status: 'info', summary: 'Not set up', details: ['Optional. Receivers email you when TLS to your MX fails.'], points: 0, max: 5 })
  out.push({ id: 'dnssec', title: 'DNSSEC', status: i.dnssec ? 'pass' : 'info', summary: i.dnssec ? 'Signed and validated (AD flag set)' : 'Not validated', details: i.dnssec ? [] : ['Optional but recommended. On Cloudflare: DNS > Settings > Enable DNSSEC, then add the DS record at your registrar.'], points: i.dnssec ? 8 : 0, max: 8 })
  const enforced = i.dmarc && i.dmarc.p !== 'none' && i.dmarc.pct === 100
  out.push(i.bimi
    ? { id: 'bimi', title: 'BIMI', status: enforced ? 'pass' : 'warn', record: i.bimi, summary: 'Logo record published', details: enforced ? [] : ['BIMI logos only show when DMARC is p=quarantine or p=reject at 100%.'], points: 5, max: 5 }
    : { id: 'bimi', title: 'BIMI', status: 'info', summary: 'Not set up', details: ['Optional. Shows your logo in Gmail/Yahoo after DMARC enforcement (Gmail needs a VMC or CMC certificate).'], points: 0, max: 5 })
  return out
}

export function gradeOf(sections: Section[]): { score: number; grade: string; capped: string | null } {
  const score = Math.round(sections.reduce((s, x) => s + x.points, 0) / sections.reduce((s, x) => s + x.max, 0) * 100)
  let grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F'
  let capped: string | null = null
  const st = (id: string) => sections.find(s => s.id === id)?.status
  if (st('dmarc') === 'fail' || st('spf') === 'fail') {
    if (grade < 'D') { grade = 'D'; capped = st('dmarc') === 'fail' ? 'Capped at D: DMARC is missing or invalid.' : 'Capped at D: SPF is missing or broken.' }
  } else if (sections.find(s => s.id === 'dmarc')?.summary.startsWith('p=none') && grade === 'A') { grade = 'B'; capped = 'Capped at B until DMARC enforces (quarantine or reject).' }
  return { score, grade, capped }
}
