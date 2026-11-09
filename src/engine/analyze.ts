// Sender inventory, alignment analysis, forwarding detection and policy readiness from aggregate reports.
import type { Report, Row } from './aggregate.ts'
import { aligned, inCidr, netOf, orgDomain } from './domain.ts'
import { ESPS, type Esp } from './esps.ts'

export type Verdict = 'legit' | 'forwarder' | 'suspicious'
export type Override = 'legit' | 'unauthorized'

export interface Options {
  domain: string
  /** Sender key -> user decision */
  overrides?: Record<string, Override>
  /** Source IP -> PTR hostname (null = looked up, none found) */
  ptr?: Record<string, string | null>
}

export type DkimWhy = 'aligned' | 'none' | 'unaligned' | 'fail'
export type SpfWhy = 'aligned' | 'none' | 'unaligned' | 'fail'

export interface RowAnalysis {
  row: Row
  report: Report
  pass: boolean
  dkimAligned: boolean
  spfAligned: boolean
  dkimWhy: DkimWhy
  spfWhy: SpfWhy
  forwarded: 'intact' | 'broken' | null
  esp: Esp | null
  ptr: string | null
}

export interface Sender {
  key: string
  name: string
  /** Header From domain this sender mostly uses */
  from: string
  esp: Esp | null
  verdict: Verdict
  /** True when the verdict came from the user, not the heuristics */
  overridden: boolean
  volume: number
  pass: number
  dkimAligned: number
  spfAligned: number
  share: number
  ips: { ip: string; count: number; ptr: string | null }[]
  dkimDomains: Record<string, number>
  spfDomains: Record<string, number>
  why: { dkim: Record<DkimWhy, number>; spf: Record<SpfWhy, number> }
  disposition: { none: number; quarantine: number; reject: number }
  forwardedBroken: number
  days: { day: string; volume: number; pass: number }[]
  /** Day from which every report shows this sender aligned, after earlier failures */
  fixedSince: string | null
  fixes: string[]
}

export interface Analysis {
  domain: string
  reports: number
  reporters: { org: string; reports: number; volume: number }[]
  range: { begin: number; end: number } | null
  total: number
  pass: number
  legitVolume: number
  legitPass: number
  forwardVolume: number
  forwardPass: number
  suspiciousVolume: number
  suspiciousPass: number
  /** Share of legitimate mail (your senders + forwarded mail that kept its DKIM) that passes DMARC */
  readiness: number
  /** Legitimate messages that would be quarantined or rejected under enforcement */
  atRisk: number
  senders: Sender[]
  days: { day: string; volume: number; pass: number; suspicious: number }[]
  policies: Record<string, number>
}

const day = (t: number) => new Date(t).toISOString().slice(0, 10)
const FORWARD_REASONS = new Set(['forwarded', 'mailing_list', 'trusted_forwarder'])

export function identify(ip: string, ptr: string | null, authDomains: string[]): Esp | null {
  for (const e of ESPS) if (authDomains.some(d => e.authDomains.test(d))) return e
  for (const e of ESPS) if (e.cidrs.some(c => inCidr(ip, c))) return e
  if (ptr) { const h = ptr.toLowerCase().replace(/\.$/, ''); for (const e of ESPS) if (e.rdns.test(h)) return e }
  return null
}

export function analyzeRow(row: Row, report: Report, domain: string, ptr: string | null): RowAnalysis {
  const from = row.headerFrom || domain
  const { adkim, aspf } = report.policy
  const passingDkim = row.dkim.filter(d => d.result === 'pass')
  const dkimAligned = row.dkim.length ? passingDkim.some(d => aligned(d.domain, from, adkim)) : row.evalDkim === 'pass'
  const ownSig = row.dkim.some(d => aligned(d.domain, from, 'r'))
  const dkimWhy: DkimWhy = dkimAligned ? 'aligned' : !row.dkim.length ? 'none' : ownSig ? 'fail' : passingDkim.length ? 'unaligned' : 'fail'
  const mfrom = row.spf.filter(s => s.scope !== 'helo')
  const spfList = mfrom.length ? mfrom : row.spf
  const spfAligned = spfList.length ? spfList.some(s => s.result === 'pass' && aligned(s.domain, from, aspf)) : row.evalSpf === 'pass'
  const spfWhy: SpfWhy = spfAligned ? 'aligned' : !spfList.length ? 'none' : spfList.some(s => aligned(s.domain, from, 'r')) ? 'fail' : 'unaligned'
  // The receiver's verdict wins (it may know about ARC or local overrides); our analysis explains it.
  const pass = row.evalDkim === 'pass' || row.evalSpf === 'pass' || dkimAligned || spfAligned
  const authDomains = [...row.dkim.filter(d => !aligned(d.domain, from, 'r')).map(d => d.domain), ...row.spf.filter(s => !aligned(s.domain, from, 'r')).map(s => s.domain)]
  const esp = identify(row.ip, ptr, authDomains)
  let forwarded: RowAnalysis['forwarded'] = null
  if (row.reasons.some(r => FORWARD_REASONS.has(r))) forwarded = dkimAligned ? 'intact' : 'broken'
  else if (!esp && dkimAligned && !spfAligned && spfWhy === 'fail') forwarded = 'intact'
  else if (!esp && !dkimAligned && dkimWhy === 'fail' && ownSig && !spfAligned) forwarded = 'broken'
  return { row, report, pass, dkimAligned, spfAligned, dkimWhy, spfWhy, forwarded, esp, ptr }
}

const zeroWhy = () => ({ aligned: 0, none: 0, unaligned: 0, fail: 0 })
const hostLabel = (ptr: string | null) => ptr ? orgDomain(ptr.replace(/\.$/, '')) : null

export function senderKey(a: RowAnalysis): string {
  if (a.esp) return `esp:${a.esp.id}`
  const host = hostLabel(a.ptr)
  if (a.forwarded) return `fwd:${host ?? netOf(a.row.ip)}`
  return host ? `host:${host}` : `net:${netOf(a.row.ip)}`
}

export function analyze(reports: Report[], opts: Options): Analysis {
  const domain = opts.domain.toLowerCase()
  const org = orgDomain(domain)
  const rows: RowAnalysis[] = []
  const policies: Record<string, number> = {}
  const reporters = new Map<string, { org: string; reports: number; volume: number }>()
  let begin = Infinity, end = -Infinity
  for (const r of reports) {
    if (domain && orgDomain(r.domain) !== org) continue
    begin = Math.min(begin, r.begin); end = Math.max(end, r.end)
    const p = `p=${r.policy.p}${r.policy.pct < 100 ? ` pct=${r.policy.pct}` : ''}`
    const rep = reporters.get(r.org) ?? { org: r.org, reports: 0, volume: 0 }
    rep.reports++
    for (const row of r.rows) {
      rows.push(analyzeRow(row, r, domain || r.domain, opts.ptr?.[row.ip] ?? null))
      rep.volume += row.count
      policies[p] = (policies[p] ?? 0) + row.count
    }
    reporters.set(r.org, rep)
  }

  const groups = new Map<string, RowAnalysis[]>()
  for (const a of rows) { const k = senderKey(a); groups.set(k, [...groups.get(k) ?? [], a]) }
  const total = rows.reduce((s, a) => s + a.row.count, 0)

  const senders: Sender[] = [...groups.entries()].map(([key, list]) => buildSender(key, list, total, opts.overrides?.[key]))
  senders.sort((a, b) => b.volume - a.volume)

  const sum = (v: Verdict, f: (s: Sender) => number) => senders.filter(s => s.verdict === v).reduce((t, s) => t + f(s), 0)
  const legitVolume = sum('legit', s => s.volume), legitPass = sum('legit', s => s.pass)
  const forwardVolume = sum('forwarder', s => s.volume), forwardPass = sum('forwarder', s => s.pass)
  const denom = legitVolume + forwardPass
  const byDay = new Map<string, { day: string; volume: number; pass: number; suspicious: number }>()
  const verdictOf = new Map(senders.map(s => [s.key, s.verdict]))
  for (const a of rows) {
    const d = day(a.report.begin)
    const e = byDay.get(d) ?? { day: d, volume: 0, pass: 0, suspicious: 0 }
    e.volume += a.row.count
    if (a.pass) e.pass += a.row.count
    if (verdictOf.get(senderKey(a)) === 'suspicious') e.suspicious += a.row.count
    byDay.set(d, e)
  }
  return {
    domain, reports: reports.filter(r => !domain || orgDomain(r.domain) === org).length,
    reporters: [...reporters.values()].sort((a, b) => b.volume - a.volume),
    range: Number.isFinite(begin) ? { begin, end } : null,
    total, pass: rows.reduce((s, a) => s + (a.pass ? a.row.count : 0), 0),
    legitVolume, legitPass, forwardVolume, forwardPass,
    suspiciousVolume: sum('suspicious', s => s.volume), suspiciousPass: sum('suspicious', s => s.pass),
    readiness: denom ? (legitPass + forwardPass) / denom : 0,
    atRisk: legitVolume - legitPass,
    senders,
    days: [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day)),
    policies,
  }
}

function buildSender(key: string, list: RowAnalysis[], total: number, override?: Override): Sender {
  const esp = list[0].esp
  const ips = new Map<string, { ip: string; count: number; ptr: string | null }>()
  const s: Sender = {
    key, name: '', from: list[0].row.headerFrom, esp, verdict: 'legit', overridden: !!override, volume: 0, pass: 0, dkimAligned: 0, spfAligned: 0, share: 0, ips: [],
    dkimDomains: {}, spfDomains: {}, why: { dkim: zeroWhy(), spf: zeroWhy() }, disposition: { none: 0, quarantine: 0, reject: 0 },
    forwardedBroken: 0, days: [], fixedSince: null, fixes: [],
  }
  const days = new Map<string, { day: string; volume: number; pass: number }>()
  let forwardedVol = 0
  for (const a of list) {
    const n = a.row.count
    s.volume += n
    if (a.pass) s.pass += n
    if (a.dkimAligned) s.dkimAligned += n
    if (a.spfAligned) s.spfAligned += n
    s.why.dkim[a.dkimWhy] += n
    s.why.spf[a.spfWhy] += n
    s.disposition[a.row.disposition] += n
    if (a.forwarded) forwardedVol += n
    if (a.forwarded === 'broken') s.forwardedBroken += n
    for (const d of a.row.dkim) if (d.domain) s.dkimDomains[d.domain] = (s.dkimDomains[d.domain] ?? 0) + n
    for (const d of a.row.spf) if (d.domain) s.spfDomains[d.domain] = (s.spfDomains[d.domain] ?? 0) + n
    const ip = ips.get(a.row.ip) ?? { ip: a.row.ip, count: 0, ptr: a.ptr }
    ip.count += n
    ips.set(a.row.ip, ip)
    const dk = day(a.report.begin)
    const d = days.get(dk) ?? { day: dk, volume: 0, pass: 0 }
    d.volume += n
    if (a.pass) d.pass += n
    days.set(dk, d)
  }
  s.ips = [...ips.values()].sort((a, b) => b.count - a.count)
  s.share = total ? s.volume / total : 0
  s.days = [...days.values()].sort((a, b) => a.day.localeCompare(b.day))
  // "I fixed it but reports still show failures": find the day after which this sender is consistently aligned.
  const ok = (d: { volume: number; pass: number }) => d.pass >= d.volume * 0.98
  if (s.days.some(d => !ok(d)) && ok(s.days.at(-1)!)) {
    let i = s.days.length - 1
    while (i > 0 && ok(s.days[i - 1])) i--
    s.fixedSince = s.days[i].day
  }
  const host = key.split(':').slice(1).join(':')
  const passShare = s.volume ? s.pass / s.volume : 0
  if (override) s.verdict = override === 'legit' ? (forwardedVol > s.volume / 2 ? 'forwarder' : 'legit') : 'suspicious'
  else if (esp) s.verdict = 'legit'
  else if (forwardedVol > s.volume / 2) s.verdict = 'forwarder'
  else s.verdict = passShare >= 0.5 ? 'legit' : 'suspicious'
  s.name = esp ? esp.name : s.verdict === 'forwarder' ? `Forwarder (${host})` : key.startsWith('host:') ? (host === orgDomain(s.from) ? `Your server (${s.ips[0].ptr?.replace(/\.$/, '')})` : host) : `Unknown (${host})`
  s.fixes = fixesFor(s)
  return s
}

const topKey = (r: Record<string, number>) => Object.entries(r).sort((a, b) => b[1] - a[1])[0]?.[0]

export function fixesFor(s: Sender): string[] {
  const out: string[] = []
  const failing = s.volume - s.pass
  if (s.verdict === 'suspicious') {
    out.push(s.overridden
      ? 'Marked unauthorized. Nothing to fix: once your policy reaches p=reject, receivers will refuse this mail.'
      : `Not identified as one of your services and ${failing ? 'mostly failing DMARC' : 'sending as you'}. If you recognise it (an app server, a CRM, a printer), mark it legitimate and set up DKIM for it. Otherwise it is likely spoofing, and p=reject will block it.`)
    return out
  }
  if (s.verdict === 'forwarder') {
    if (s.forwardedBroken) out.push(`${s.forwardedBroken.toLocaleString('en-US')} forwarded messages lost their DKIM signature (mailing lists and forwarders that rewrite the message). This cannot be fixed in your DNS; receivers that honour ARC usually still deliver them. They are excluded from readiness.`)
    else out.push('Forwarded mail that kept your DKIM signature, so it passes DMARC even though SPF fails at the forwarder. Nothing to fix. This is why DKIM on every sender matters more than SPF.')
    return out
  }
  if (failing === 0) {
    out.push(s.dkimAligned === s.volume ? 'Fully aligned on DKIM. Ready for enforcement.' : 'Passing on SPF alignment only. Add DKIM signing with your domain so the mail survives forwarding.')
    if (s.dkimAligned < s.volume && s.esp) out.push(s.esp.dkimFix)
    return out
  }
  const dkimOther = topKey(Object.fromEntries(Object.entries(s.dkimDomains).filter(([d]) => !aligned(d, s.from, 'r'))))
  if (s.esp) {
    if (s.why.dkim.unaligned || s.why.dkim.none) out.push(`DKIM is ${s.why.dkim.unaligned ? `signed by ${dkimOther}, not your domain` : 'missing'}. ${s.esp.dkimFix}`)
    else if (s.why.dkim.fail) out.push(`DKIM signatures for your domain are failing. Check that the published ${s.esp.name} DKIM record matches the key in its settings (a stale or truncated key is the usual cause).`)
    if (s.why.spf.fail && s.esp.spfInclude) out.push(`SPF fails for your domain from ${s.esp.name} IPs. If ${s.esp.name} sends with your domain as the Return-Path, add include:${s.esp.spfInclude} to your SPF record (watch the 10-lookup limit; the SPF builder handles it).`)
    else if (s.why.spf.unaligned && s.esp.spfFix) out.push(`Optional once DKIM aligns: ${s.esp.spfFix}`)
  } else {
    const ip = s.ips[0]
    out.push(`Unrecognised source${ip?.ptr ? ` (${ip.ptr})` : ''} sending as your domain with ${Math.round((failing / s.volume) * 100)}% failing. Find which system this is (look up ${ip?.ip ?? 'the IP'}), then turn on DKIM signing with your domain there, or add its IPs to SPF and have it use your domain as the Return-Path.`)
  }
  if (s.fixedSince) out.push(`Looks fixed: every report since ${s.fixedSince} shows this sender aligned. Aggregate reports cover 24-hour windows and arrive 1 to 3 days late, so failures from before the fix keep showing up for a few days.`)
  return out
}

// ---------- Weeks and snapshots ----------

/** ISO week, e.g. "2026-W44" */
export function isoWeek(t: number): string {
  const d = new Date(t)
  const date = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())
  const dow = (new Date(date).getUTCDay() + 6) % 7
  const thursday = date - dow * 86400000 + 3 * 86400000
  const year = new Date(thursday).getUTCFullYear()
  const week = 1 + Math.floor((thursday - Date.UTC(year, 0, 4) + ((new Date(Date.UTC(year, 0, 4)).getUTCDay() + 6) % 7) * 86400000) / (7 * 86400000))
  return `${year}-W${String(week).padStart(2, '0')}`
}

/** Monday of an ISO week (UTC ms) */
export function weekStart(w: string): number {
  const [y, n] = w.split('-W').map(Number)
  const jan4 = Date.UTC(y, 0, 4)
  const dow = (new Date(jan4).getUTCDay() + 6) % 7
  return jan4 - dow * 86400000 + (n - 1) * 7 * 86400000
}

export const weeksOf = (reports: Report[]) => [...new Set(reports.map(r => isoWeek(r.begin)))].sort()

export interface Snapshot {
  id: string
  period: string
  label: string
  at: number
  total: number
  pass: number
  legitVolume: number
  readiness: number
  atRisk: number
  suspiciousVolume: number
  forwardVolume: number
  senders: { key: string; name: string; verdict: Verdict; volume: number; pass: number }[]
}

export function snapshot(reports: Report[], opts: Options, week: string, id: string): Snapshot {
  const a = analyze(reports.filter(r => isoWeek(r.begin) === week), opts)
  const start = weekStart(week)
  const label = `Week of ${new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}`
  return {
    id, period: week, label, at: Date.now(), total: a.total, pass: a.pass, legitVolume: a.legitVolume, readiness: a.readiness, atRisk: a.atRisk,
    suspiciousVolume: a.suspiciousVolume, forwardVolume: a.forwardVolume,
    senders: a.senders.map(s => ({ key: s.key, name: s.name, verdict: s.verdict, volume: s.volume, pass: s.pass })),
  }
}

export interface SnapshotDiff {
  readiness: number
  total: number
  added: Snapshot['senders']
  removed: Snapshot['senders']
  changed: { key: string; name: string; before: number; after: number; volumeBefore: number; volumeAfter: number }[]
}

export function compareSnapshots(a: Snapshot, b: Snapshot): SnapshotDiff {
  const am = new Map(a.senders.map(s => [s.key, s]))
  const bm = new Map(b.senders.map(s => [s.key, s]))
  const rate = (s: { volume: number; pass: number }) => s.volume ? s.pass / s.volume : 0
  return {
    readiness: b.readiness - a.readiness,
    total: b.total - a.total,
    added: b.senders.filter(s => !am.has(s.key)),
    removed: a.senders.filter(s => !bm.has(s.key)),
    changed: b.senders.filter(s => am.has(s.key)).map(s => {
      const o = am.get(s.key)!
      return { key: s.key, name: s.name, before: rate(o), after: rate(s), volumeBefore: o.volume, volumeAfter: s.volume }
    }).filter(c => Math.abs(c.after - c.before) >= 0.005 || c.volumeAfter !== c.volumeBefore).sort((x, y) => Math.abs(y.after - y.before) - Math.abs(x.after - x.before)),
  }
}
