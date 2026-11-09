// RFC 7489 Appendix C aggregate report parser with a validation report.
import { child, kids, parseXml, txt, XmlError, type XNode } from './xml.ts'
import { isIP, normDomain } from './domain.ts'

export type Result = 'pass' | 'fail' | 'none' | 'neutral' | 'softfail' | 'temperror' | 'permerror' | 'policy'

export interface Row {
  ip: string
  count: number
  disposition: 'none' | 'quarantine' | 'reject'
  /** policy_evaluated results as the receiver saw them (aligned pass / fail) */
  evalDkim: 'pass' | 'fail'
  evalSpf: 'pass' | 'fail'
  reasons: string[]
  headerFrom: string
  envelopeFrom: string
  dkim: { domain: string; selector: string; result: Result }[]
  spf: { domain: string; scope: string; result: Result }[]
}

export interface Report {
  org: string
  email: string
  id: string
  begin: number
  end: number
  domain: string
  policy: { p: string; sp: string; pct: number; adkim: 'r' | 's'; aspf: 'r' | 's' }
  rows: Row[]
}

export interface Issue { line: number; level: 'error' | 'warn'; msg: string }

const RESULTS = new Set(['pass', 'fail', 'none', 'neutral', 'softfail', 'temperror', 'permerror', 'policy', 'hardfail'])
const res = (s: string): Result => { const v = s.toLowerCase(); return (v === 'hardfail' ? 'fail' : RESULTS.has(v) ? v : 'none') as Result }

export function parseAggregate(xml: string): { report: Report | null; issues: Issue[] } {
  const issues: Issue[] = []
  let root: XNode
  try { root = parseXml(xml) } catch (e) {
    return { report: null, issues: [{ line: e instanceof XmlError ? e.line : 1, level: 'error', msg: `Not well-formed XML: ${(e as Error).message}` }] }
  }
  const fb = child(root, 'feedback')
  if (!fb) return { report: null, issues: [{ line: root.children[0]?.line ?? 1, level: 'error', msg: 'No <feedback> element. This does not look like a DMARC aggregate (RUA) report.' }] }
  const meta = child(fb, 'report_metadata')
  const pol = child(fb, 'policy_published')
  if (!meta) issues.push({ line: fb.line, level: 'warn', msg: 'Missing <report_metadata>.' })
  if (!pol) issues.push({ line: fb.line, level: 'error', msg: 'Missing <policy_published>; the report does not say which domain it covers.' })
  const begin = Number(txt(meta, 'date_range', 'begin')) * 1000
  const end = Number(txt(meta, 'date_range', 'end')) * 1000
  if (!Number.isFinite(begin) || !begin) issues.push({ line: child(meta, 'date_range')?.line ?? meta?.line ?? fb.line, level: 'error', msg: 'Missing or invalid <date_range><begin>.' })
  const domain = normDomain(txt(pol, 'domain'))
  if (pol && !domain) issues.push({ line: pol.line, level: 'error', msg: 'Missing <policy_published><domain>.' })
  const pctS = txt(pol, 'pct')
  const al = (s: string) => (s.toLowerCase() === 's' ? 's' : 'r') as 'r' | 's'
  const report: Report = {
    org: txt(meta, 'org_name') || 'Unknown reporter',
    email: txt(meta, 'email'),
    id: txt(meta, 'report_id'),
    begin, end: Number.isFinite(end) && end ? end : begin,
    domain,
    policy: { p: txt(pol, 'p') || 'none', sp: txt(pol, 'sp') || txt(pol, 'p') || 'none', pct: pctS ? Number(pctS) : 100, adkim: al(txt(pol, 'adkim')), aspf: al(txt(pol, 'aspf')) },
    rows: [],
  }
  if (!report.id) issues.push({ line: meta?.line ?? fb.line, level: 'warn', msg: 'Missing <report_id>; duplicates of this report cannot be detected.' })
  const recs = kids(fb, 'record')
  if (!recs.length) issues.push({ line: fb.line, level: 'warn', msg: 'Report has no <record> rows (no mail seen in this period).' })
  for (const r of recs) {
    const row = child(r, 'row')
    const ip = txt(row, 'source_ip')
    const count = Number(txt(row, 'count'))
    if (!isIP(ip)) { issues.push({ line: child(row, 'source_ip')?.line ?? r.line, level: 'error', msg: `Invalid source IP "${ip}"; row skipped.` }); continue }
    if (!Number.isInteger(count) || count < 0) { issues.push({ line: child(row, 'count')?.line ?? r.line, level: 'error', msg: `Invalid message count "${txt(row, 'count')}"; row skipped.` }); continue }
    const pe = child(row, 'policy_evaluated')
    const ids = child(r, 'identifiers')
    const auth = child(r, 'auth_results')
    const headerFrom = normDomain(txt(ids, 'header_from')) || domain
    if (!txt(ids, 'header_from')) issues.push({ line: r.line, level: 'warn', msg: `Row for ${ip} has no <header_from>; assumed ${domain}.` })
    const disp = txt(pe, 'disposition').toLowerCase()
    report.rows.push({
      ip, count,
      disposition: disp === 'reject' ? 'reject' : disp === 'quarantine' ? 'quarantine' : 'none',
      evalDkim: txt(pe, 'dkim').toLowerCase() === 'pass' ? 'pass' : 'fail',
      evalSpf: txt(pe, 'spf').toLowerCase() === 'pass' ? 'pass' : 'fail',
      reasons: kids(pe, 'reason').map(x => txt(x, 'type').toLowerCase()).filter(Boolean),
      headerFrom,
      envelopeFrom: normDomain(txt(ids, 'envelope_from')),
      dkim: kids(auth, 'dkim').map(d => ({ domain: normDomain(txt(d, 'domain')), selector: txt(d, 'selector'), result: res(txt(d, 'result')) })),
      spf: kids(auth, 'spf').map(s => ({ domain: normDomain(txt(s, 'domain')), scope: txt(s, 'scope') || 'mfrom', result: res(txt(s, 'result')) })),
    })
  }
  if (!domain || !begin) return { report: null, issues }
  return { report, issues }
}

/** Stable key for de-duplicating reports that arrive twice (same reporter + id, or same reporter + range + domain). */
export const reportKey = (r: Report) => `${r.org}|${r.id || `${r.begin}-${r.end}`}|${r.domain}`
