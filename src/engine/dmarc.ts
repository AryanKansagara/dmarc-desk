// DMARC record parsing, validation and generation (RFC 7489, plus the DMARCbis np/t tags).
import { normDomain, orgDomain } from './domain.ts'

export interface DmarcIssue { level: 'error' | 'warn' | 'info'; msg: string }
export interface Dmarc {
  tags: Record<string, string>
  p: 'none' | 'quarantine' | 'reject' | null
  sp: string | null
  pct: number
  rua: string[]
  ruf: string[]
  adkim: 'r' | 's'
  aspf: 'r' | 's'
  issues: DmarcIssue[]
}

const KNOWN = new Set(['v', 'p', 'sp', 'np', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri', 't', 'psd'])
const POLICIES = ['none', 'quarantine', 'reject']

export const isDmarc = (s: string) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(s.trim())

export function parseDmarc(record: string): Dmarc {
  const issues: DmarcIssue[] = []
  const tags: Record<string, string> = {}
  const parts = record.split(';').map(s => s.trim()).filter(Boolean)
  parts.forEach((p, i) => {
    const eq = p.indexOf('=')
    if (eq < 0) { issues.push({ level: 'error', msg: `"${p}" is not a tag=value pair.` }); return }
    const k = p.slice(0, eq).trim().toLowerCase(), v = p.slice(eq + 1).trim()
    if (i === 0 && (k !== 'v' || v !== 'DMARC1')) issues.push({ level: 'error', msg: 'The record must start with v=DMARC1 (case-sensitive).' })
    if (k in tags) issues.push({ level: 'warn', msg: `Tag ${k} appears twice; the first value is used.` })
    else tags[k] = v
    if (!KNOWN.has(k)) issues.push({ level: 'warn', msg: `Unknown tag "${k}" is ignored by receivers.` })
  })
  const p = (tags.p ?? '').toLowerCase()
  if (!tags.p) issues.push({ level: 'error', msg: 'Missing required p= tag. Without it receivers treat the record as invalid (or as p=none if rua is valid).' })
  else if (!POLICIES.includes(p)) issues.push({ level: 'error', msg: `p=${tags.p} is not valid; use none, quarantine or reject.` })
  if (tags.sp && !POLICIES.includes(tags.sp.toLowerCase())) issues.push({ level: 'error', msg: `sp=${tags.sp} is not valid.` })
  const pct = tags.pct === undefined ? 100 : Number(tags.pct)
  if (tags.pct !== undefined && (!Number.isInteger(pct) || pct < 0 || pct > 100)) issues.push({ level: 'error', msg: `pct=${tags.pct} must be an integer from 0 to 100.` })
  for (const k of ['adkim', 'aspf']) if (tags[k] && !/^[rs]$/i.test(tags[k])) issues.push({ level: 'error', msg: `${k}=${tags[k]} must be r or s.` })
  const uris = (k: string) => (tags[k] ?? '').split(',').map(s => s.trim()).filter(Boolean)
  const rua = uris('rua'), ruf = uris('ruf')
  for (const u of [...rua, ...ruf]) if (!/^mailto:[^@\s]+@[^@\s!]+(![0-9]+[kmgt]?)?$/i.test(u)) issues.push({ level: 'error', msg: `"${u}" is not a valid mailto: URI.` })
  if (!rua.length) issues.push({ level: 'warn', msg: 'No rua= address, so you receive no aggregate reports and cannot see who sends as you.' })
  if (p === 'none') issues.push({ level: 'info', msg: 'p=none only monitors. Spoofed mail is still delivered, and Gmail/Yahoo bulk-sender rules only require that a record exists.' })
  if (p !== 'none' && pct < 100) issues.push({ level: 'info', msg: `pct=${pct}: the policy applies to ${pct}% of failing mail. Fine during rollout; finish at 100.` })
  if (ruf.length) issues.push({ level: 'info', msg: 'ruf= (forensic reports) is ignored by Gmail, Outlook.com and most large receivers.' })
  return {
    tags, p: POLICIES.includes(p) ? p as Dmarc['p'] : null, sp: tags.sp?.toLowerCase() ?? null, pct: Number.isFinite(pct) ? pct : 100, rua, ruf,
    adkim: tags.adkim?.toLowerCase() === 's' ? 's' : 'r', aspf: tags.aspf?.toLowerCase() === 's' ? 's' : 'r', issues,
  }
}

/** rua/ruf addresses on another organizational domain must authorise reports (RFC 7489 7.1). */
export function externalDestinations(domain: string, uris: string[]) {
  return uris.map(u => {
    const host = normDomain(u.replace(/^mailto:/i, '').replace(/!.*$/, '').split('@')[1] ?? '')
    const external = !!host && orgDomain(host) !== orgDomain(domain)
    return { uri: u, host, external, checkName: external ? `${normDomain(domain)}._report._dmarc.${host}` : null }
  })
}

export interface DmarcGen { p: 'none' | 'quarantine' | 'reject'; sp?: 'none' | 'quarantine' | 'reject'; pct?: number; rua: string[]; ruf?: string[]; adkim?: 'r' | 's'; aspf?: 'r' | 's'; fo?: string }

export function generateDmarc(g: DmarcGen): string {
  const parts = [`v=DMARC1`, `p=${g.p}`]
  if (g.sp && g.sp !== g.p) parts.push(`sp=${g.sp}`)
  if (g.pct !== undefined && g.pct < 100) parts.push(`pct=${g.pct}`)
  const mail = (a: string) => a.startsWith('mailto:') ? a : `mailto:${a}`
  if (g.rua.length) parts.push(`rua=${g.rua.map(mail).join(',')}`)
  if (g.ruf?.length) parts.push(`ruf=${g.ruf.map(mail).join(',')}`)
  if (g.adkim === 's') parts.push('adkim=s')
  if (g.aspf === 's') parts.push('aspf=s')
  if (g.fo) parts.push(`fo=${g.fo}`)
  return parts.join('; ')
}
