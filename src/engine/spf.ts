// SPF (RFC 7208): recursive expansion with the 10 DNS-lookup and 2 void-lookup limits, and a builder that
// flattens the heaviest includes into ip4/ip6 when a record would go over the limit.
import { ofType, txtOf, type Resolver } from './dns.ts'
import { isIP } from './domain.ts'

export interface Term { qualifier: '+' | '-' | '~' | '?'; kind: string; value: string; raw: string }
export interface SpfIssue { level: 'error' | 'warn' | 'info'; msg: string }
export interface SpfNode {
  domain: string
  record: string | null
  terms: Term[]
  /** DNS lookups this node itself causes (include, a, mx, ptr, exists, redirect) */
  lookups: number
  /** Lookups including all children */
  totalLookups: number
  children: SpfNode[]
  ip4: string[]
  ip6: string[]
  error?: string
}
export interface SpfResult {
  domain: string
  record: string | null
  tree: SpfNode | null
  lookups: number
  voidLookups: number
  all: string | null
  ip4: string[]
  ip6: string[]
  issues: SpfIssue[]
}

const LOOKUP_KINDS = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect'])

export function parseSpf(record: string): Term[] {
  return record.trim().split(/\s+/).slice(1).filter(Boolean).map(raw => {
    const q = '+-~?'.includes(raw[0]) ? raw[0] as Term['qualifier'] : '+'
    const body = q === raw[0] && '+-~?'.includes(raw[0]) ? raw.slice(1) : raw
    const m = body.match(/^([a-z0-9]+)(?:[:=](.*))?$/i)
    let kind = (m?.[1] ?? body).toLowerCase()
    let value = m?.[2] ?? ''
    if (!m && /^(a|mx)\//i.test(body)) { kind = body.split('/')[0].toLowerCase(); value = '/' + body.split('/').slice(1).join('/') }
    if (m && /^(a|mx)$/.test(kind) && value === '' && body.includes('/')) value = body.slice(kind.length)
    return { qualifier: q, kind, value, raw }
  })
}

export const isSpf = (txt: string) => /^v=spf1(\s|$)/i.test(txt.trim())

export async function expandSpf(domain: string, resolve: Resolver): Promise<SpfResult> {
  const issues: SpfIssue[] = []
  let lookups = 0, voids = 0
  const seen = new Set<string>()

  const fetchRecord = async (d: string): Promise<{ record: string | null; void: boolean; error?: string }> => {
    try {
      const a = await resolve(d, 'TXT')
      const recs = txtOf(a).filter(isSpf)
      if (recs.length > 1) issues.push({ level: 'error', msg: `${d} publishes ${recs.length} SPF records. Receivers return permerror; merge them into one.` })
      return { record: recs[0] ?? null, void: a.status === 3 || !a.answers.length }
    } catch (e) { return { record: null, void: false, error: (e as Error).message } }
  }

  const addrs = async (host: string) => {
    const [a, aaaa] = await Promise.all([resolve(host, 'A').catch(() => null), resolve(host, 'AAAA').catch(() => null)])
    return { ip4: a ? ofType(a, 'A') : [], ip6: aaaa ? ofType(aaaa, 'AAAA') : [], void: (!a || !ofType(a, 'A').length) && (!aaaa || !ofType(aaaa, 'AAAA').length) }
  }

  const walk = async (d: string, record: string | null, depth: number): Promise<SpfNode> => {
    const node: SpfNode = { domain: d, record, terms: record ? parseSpf(record) : [], lookups: 0, totalLookups: 0, children: [], ip4: [], ip6: [] }
    if (!record) return node
    if (record.length > 255 && !record.includes('"')) issues.push({ level: 'info', msg: `${d}: SPF record is ${record.length} characters; it must be split into 255-character strings in one TXT record.` })
    for (const t of node.terms) {
      if (t.value.includes('%{')) { issues.push({ level: 'info', msg: `${d}: "${t.raw}" uses SPF macros; resolved per message, not expanded here.` }) }
      if (LOOKUP_KINDS.has(t.kind)) { node.lookups++; lookups++ }
      const target = (t.value.split('/')[0] || d).toLowerCase()
      if (t.kind === 'ip4' || t.kind === 'ip6') {
        if (!isIP(t.value.split('/')[0])) issues.push({ level: 'error', msg: `${d}: "${t.raw}" is not a valid address.` })
        else if (t.qualifier === '+') (t.kind === 'ip4' ? node.ip4 : node.ip6).push(t.value)
      } else if (t.kind === 'include' || t.kind === 'redirect') {
        if (t.kind === 'redirect' && node.terms.some(x => x.kind === 'all')) continue // redirect is ignored when "all" is present
        if (seen.has(target) || depth > 10) { issues.push({ level: 'error', msg: `${d}: ${t.kind} loop through ${target}.` }); continue }
        seen.add(target)
        const r = await fetchRecord(target)
        if (r.error) issues.push({ level: 'warn', msg: `${target}: lookup failed (${r.error}).` })
        if (!r.record) {
          if (r.void) voids++
          issues.push({ level: t.kind === 'redirect' ? 'error' : 'error', msg: `${d}: ${t.kind} ${target} has no SPF record${r.void ? ' (void lookup)' : ''}. Receivers return permerror.` })
          node.children.push({ domain: target, record: null, terms: [], lookups: 0, totalLookups: 0, children: [], ip4: [], ip6: [], error: 'No SPF record' })
          continue
        }
        node.children.push(await walk(target, r.record, depth + 1))
      } else if (t.kind === 'a' && t.qualifier === '+') {
        const r = await addrs(target)
        if (r.void) voids++
        node.ip4.push(...r.ip4); node.ip6.push(...r.ip6)
      } else if (t.kind === 'mx' && t.qualifier === '+') {
        const mx = await resolve(target, 'MX').catch(() => null)
        const hosts = mx ? ofType(mx, 'MX').map(x => x.split(/\s+/)[1]?.replace(/\.$/, '')).filter(Boolean) : []
        if (!hosts.length) voids++
        if (hosts.length > 10) issues.push({ level: 'error', msg: `${d}: mx mechanism resolves to ${hosts.length} hosts; the limit is 10.` })
        for (const h of hosts.slice(0, 10)) { const r = await addrs(h); node.ip4.push(...r.ip4); node.ip6.push(...r.ip6) }
      } else if (t.kind === 'ptr') {
        issues.push({ level: 'warn', msg: `${d}: "ptr" is deprecated (RFC 7208 5.5) and many receivers ignore it. Replace it with ip4/ip6 or include.` })
      } else if (!['all', 'exists', 'exp'].includes(t.kind) && !t.raw.includes('=')) {
        issues.push({ level: 'error', msg: `${d}: unknown mechanism "${t.raw}".` })
      }
    }
    node.totalLookups = node.lookups + node.children.reduce((s, c) => s + c.totalLookups, 0)
    return node
  }

  const top = await fetchRecord(domain)
  if (top.error) issues.push({ level: 'error', msg: `Lookup failed: ${top.error}` })
  if (!top.record) {
    if (!top.error) issues.push({ level: 'error', msg: 'No SPF record. Receivers cannot tell which servers may send for this domain.' })
    return { domain, record: null, tree: null, lookups: 0, voidLookups: 0, all: null, ip4: [], ip6: [], issues }
  }
  seen.add(domain.toLowerCase())
  const tree = await walk(domain, top.record, 0)
  const allTerm = tree.terms.find(t => t.kind === 'all')
  const all = allTerm ? `${allTerm.qualifier}all` : null
  if (lookups > 10) issues.push({ level: 'error', msg: `${lookups} DNS lookups; the limit is 10. Receivers return permerror and SPF fails for all your mail. Flatten or remove includes.` })
  else if (lookups >= 8) issues.push({ level: 'warn', msg: `${lookups} of 10 DNS lookups used. One more vendor include will break SPF.` })
  if (voids > 2) issues.push({ level: 'error', msg: `${voids} void lookups (names that do not exist or have no records); the limit is 2.` })
  if (all === '+all') issues.push({ level: 'error', msg: '+all lets any server on the internet pass SPF for your domain. Use ~all or -all.' })
  else if (all === '?all') issues.push({ level: 'warn', msg: '?all (neutral) gives receivers no signal. Use ~all, or -all once DMARC is enforcing.' })
  else if (!all && !tree.terms.some(t => t.kind === 'redirect')) issues.push({ level: 'warn', msg: 'No "all" mechanism; unlisted servers get a neutral result. End the record with ~all or -all.' })
  const dupes = tree.terms.filter((t, i) => tree.terms.findIndex(x => x.raw.toLowerCase() === t.raw.toLowerCase()) !== i)
  if (dupes.length) issues.push({ level: 'warn', msg: `Duplicate terms: ${[...new Set(dupes.map(d => d.raw))].join(', ')}. Each duplicate include still costs a lookup.` })
  const ip4 = collect(tree, 'ip4'), ip6 = collect(tree, 'ip6')
  return { domain, record: top.record, tree, lookups, voidLookups: voids, all, ip4, ip6, issues }
}

const collect = (n: SpfNode, k: 'ip4' | 'ip6'): string[] => [...new Set([...n[k], ...n.children.flatMap(c => collect(c, k))])]

// ---------- Builder / flattener ----------

export interface BuildInput {
  domain: string
  /** Includes to keep, e.g. ["_spf.google.com", "sendgrid.net"] */
  includes: string[]
  ip4?: string[]
  ip6?: string[]
  /** Keep "mx" / "a" mechanisms (each costs a lookup) */
  mx?: boolean
  a?: boolean
  all: '-all' | '~all'
  /** Expanded include trees (from expandSpf on each include) so the builder can count and flatten */
  expanded: Record<string, SpfNode | undefined>
  limit?: number
}

export interface BuildOutput {
  records: { host: string; value: string }[]
  lookups: number
  flattened: string[]
  warnings: string[]
}

const MAX_TXT = 450 // keep each record well under the 512-byte UDP response limit

export function buildSpf(inp: BuildInput): BuildOutput {
  const limit = inp.limit ?? 10
  const warnings: string[] = []
  const incs = [...new Set(inp.includes.map(s => s.trim().toLowerCase()).filter(Boolean))]
  const cost = (i: string) => 1 + (inp.expanded[i]?.totalLookups ?? 0)
  let kept = [...incs]
  const flattened: string[] = []
  const base = (inp.mx ? 1 : 0) + (inp.a ? 1 : 0)
  const total = () => base + kept.reduce((s, i) => s + cost(i), 0)
  // Flatten the most expensive includes first until the record fits, as long as we know their addresses.
  while (total() > limit) {
    const cand = kept.filter(i => inp.expanded[i]).sort((x, y) => cost(y) - cost(x))[0]
    if (!cand) { warnings.push(`Still ${total()} lookups and the remaining includes could not be expanded. Remove a sender or move it to a subdomain.`); break }
    kept = kept.filter(i => i !== cand)
    flattened.push(cand)
  }
  const ip4 = [...new Set([...(inp.ip4 ?? []), ...flattened.flatMap(f => collect(inp.expanded[f]!, 'ip4'))])]
  const ip6 = [...new Set([...(inp.ip6 ?? []), ...flattened.flatMap(f => collect(inp.expanded[f]!, 'ip6'))])]
  const addrTerms = [...ip4.map(i => `ip4:${i}`), ...ip6.map(i => `ip6:${i}`)]
  const head = ['v=spf1', ...(inp.mx ? ['mx'] : []), ...(inp.a ? ['a'] : [])]
  const tail = [...kept.map(i => `include:${i}`), inp.all]
  const inline = [...head, ...addrTerms, ...tail].join(' ')
  const records: { host: string; value: string }[] = []
  let lookups = total()
  if (inline.length <= MAX_TXT) records.push({ host: inp.domain, value: inline })
  else {
    // Too long for one record: pack addresses into _spf1, _spf2 ... subrecords, each costing one include.
    const chunks: string[][] = [[]]
    for (const t of addrTerms) {
      const cur = chunks.at(-1)!
      if (['v=spf1', ...cur, t, '~all'].join(' ').length > MAX_TXT) chunks.push([t]); else cur.push(t)
    }
    chunks.forEach((c, i) => records.push({ host: `_spf${i + 1}.${inp.domain}`, value: ['v=spf1', ...c, '~all'].join(' ') }))
    lookups += chunks.length
    records.unshift({ host: inp.domain, value: [...head, ...chunks.map((_, i) => `include:_spf${i + 1}.${inp.domain}`), ...tail].join(' ') })
    if (lookups > limit) warnings.push(`The split record needs ${lookups} lookups. Remove a sender or send it from a subdomain.`)
  }
  if (flattened.length) warnings.push(`Flattened ${flattened.join(', ')} into IP addresses. Providers change their ranges without notice: re-run this check monthly, or better, move those senders to custom DKIM and their own Return-Path so they no longer need your root SPF.`)
  return { records, lookups, flattened, warnings }
}

/** Splits a TXT value into quoted 255-character strings for zone files. */
export const txtQuote = (v: string) => (v.match(/.{1,255}/g) ?? ['']).map(s => `"${s.replace(/(["\\])/g, '\\$1')}"`).join(' ')
