// DNS-over-HTTPS client (Cloudflare JSON API, Google as fallback). Both send Access-Control-Allow-Origin: *,
// so this runs straight from the browser. The engine takes a Resolver so tests can use a fake zone.

export const TYPES = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28, DS: 43, DNSKEY: 48 } as const
export type RRType = keyof typeof TYPES

export interface DnsAnswer {
  /** 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN */
  status: number
  answers: { name: string; type: number; data: string; ttl: number }[]
  /** DNSSEC validated by the resolver */
  ad: boolean
  via?: string
}
export type Resolver = (name: string, type: RRType) => Promise<DnsAnswer>

const PROVIDERS = [
  { name: 'Cloudflare', url: (n: string, t: string) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}` },
  { name: 'Google', url: (n: string, t: string) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}` },
]

interface RawAnswer { Status: number; AD?: boolean; Answer?: { name: string; type: number; data: string; TTL: number }[] }

const RCODE: Record<number, string> = { 1: 'FORMERR', 2: 'SERVFAIL', 4: 'NOTIMP', 5: 'REFUSED' }

/**
 * Only NOERROR (0, possibly with no answers) and NXDOMAIN (3) are answers about the name. Any other RCODE and any
 * body that is not a DNS JSON answer is a failure to look the name up (RFC 7208 temperror), never an empty answer.
 */
function parseAnswer(j: unknown, prov: string, name: string): RawAnswer {
  const a = j as RawAnswer | null
  if (!a || typeof a !== 'object' || !Number.isInteger(a.Status)) throw new Error(`${prov}: unreadable DNS answer for ${name}`)
  if (a.Status !== 0 && a.Status !== 3) throw new Error(`${prov}: ${RCODE[a.Status] ?? `RCODE ${a.Status}`} for ${name}`)
  if (a.Answer !== undefined && (!Array.isArray(a.Answer) || a.Answer.some(x => !x || typeof x !== 'object' || typeof x.data !== 'string' || !Number.isInteger(x.type))))
    throw new Error(`${prov}: unreadable DNS answer for ${name}`)
  return a
}

/** A caching DoH resolver. Falls back to the next provider on network error, timeout, HTTP error, bad body or SERVFAIL; throws when every provider failed. */
export function dohResolver(fetchFn: typeof fetch = fetch, timeoutMs = 6000): Resolver {
  const cache = new Map<string, Promise<DnsAnswer>>()
  return (name, type) => {
    const key = `${name.toLowerCase()}|${type}`
    let p = cache.get(key)
    if (!p) {
      p = (async () => {
        let last: unknown = null
        for (const prov of PROVIDERS) {
          const ctrl = new AbortController()
          const t = setTimeout(() => ctrl.abort(), timeoutMs)
          try {
            const r = await fetchFn(prov.url(name, type), { headers: { accept: 'application/dns-json' }, signal: ctrl.signal })
            if (!r.ok) throw new Error(`${prov.name} DoH returned HTTP ${r.status}`)
            const j = parseAnswer(await r.json().catch(() => { throw new Error(`${prov.name}: unreadable DNS answer for ${name}`) }), prov.name, name)
            return { status: j.Status, ad: !!j.AD, via: prov.name, answers: (j.Answer ?? []).map(a => ({ name: a.name, type: a.type, data: a.data, ttl: a.TTL })) }
          } catch (e) { last = ctrl.signal.aborted ? new Error(`${prov.name}: no answer for ${name} within ${timeoutMs / 1000}s`) : e } finally { clearTimeout(t) }
        }
        cache.delete(key)
        throw last instanceof Error ? last : new Error('DNS lookup failed')
      })()
      cache.set(key, p)
    }
    return p
  }
}

/** Joins the character-strings of one TXT record. Cloudflare returns them quoted ("a" "b"), Google unquoted. */
export function txtData(data: string): string {
  const d = data.trim()
  if (!d.startsWith('"')) return d
  const parts = [...d.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1].replace(/\\(\d{3})/g, (_, n) => String.fromCharCode(+n)).replace(/\\(.)/g, '$1'))
  return parts.join('')
}

export const txtOf = (a: DnsAnswer) => a.answers.filter(x => x.type === TYPES.TXT).map(x => txtData(x.data))
export const ofType = (a: DnsAnswer, t: RRType) => a.answers.filter(x => x.type === TYPES[t]).map(x => x.data.replace(/\.$/, ''))

/** In-memory zone for tests and the offline sample: { "example.com": { TXT: ["v=spf1 ..."], MX: ["10 mx.example.com."] } } */
export function fakeResolver(zone: Record<string, Partial<Record<RRType, string[]>>>, opts: { ad?: string[] } = {}): Resolver & { calls: string[] } {
  const calls: string[] = []
  const fn = async (name: string, type: RRType): Promise<DnsAnswer> => {
    calls.push(`${name} ${type}`)
    const n = name.toLowerCase().replace(/\.$/, '')
    const z = zone[n]
    const ad = opts.ad?.includes(n) ?? false
    if (!z) return { status: 3, answers: [], ad }
    return { status: 0, ad, answers: (z[type] ?? []).map(data => ({ name: n, type: TYPES[type], data: type === 'TXT' ? `"${data}"` : data, ttl: 300 })) }
  }
  return Object.assign(fn, { calls })
}
