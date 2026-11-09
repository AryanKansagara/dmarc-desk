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

/** A caching DoH resolver. Falls back to the next provider on network error or SERVFAIL. */
export function dohResolver(fetchFn: typeof fetch = fetch, timeoutMs = 6000): Resolver {
  const cache = new Map<string, Promise<DnsAnswer>>()
  return (name, type) => {
    const key = `${name.toLowerCase()}|${type}`
    let p = cache.get(key)
    if (!p) {
      p = (async () => {
        let last: unknown = null
        for (const prov of PROVIDERS) {
          try {
            const ctrl = new AbortController()
            const t = setTimeout(() => ctrl.abort(), timeoutMs)
            const r = await fetchFn(prov.url(name, type), { headers: { accept: 'application/dns-json' }, signal: ctrl.signal })
            clearTimeout(t)
            if (!r.ok) throw new Error(`${prov.name} DoH returned HTTP ${r.status}`)
            const j = await r.json() as RawAnswer
            if (j.Status === 2) { last = new Error(`${prov.name}: SERVFAIL for ${name}`); continue }
            return { status: j.Status, ad: !!j.AD, via: prov.name, answers: (j.Answer ?? []).map(a => ({ name: a.name, type: a.type, data: a.data, ttl: a.TTL })) }
          } catch (e) { last = e }
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
