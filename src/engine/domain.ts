// Domain and IP helpers: organizational domain, DMARC alignment, CIDR matching.

// Short list of multi-label public suffixes. A full Public Suffix List is ~200 KB; this covers the common
// business registrations. Anything else falls back to "last two labels", which is right for .com/.org/.io etc.
const MULTI = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'org.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'com.br', 'net.br', 'org.br', 'com.mx', 'com.ar', 'com.co',
  'co.za', 'org.za', 'com.sg', 'com.hk', 'com.tw', 'com.cn', 'net.cn', 'org.cn', 'co.kr', 'or.kr', 'com.tr', 'co.il', 'com.my', 'com.ph', 'com.pk', 'com.ng', 'co.id', 'ac.in'])

export const normDomain = (d: string) => d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^mailto:/, '').replace(/^.*@/, '').replace(/[/?#].*$/, '').replace(/\.$/, '')

export function orgDomain(d: string): string {
  const parts = normDomain(d).split('.').filter(Boolean)
  if (parts.length <= 2) return parts.join('.')
  const last2 = parts.slice(-2).join('.')
  return MULTI.has(last2) ? parts.slice(-3).join('.') : last2
}

export const isDomain = (d: string) => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]$/i.test(normDomain(d))

/** DMARC identifier alignment (RFC 7489 3.1). */
export function aligned(authDomain: string, fromDomain: string, mode: 'r' | 's' = 'r') {
  const a = normDomain(authDomain), f = normDomain(fromDomain)
  if (!a || !f) return false
  return mode === 's' ? a === f : orgDomain(a) === orgDomain(f)
}

// ---------- IP ----------

export function parseIPv4(s: string): number | null {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return null
  const o = m.slice(1).map(Number)
  if (o.some(x => x > 255)) return null
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]
}

export function parseIPv6(s: string): bigint | null {
  let str = s.trim().toLowerCase()
  if (!str.includes(':')) return null
  const v4 = str.match(/(\d+\.\d+\.\d+\.\d+)$/)
  if (v4) {
    const n = parseIPv4(v4[1])
    if (n === null) return null
    str = str.slice(0, -v4[1].length) + (n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16)
  }
  const halves = str.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const fill = 8 - head.length - tail.length
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail]
  let v = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    v = (v << 16n) + BigInt(parseInt(g, 16))
  }
  return v
}

export const isIP = (s: string) => parseIPv4(s) !== null || parseIPv6(s) !== null

export function inCidr(ip: string, cidr: string): boolean {
  const [net, bitsS] = cidr.split('/')
  const v4 = parseIPv4(ip), n4 = parseIPv4(net)
  if (v4 !== null && n4 !== null) {
    const bits = bitsS === undefined ? 32 : +bitsS
    if (bits === 0) return true
    const mask = (~0 << (32 - bits)) >>> 0
    return ((v4 & mask) >>> 0) === ((n4 & mask) >>> 0)
  }
  const v6 = parseIPv6(ip), n6 = parseIPv6(net)
  if (v6 !== null && n6 !== null) {
    const bits = BigInt(bitsS === undefined ? 128 : +bitsS)
    const shift = 128n - bits
    return v6 >> shift === n6 >> shift
  }
  return false
}

/** in-addr.arpa / ip6.arpa name for a PTR lookup. */
export function ptrName(ip: string): string | null {
  const v4 = parseIPv4(ip)
  if (v4 !== null) return ip.trim().split('.').reverse().join('.') + '.in-addr.arpa'
  const v6 = parseIPv6(ip)
  if (v6 === null) return null
  return v6.toString(16).padStart(32, '0').split('').reverse().join('.') + '.ip6.arpa'
}

/** The /24 (IPv4) or /48 (IPv6) a source IP sits in, used to label unknown senders. */
export function netOf(ip: string): string {
  const v4 = parseIPv4(ip)
  if (v4 !== null) return ip.split('.').slice(0, 3).join('.') + '.0/24'
  const v6 = parseIPv6(ip)
  if (v6 === null) return ip
  const g = v6.toString(16).padStart(32, '0').match(/.{4}/g)!.slice(0, 3).map(x => x.replace(/^0+(?=.)/, ''))
  return g.join(':') + '::/48'
}
