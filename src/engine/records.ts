// Copy-ready DNS records and a BIND zone snippet (Cloudflare: DNS > Records > Import and Export accepts it).
import { txtQuote } from './spf.ts'

export interface DnsRecord { host: string; type: 'TXT' | 'CNAME' | 'MX'; value: string; note: string }

export function mtaStsPolicy(mx: string[], mode: 'testing' | 'enforce' = 'testing', maxAge = 604800): string {
  return ['version: STSv1', `mode: ${mode}`, ...mx.map(m => `mx: ${m.replace(/\.$/, '')}`), `max_age: ${maxAge}`].join('\n') + '\n'
}

export const stsId = (t: number) => new Date(t).toISOString().replace(/[-:T]/g, '').slice(0, 12)

export function zoneSnippet(records: DnsRecord[], ttl = 3600): string {
  return records.map(r => {
    const name = r.host.endsWith('.') ? r.host : r.host + '.'
    const value = r.type === 'TXT' ? txtQuote(r.value) : r.value.endsWith('.') || r.type === 'MX' ? r.value : r.value + '.'
    return `; ${r.note}\n${name}\t${ttl}\tIN\t${r.type}\t${value}`
  }).join('\n')
}

/** Cloudflare Worker that serves the MTA-STS policy at https://mta-sts.<domain>/.well-known/mta-sts.txt */
export const stsWorker = (policy: string) => `export default {
  fetch(request) {
    const url = new URL(request.url)
    if (url.pathname !== '/.well-known/mta-sts.txt') return new Response('Not found', { status: 404 })
    return new Response(${JSON.stringify(policy)}, { headers: { 'content-type': 'text/plain; charset=utf-8' } })
  },
}`
