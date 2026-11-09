// Synthetic aggregate reports and a synthetic DNS zone for two fictional domains.
// All data is generated. Real ESP netblocks are used for ESP traffic (so identification works as it would on
// real reports); invented sources use the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
import type { RRType } from './dns.ts'

export interface SampleDef { id: string; name: string; domain: string; blurb: string; policy: { p: string; pct: number } }

export const SAMPLES: SampleDef[] = [
  { id: 'northwind', name: 'Northwind Coffee', domain: 'example.com', policy: { p: 'none', pct: 100 },
    blurb: 'p=none, Google Workspace, an unaligned SendGrid newsletter (fixed mid-October), an alumni forwarder, a spoofing source and an SPF record over the 10-lookup limit.' },
  { id: 'fieldstone', name: 'Fieldstone Outfitters', domain: 'example.org', policy: { p: 'quarantine', pct: 10 },
    blurb: 'Mid-rollout at quarantine 10%. Microsoft 365, Mailchimp and SES are aligned; Zendesk still signs as zendesk.com.' },
]

function rng(seed: number) {
  return () => { seed |= 0; seed = seed + 0x6d2b79f5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296 }
}

interface Src {
  ips: string[]
  perDay: (day: Date, r: () => number) => number
  dkim: (day: Date) => { d: string; s: string; r: string }[]
  spf: (day: Date) => { d: string; r: string }
  envelope?: (day: Date) => string
  reason?: string
  /** Split part of the volume into a variant (e.g. forwarded mail that lost DKIM) */
  variant?: { share: number; dkim: { d: string; s: string; r: string }[]; spf: { d: string; r: string }; reason?: string }
}

const REPORTERS = [
  { org: 'google.com', email: 'noreply-dmarc-support@google.com', share: 0.55 },
  { org: 'Enterprise Outlook', email: 'dmarcreport@microsoft.com', share: 0.3 },
  { org: 'Yahoo', email: 'dmarchelp@yahooinc.com', share: 0.15 },
]

const START = Date.UTC(2026, 8, 21) // Monday 21 Sep 2026
const DAYS = 42
const isTue = (d: Date) => d.getUTCDay() === 2
const after = (d: Date, iso: string) => d.getTime() >= Date.parse(iso)

function sources(id: string): { domain: string; p: string; pct: number; srcs: Src[] } {
  if (id === 'northwind') {
    const d = 'example.com'
    return {
      domain: d, p: 'none', pct: 100, srcs: [
        { ips: ['209.85.220.41', '209.85.220.69', '2607:f8b0:4864:20::a2f'], perDay: (day, r) => (day.getUTCDay() % 6 === 0 ? 70 : 380) + Math.round(r() * 60),
          dkim: () => [{ d, s: 'google', r: 'pass' }], spf: () => ({ d, r: 'pass' }) },
        { ips: ['167.89.12.34', '149.72.120.8'], perDay: (day, r) => (isTue(day) ? 1800 : 110) + Math.round(r() * 40),
          dkim: day => after(day, '2026-10-22') ? [{ d, s: 's1', r: 'pass' }, { d: 'sendgrid.net', s: 'smtpapi', r: 'pass' }] : [{ d: 'sendgrid.net', s: 'smtpapi', r: 'pass' }],
          spf: day => after(day, '2026-10-22') ? { d: 'em4821.example.com', r: 'pass' } : { d: 'sendgrid.net', r: 'pass' } },
        { ips: ['192.0.2.10'], perDay: (_d, r) => 30 + Math.round(r() * 15), dkim: () => [], spf: () => ({ d, r: 'pass' }) },
        { ips: ['198.51.100.23', '198.51.100.24'], perDay: (_d, r) => 18 + Math.round(r() * 10), reason: 'forwarded',
          dkim: () => [{ d, s: 'google', r: 'pass' }], spf: () => ({ d, r: 'fail' }),
          variant: { share: 0.3, dkim: [{ d, s: 'google', r: 'fail' }], spf: { d, r: 'softfail' }, reason: 'mailing_list' } },
        { ips: ['203.0.113.77', '203.0.113.140', '203.0.113.141'], perDay: (_d, r) => r() < 0.35 ? 300 + Math.round(r() * 500) : Math.round(r() * 40),
          dkim: () => [], spf: () => ({ d, r: 'fail' }) },
      ],
    }
  }
  const d = 'example.org'
  return {
    domain: d, p: 'quarantine', pct: 10, srcs: [
      { ips: ['40.107.22.51', '40.107.236.88', '52.100.165.12'], perDay: (day, r) => (day.getUTCDay() % 6 === 0 ? 40 : 260) + Math.round(r() * 50),
        dkim: () => [{ d, s: 'selector1', r: 'pass' }], spf: () => ({ d, r: 'pass' }) },
      { ips: ['198.2.180.61', '205.201.131.92'], perDay: (day, r) => (day.getUTCDay() === 4 ? 2400 : 0) + Math.round(r() * 20),
        dkim: () => [{ d, s: 'k2', r: 'pass' }, { d: 'mcsv.net', s: 'k1', r: 'pass' }], spf: () => ({ d: 'mail204.atl21.mcsv.net', r: 'pass' }) },
      { ips: ['54.240.11.31', '54.240.11.32'], perDay: (_d, r) => 150 + Math.round(r() * 60),
        dkim: () => [{ d, s: 'x3k2dmnpq7', r: 'pass' }, { d: 'amazonses.com', s: '6gbrjpgw', r: 'pass' }], spf: () => ({ d: 'bounce.example.org', r: 'pass' }) },
      { ips: ['192.161.147.1', '192.161.148.3'], perDay: (_d, r) => 90 + Math.round(r() * 30),
        dkim: () => [{ d: 'zendesk.com', s: 'zendesk1', r: 'pass' }], spf: () => ({ d: 'zendesk.com', r: 'pass' }) },
      { ips: ['203.0.113.9', '203.0.113.10'], perDay: (_d, r) => r() < 0.25 ? 120 + Math.round(r() * 300) : Math.round(r() * 15),
        dkim: () => [{ d: 'example-org.support', s: 'default', r: 'pass' }], spf: () => ({ d: 'example-org.support', r: 'pass' }) },
    ],
  }
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

/** One aggregate report per reporter per day, as RFC 7489 XML. */
export function sampleXml(id: string): { name: string; xml: string }[] {
  const { domain, p, pct, srcs } = sources(id)
  const r = rng(id.length * 7919 + 17)
  const out: { name: string; xml: string }[] = []
  for (let i = 0; i < DAYS; i++) {
    const begin = START + i * 86400000
    const day = new Date(begin)
    for (const rep of REPORTERS) {
      const recs: string[] = []
      for (const s of srcs) {
        const total = Math.round(s.perDay(day, r) * rep.share)
        if (!total) continue
        // spread over the source's IPs
        s.ips.forEach((ip, k) => {
          const n = k === s.ips.length - 1 ? total - Math.floor(total / s.ips.length) * (s.ips.length - 1) : Math.floor(total / s.ips.length)
          if (n <= 0) return
          const vn = s.variant ? Math.round(n * s.variant.share) : 0
          const parts: [number, { d: string; s: string; r: string }[], { d: string; r: string }, string | undefined][] = [[n - vn, s.dkim(day), s.spf(day), s.reason]]
          if (vn) parts.push([vn, s.variant!.dkim, s.variant!.spf, s.variant!.reason])
          for (const [cnt, dk, sp, reason] of parts) {
            if (cnt <= 0) continue
            const dkPass = dk.some(x => x.r === 'pass' && (x.d === domain || x.d.endsWith('.' + domain)))
            const spPass = sp.r === 'pass' && (sp.d === domain || sp.d.endsWith('.' + domain))
            const fails = !dkPass && !spPass
            const disp = fails && p !== 'none' && r() * 100 < pct ? p : 'none'
            recs.push(`  <record>
    <row>
      <source_ip>${ip}</source_ip>
      <count>${cnt}</count>
      <policy_evaluated>
        <disposition>${disp}</disposition>
        <dkim>${dkPass ? 'pass' : 'fail'}</dkim>
        <spf>${spPass ? 'pass' : 'fail'}</spf>${reason && rep.org === 'google.com' ? `
        <reason><type>${reason}</type></reason>` : ''}
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>${domain}</header_from>
      <envelope_from>${sp.d}</envelope_from>
    </identifiers>
    <auth_results>${dk.map(x => `
      <dkim><domain>${x.d}</domain><selector>${x.s}</selector><result>${x.r}</result></dkim>`).join('')}
      <spf><domain>${sp.d}</domain><scope>mfrom</scope><result>${sp.r}</result></spf>
    </auth_results>
  </record>`)
          }
        })
      }
      const rid = `${rep.org.replace(/\W/g, '').slice(0, 8)}-${id}-${i}`
      out.push({
        name: `${rep.org}!${domain}!${begin / 1000}!${begin / 1000 + 86399}.xml`,
        xml: `<?xml version="1.0" encoding="UTF-8" ?>
<!-- Synthetic DMARC aggregate report generated for the DMARC Desk sample. Not real mail data. -->
<feedback>
  <report_metadata>
    <org_name>${esc(rep.org)}</org_name>
    <email>${rep.email}</email>
    <report_id>${rid}</report_id>
    <date_range><begin>${begin / 1000}</begin><end>${begin / 1000 + 86399}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>${domain}</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>${p}</p>
    <sp>${p}</sp>
    <pct>${pct}</pct>
  </policy_published>
${recs.join('\n')}
</feedback>
`,
      })
    }
  }
  return out
}

/** Synthetic DNS for the sample domains, so their DNS tab shows the same story as their reports. */
export function sampleZone(id: string): Record<string, Partial<Record<RRType, string[]>>> {
  const vendor: Record<string, Partial<Record<RRType, string[]>>> = {
    '_spf.google.com': { TXT: ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all'] },
    '_netblocks.google.com': { TXT: ['v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ~all'] },
    '_netblocks2.google.com': { TXT: ['v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ~all'] },
    '_netblocks3.google.com': { TXT: ['v=spf1 ip4:172.217.0.0/19 ip4:172.217.32.0/20 ip4:108.177.96.0/19 ~all'] },
    'sendgrid.net': { TXT: ['v=spf1 ip4:167.89.0.0/17 ip4:208.117.48.0/20 ip4:50.31.32.0/19 ip4:198.37.144.0/20 ip4:149.72.0.0/16 ip4:168.245.0.0/17 ~all'] },
    'servers.mcsv.net': { TXT: ['v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 ?all'] },
    'mail.zendesk.com': { TXT: ['v=spf1 include:_spf1.zendesk.com ~all'] },
    '_spf1.zendesk.com': { TXT: ['v=spf1 ip4:192.161.144.0/20 ip4:216.198.0.0/18 ~all'] },
    'spf.protection.outlook.com': { TXT: ['v=spf1 include:spfa.protection.outlook.com ~all'] },
    'spfa.protection.outlook.com': { TXT: ['v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/14 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/48 ~all'] },
    '_spf.salesforce.com': { TXT: ['v=spf1 include:_spf1.salesforce.com include:_spf2.salesforce.com ~all'] },
    '_spf1.salesforce.com': { TXT: ['v=spf1 ip4:13.108.0.0/14 ip4:96.43.144.0/20 ~all'] },
    '_spf2.salesforce.com': { TXT: ['v=spf1 ip4:136.146.0.0/15 ~all'] },
    'amazonses.com': { TXT: ['v=spf1 ip4:54.240.0.0/18 ip4:23.249.208.0/20 ip4:199.255.192.0/22 ~all'] },
  }
  if (id === 'northwind') return {
    ...vendor,
    'example.com': { MX: ['1 smtp.google.com.'], TXT: ['v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net include:mail.zendesk.com include:spf.protection.outlook.com include:_spf.salesforce.com ip4:192.0.2.10 ~all', 'google-site-verification=synthetic-sample'] },
    '_dmarc.example.com': { TXT: ['v=DMARC1; p=none; rua=mailto:dmarc@example.com,mailto:reports@dmarc.example.net'] },
    'google._domainkey.example.com': { TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsyQIDAQAB'] },
    's1._domainkey.example.com': { CNAME: ['s1.domainkey.u4821.wl.sendgrid.net.'], TXT: ['k=rsa; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthIDAQAB'] },
  }
  return {
    ...vendor,
    'example.org': { MX: ['0 example-org.mail.protection.outlook.com.'], TXT: ['v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net include:amazonses.com include:mail.zendesk.com -all'] },
    '_dmarc.example.org': { TXT: ['v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc-rua@example.org; fo=1'] },
    'selector1._domainkey.example.org': { TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsyQIDAQAB'] },
    'k2._domainkey.example.org': { TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsynthsyQIDAQAB'] },
    '_mta-sts.example.org': { TXT: ['v=STSv1; id=20261001T0000'] },
    '_smtp._tls.example.org': { TXT: ['v=TLSRPTv1; rua=mailto:tls-reports@example.org'] },
  }
}

/** Synthetic PTR names for the invented sources (documentation ranges never resolve in real DNS). */
export const SAMPLE_PTR: Record<string, string | null> = {
  '192.0.2.10': 'billing-app.example.com',
  '198.51.100.23': 'relay1.alumni-forward.example.net',
  '198.51.100.24': 'relay2.alumni-forward.example.net',
  '203.0.113.77': null, '203.0.113.140': null, '203.0.113.141': null, '203.0.113.9': null, '203.0.113.10': null,
}
