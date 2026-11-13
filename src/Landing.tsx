import { useEffect, useMemo, useState } from 'react'
import { analyze, isoWeek } from './engine/analyze.ts'
import { checkDomain, type DomainCheck } from './engine/checks.ts'
import { isDomain, normDomain } from './engine/domain.ts'
import { SAMPLE_PTR } from './engine/sample.ts'
import { FlowDiagram } from './charts.tsx'
import { GradeCard } from './DnsTab.tsx'
import { fetchStsPolicy, liveResolver, sampleReports } from './projectData.ts'
import { fmtPct, go, Link } from './ui.tsx'
import { openDomain } from './Workspace.tsx'

const WEEKS = [['2026-W40', 'Before: newsletter unaligned'], ['2026-W44', 'After: SendGrid custom DKIM']] as const
const EXAMPLES = ['cloudflare.com', 'github.com', 'gmail.com']

function HeroCheck() {
  const [q, setQ] = useState('')
  const [state, setState] = useState<{ busy: boolean; check: DomainCheck | null; err: string | null }>({ busy: false, check: null, err: null })
  const run = async (raw: string) => {
    const d = normDomain(raw)
    if (!isDomain(d)) { setState(s => ({ ...s, err: `"${raw}" is not a domain name` })); return }
    setQ(d)
    setState(s => ({ ...s, busy: true, err: null }))
    try { setState({ busy: false, check: await checkDomain(d, liveResolver(), { fetchPolicy: fetchStsPolicy }), err: null }) }
    catch (e) { setState(s => ({ ...s, busy: false, err: `Lookup failed: ${(e as Error).message}. Your network may block DNS-over-HTTPS.` })) }
  }
  useEffect(() => { void run(EXAMPLES[0]) }, [])
  return (
    <div className="hero-check">
      <form className="domain-form big" onSubmit={e => { e.preventDefault(); void run(q) }}>
        <label className="sr-only" htmlFor="hero-domain">Your domain</label>
        <input id="hero-domain" value={q} onChange={e => setQ(e.target.value)} placeholder="yourcompany.com" autoComplete="off" spellCheck={false} />
        <button className="btn primary" disabled={state.busy}>{state.busy ? 'Checking' : 'Check DNS'}</button>
      </form>
      <div className="examples small">Try {EXAMPLES.map(d => <button key={d} type="button" className="linkish" onClick={() => void run(d)}>{d}</button>)}</div>
      {state.err && <p className="error small" role="alert">{state.err}</p>}
      <div className={`hero-grade${state.busy ? ' busy' : ''}`} aria-live="polite">
        {state.check ? <GradeCard check={state.check} compact /> : <div className="grade-skeleton"><span className="spinner" /> Querying cloudflare-dns.com</div>}
        {state.check && (
          <div className="row between wrap gap hero-grade-foot">
            <span className="muted small">Live, from your browser, {state.check.spf.lookups} SPF lookups followed.</span>
            <button type="button" className="btn ghost sm" onClick={() => void openDomain(state.check!.domain)}>Open {state.check.domain} in the app &rarr;</button>
          </div>
        )}
      </div>
    </div>
  )
}

function HeroFlow() {
  const [w, setW] = useState(0)
  const reports = useMemo(() => sampleReports('northwind')!, [])
  const a = useMemo(() => analyze(reports.filter(r => isoWeek(r.begin) === WEEKS[w][0]), { domain: 'example.com', ptr: SAMPLE_PTR }), [w, reports])
  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const t = setInterval(() => setW(x => 1 - x), 5200)
    return () => clearInterval(t)
  }, [])
  return (
    <div className="window">
      <div className="window-bar"><i /><i /><i /><strong>example.com</strong><span className="badge synthetic">Synthetic sample</span><span className="muted small hide-sm" style={{ marginLeft: 'auto' }}>Readiness {fmtPct(a.readiness, 1)}</span></div>
      <div className="window-body">
        <div className="seg-control" role="radiogroup" aria-label="Sample week">
          {WEEKS.map(([id, l], i) => <button key={id} type="button" role="radio" aria-checked={w === i} className={w === i ? 'on' : ''} onClick={() => setW(i)}>{l}</button>)}
        </div>
        <FlowDiagram a={a} maxSources={5} compact />
      </div>
    </div>
  )
}

export function Landing() {
  return (
    <>
      <section className="hero">
        <div className="hero-inner">
          <div>
            <div className="eyebrow">Email authentication</div>
            <h1>From <code className="h-code">p=none</code> to <code className="h-code accent">p=reject</code>, without losing a single real email.</h1>
            <p className="lede">Gmail, Yahoo and now Outlook.com reject unauthenticated bulk mail. DMARC Desk checks your DNS live, reads the aggregate reports receivers send you, names every service sending as your domain, tells you exactly how to fix each one, and dates each step to enforcement.</p>
            <HeroCheck />
          </div>
          <div className="hero-visual">
            <HeroFlow />
            <p className="hero-note">The diagram is the real engine running on six weeks of synthetic reports: sources on the left, how each message authenticated, and whether DMARC passed.</p>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-head"><div className="eyebrow">Why this exists</div><h2>DMARC is easy to publish and hard to finish</h2><p>Most domains stall at p=none because nobody can tell which failures are their own mail.</p></div>
        <div className="quotes">
          <figure className="quote"><blockquote>Outlook.com started bouncing our Microsoft 365 mail with a 550 5.7 error because SPF, DKIM and DMARC weren&rsquo;t all lined up.</blockquote><figcaption className="src">Paraphrased from r/M365Reports</figcaption></figure>
          <figure className="quote"><blockquote>I fixed the failure, but the reports keep showing failures. Why?</blockquote><figcaption className="src">Paraphrased from r/DMARC</figcaption></figure>
          <figure className="quote"><blockquote>We moved DNS to Cloudflare and suddenly our mail is going to spam, or not arriving at all.</blockquote><figcaption className="src">Paraphrased from r/CloudFlare</figcaption></figure>
        </div>
      </section>

      <section className="section">
        <div className="section-head"><div className="eyebrow">How it works</div><h2>Four steps, all in your browser</h2></div>
        <div className="steps">
          {[
            ['01', 'Check DNS live', 'SPF expanded recursively against the 10-lookup and void-lookup limits, every DMARC tag, DKIM at 36 common selectors, MTA-STS, TLS-RPT, BIMI and DNSSEC, over DNS-over-HTTPS.'],
            ['02', 'Import reports', 'Drop hundreds of .xml, .xml.gz and .zip aggregate reports at once, or the report emails themselves (.eml, Google Takeout .mbox). Decompressed in the browser, validated with line numbers, duplicates skipped.'],
            ['03', 'Fix each sender', 'Every source IP is mapped to a service (Google, Microsoft 365, SendGrid, Mailchimp, SES, Postmark, HubSpot, Salesforce, Zendesk and more) with the exact setting that makes it align.'],
            ['04', 'Enforce on a schedule', 'A readiness score on legitimate mail only, a staged plan to quarantine and reject with dates and gates, and copy-ready records with a Cloudflare zone-file snippet.'],
          ].map(([n, t, d]) => <div key={n} className="step corners"><span className="step-n">{n}</span><h3>{t}</h3><p>{d}</p></div>)}
        </div>
      </section>

      <section className="section">
        <div className="features">
          {[
            ['Forwarding, explained', 'Forwarded mail that kept DKIM passes; mailing lists that broke it are separated out and excluded from readiness, because no DNS change can fix them.'],
            ['"Looks fixed since Tuesday"', 'Reports cover 24-hour windows and arrive late. DMARC Desk spots the day a sender became aligned so stale failures stop worrying you.'],
            ['SPF flattener', 'Over 10 lookups? The builder flattens the heaviest includes into ip4/ip6, splits long records, and warns when flattened ranges need a refresh.'],
            ['Weekly history', 'A snapshot per week with a compare view: which senders improved, which are new, and the aligned share trend.'],
            ['Leadership report', 'A printable one-pager: readiness, spoofing volume, what is left to fix, and when the domain reaches p=reject.'],
            ['Yours, locally', 'No account needed. Projects live in your browser; sign in only if you want sync across devices.'],
          ].map(([t, d]) => <article key={t} className="feature"><h3>{t}</h3><p>{d}</p></article>)}
        </div>
      </section>

      <section className="cta-band">
        <div className="cta-inner">
          <div><h2>See it on a messy domain first</h2><p>Six weeks of synthetic reports with an unaligned newsletter, a forwarder and a spoofer.</p></div>
          <div className="row gap wrap">
            <button type="button" className="btn primary lg" onClick={() => go('/app?sample=northwind')}>Open the sample</button>
            <Link href="/docs" className="btn lg cta-ghost">Read the docs</Link>
          </div>
        </div>
      </section>
    </>
  )
}
