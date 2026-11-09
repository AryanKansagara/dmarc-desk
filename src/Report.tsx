import { useEffect, useMemo } from 'react'
import { planRollout } from './engine/rollout.ts'
import { FlowDiagram, TrendChart, VERDICT_LABEL } from './charts.tsx'
import { periodFromUrl } from './Project.tsx'
import { defaultPeriod, periodOptions, useAnalysis, useProject } from './projectData.ts'
import { download, fmtDate, fmtN, fmtPct, fmtPeriod, Link, SyntheticBadge } from './ui.tsx'

export default function Report({ id }: { id: string }) {
  const { loading, project, ds } = useProject(id)
  const opts = useMemo(() => periodOptions(ds), [ds])
  const period = periodFromUrl(opts, useMemo(() => defaultPeriod(ds), [ds]))
  const x = useAnalysis(ds, project, period)
  useEffect(() => { if (project) document.title = `Email authentication report · ${project.domain} · ${fmtPeriod(period)}` }, [project?.domain, period])

  if (loading) return <div className="boot"><span className="spinner" /> Building the report</div>
  if (!project || !x) return <section className="page narrow center"><h1>Domain not found</h1><Link href="/app" className="btn primary">All domains</Link></section>
  const { a, weekly } = x
  const dns = project.dns
  const cur = dns?.dmarc?.p ? { p: dns.dmarc.p, pct: dns.dmarc.pct } : null
  const plan = planRollout({ domain: project.domain, current: cur, since: project.policySince ?? project.createdAt, now: Date.now(), rua: dns?.dmarc?.rua ?? [project.rua], weekly, reporters: a.reporters.length, unreviewed: a.senders.filter(s => s.verdict === 'suspicious' && !s.overridden && s.share >= 0.01).length, threshold: project.threshold })
  const failing = a.senders.filter(s => s.verdict === 'legit' && s.pass < s.volume)
  const findings = [
    a.total ? `Receivers reported ${fmtN(a.total)} messages using ${project.domain} as the sender (${fmtPeriod(period).toLowerCase()}), from ${a.senders.length} distinct sources.` : 'No aggregate reports have been imported for this period yet.',
    a.legitVolume ? `${fmtPct(a.readiness, 1)} of our legitimate mail passes DMARC. ${a.atRisk ? `${fmtN(a.atRisk)} legitimate messages would be quarantined or rejected under enforcement until ${failing.map(s => s.name).join(', ')} ${failing.length > 1 ? 'are' : 'is'} fixed.` : 'Nothing legitimate would be blocked by enforcement.'}` : '',
    a.suspiciousVolume ? `${fmtN(a.suspiciousVolume)} messages (${fmtPct(a.suspiciousVolume / a.total, 1)}) came from sources we do not recognise and that fail authentication: likely spoofing. They are delivered today${cur?.p === 'reject' ? '' : ' because the policy is not yet p=reject'}.` : 'No spoofing sources were seen in this period.',
    dns ? `DNS grade ${dns.grade} (${dns.score}/100) on ${fmtDate(dns.at)}. ${dns.sections.filter(s => s.status === 'fail').map(s => `${s.title}: ${s.summary}`).join('; ') || 'No failing checks.'}` : 'DNS has not been checked yet.',
    `Gmail, Yahoo and Outlook.com now reject or junk bulk mail that lacks SPF, DKIM and DMARC alignment. Moving to p=reject also stops others sending as ${project.domain}.`,
    plan.summary,
  ].filter(Boolean)
  const csv = () => [['sender', 'verdict', 'messages', 'share', 'dmarc_pass_rate', 'next_step'], ...a.senders.map(s => [s.name, s.verdict, s.volume, (s.share * 100).toFixed(1) + '%', (s.volume ? s.pass / s.volume * 100 : 0).toFixed(1) + '%', s.fixes[0] ?? ''])]
    .map(r => r.map(c => /[",\n]/.test(String(c)) ? `"${String(c).replace(/"/g, '""')}"` : c).join(',')).join('\n')

  return (
    <article className="report">
      <div className="report-actions">
        <Link href={`/app/p/${id}${location.search}`} className="btn ghost">Back to the domain</Link>
        <button type="button" className="btn outline" onClick={() => download(`${project.domain}-senders-${period}.csv`, csv())}>Download CSV</button>
        <button type="button" className="btn primary" onClick={() => print()}>Print or save as PDF</button>
      </div>
      <div className="eyebrow">Email deliverability and authentication</div>
      <h1>{project.domain} {project.sampleId && <SyntheticBadge />}</h1>
      <p className="muted">{fmtPeriod(period)} · {a.reports} reports from {a.reporters.map(r => r.org).join(', ') || 'no receivers'} · prepared {new Date().toLocaleDateString('en-US', { dateStyle: 'long' })}</p>
      <div className="kpis">
        <div className="kpi"><small>Policy readiness</small><b>{fmtPct(a.readiness, 1)}</b><p>target {fmtPct(project.threshold, 0)}</p></div>
        <div className="kpi"><small>Current policy</small><b className="mono kpi-mono">{cur ? `p=${cur.p}${cur.pct < 100 ? ` ${cur.pct}%` : ''}` : '—'}</b></div>
        <div className="kpi"><small>Legit mail at risk</small><b>{fmtN(a.atRisk)}</b></div>
        <div className="kpi"><small>Spoofing / unknown</small><b>{fmtN(a.suspiciousVolume)}</b></div>
      </div>
      <h2>Summary</h2>
      <ol>{findings.map((f, i) => <li key={i}>{f}</li>)}</ol>
      {a.total > 0 && <><h2>Mail flow</h2><FlowDiagram a={a} maxSources={6} compact /></>}
      {weekly.length > 1 && <><h2>Readiness by week</h2><TrendChart weekly={weekly} threshold={project.threshold} /></>}
      <h2>Senders</h2>
      <div className="table-wrap"><table>
        <thead><tr><th>Sender</th><th>Type</th><th className="num">Messages</th><th className="num">Share</th><th className="num">Pass</th><th>Next step</th></tr></thead>
        <tbody>{a.senders.map(s => <tr key={s.key}><th scope="row">{s.name}</th><td className="small">{VERDICT_LABEL[s.verdict]}</td><td className="num">{fmtN(s.volume)}</td><td className="num">{fmtPct(s.share, 1)}</td><td className="num">{fmtPct(s.volume ? s.pass / s.volume : 0, 1)}</td><td className="small">{(s.fixes[0] ?? '').split('. ')[0]}.</td></tr>)}</tbody>
      </table></div>
      <h2>Rollout plan</h2>
      <div className="table-wrap"><table>
        <thead><tr><th>Stage</th><th>Record</th><th>Status</th><th>From</th></tr></thead>
        <tbody>{plan.stages.map(s => <tr key={s.id}><td>{s.title}</td><td><code className="small">{s.record}</code></td><td>{s.status}</td><td className="small">{Number.isFinite(s.start) ? fmtDate(s.start) : 'done'}</td></tr>)}</tbody>
      </table></div>
      <p className="muted small">Dates are earliest possible: each step waits for its minimum time and for readiness to hold above target. Generated by DMARC Desk from DMARC aggregate (RUA) reports{project.sampleId ? '; this sample uses synthetic data' : ''}.</p>
    </article>
  )
}
