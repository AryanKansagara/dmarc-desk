import { DayBars, FlowDiagram, Ring, TrendChart, VERDICT_COLOR } from './charts.tsx'
import type { TabProps } from './Project.tsx'
import { fmtN, fmtPct, Link } from './ui.tsx'

export default function Overview({ project, x, period }: TabProps) {
  const { a, weekly } = x
  const q = location.search
  const todo = a.senders.filter(s => s.verdict === 'legit' && s.pass < s.volume).sort((p, r) => (r.volume - r.pass) - (p.volume - p.pass))
  const unknown = a.senders.filter(s => s.verdict === 'suspicious' && !s.overridden && s.share >= 0.01)
  const fixed = a.senders.filter(s => s.fixedSince)
  const ready = a.readiness >= project.threshold
  return (
    <>
      {fixed.length > 0 && period === 'all' && (
        <div className="banner good"><span><b>{fixed.map(s => s.name).join(', ')}</b> {fixed.length > 1 ? 'look' : 'looks'} fixed since {fixed[0].fixedSince}. Older reports still show failures because each covers a 24-hour window and arrives 1 to 3 days late. Switch to the latest week to see the current state.</span></div>
      )}
      <div className="overview-top">
        <div className="panel readiness-card corners">
          <div className="row gap" style={{ alignItems: 'center' }}>
            <Ring value={a.readiness} size={128} />
            <div>
              <div className="eyebrow">Policy readiness</div>
              <h2 style={{ margin: '0 0 6px' }}>{ready ? 'Ready to tighten the policy' : a.legitVolume ? `${fmtN(a.atRisk)} legitimate messages would fail` : 'No legitimate mail identified yet'}</h2>
              <p className="muted small" style={{ margin: 0 }}>Share of your legitimate mail (your senders plus forwarded mail that kept its DKIM) that passes DMARC. Target {fmtPct(project.threshold, 0)} before enforcing.</p>
            </div>
          </div>
          <div className="row gap wrap" style={{ marginTop: 16 }}>
            <Link className="btn primary sm" href={`/app/p/${project.id}/rollout${q}`}>Rollout plan</Link>
            <Link className="btn ghost sm" href={`/app/p/${project.id}/senders${q}`}>Fix senders</Link>
          </div>
        </div>
        <div className="kpis kpis-3">
          <div className="kpi"><small>Messages reported</small><b>{fmtN(a.total)}</b><p>{a.reports} reports from {a.reporters.length} receiver{a.reporters.length === 1 ? '' : 's'}</p></div>
          <div className="kpi"><small>DMARC pass, all mail</small><b>{fmtPct(a.total ? a.pass / a.total : 0, 1)}</b><p>includes spoofing, which should fail</p></div>
          <div className="kpi"><small>Unknown or spoofing</small><b style={{ color: a.suspiciousVolume ? 'var(--c-spoof)' : undefined }}>{fmtN(a.suspiciousVolume)}</b><p>{fmtPct(a.total ? a.suspiciousVolume / a.total : 0, 1)} of volume, blocked at p=reject</p></div>
          <div className="kpi"><small>Forwarded</small><b>{fmtN(a.forwardVolume)}</b><p>{fmtN(a.forwardPass)} kept DKIM and pass</p></div>
          <div className="kpi"><small>Senders</small><b>{a.senders.length}</b><p>{a.senders.filter(s => s.verdict === 'legit').length} yours, {unknown.length} to review</p></div>
          <div className="kpi"><small>Policy in reports</small><b className="mono kpi-mono">{Object.entries(a.policies).sort((p, r) => r[1] - p[1])[0]?.[0] ?? '—'}</b><p>{project.dns?.dmarc ? `DNS now: p=${project.dns.dmarc.p}${project.dns.dmarc.pct < 100 ? ` pct=${project.dns.dmarc.pct}` : ''}` : 'Run the DNS check to compare'}</p></div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><h2>Where your mail comes from</h2><span className="muted small">Hover a node to trace it</span></div>
        <FlowDiagram a={a} maxSources={6} />
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head"><h2>Next actions</h2><Link href={`/app/p/${project.id}/senders${q}`} className="small">All senders</Link></div>
          {!todo.length && !unknown.length && <p className="muted">Every identified sender passes DMARC in this period. Check the rollout plan for the next step.</p>}
          <ol className="actions">
            {todo.slice(0, 4).map(s => (
              <li key={s.key}>
                <div className="row between gap"><b>{s.name}</b><span className="bad-text small tab-nums">{fmtN(s.volume - s.pass)} failing</span></div>
                <p className="small muted">{s.fixes[0]}</p>
              </li>
            ))}
            {unknown.slice(0, 3).map(s => (
              <li key={s.key}>
                <div className="row between gap"><b><i className="dot" style={{ background: VERDICT_COLOR.suspicious }} />{s.name}</b><span className="small tab-nums">{fmtN(s.volume)} msgs</span></div>
                <p className="small muted">Unknown source. Review it on the Senders tab: mark it legitimate if it is yours, or unauthorized if not.</p>
              </li>
            ))}
          </ol>
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Readiness by week</h2></div>
          <TrendChart weekly={weekly} threshold={project.threshold} />
          <h3 className="small muted" style={{ marginTop: 18 }}>Messages per day</h3>
          <DayBars days={a.days} />
          <div className="legend" style={{ marginTop: 8 }}>
            <span><i style={{ background: 'var(--good)' }} />Pass</span><span><i style={{ background: 'var(--bad)' }} />Your mail failing</span><span><i style={{ background: 'var(--c-spoof)' }} />Unknown / spoofing</span>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><h2>Who reported</h2><span className="muted small">Receivers send one report per day each</span></div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Receiver</th><th className="num">Reports</th><th className="num">Messages</th><th>Share</th></tr></thead>
            <tbody>
              {a.reporters.map(r => <tr key={r.org}><td>{r.org}</td><td className="num">{r.reports}</td><td className="num">{fmtN(r.volume)}</td><td><div className="share"><span style={{ width: `${(r.volume / a.total) * 100}%` }} /></div></td></tr>)}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
