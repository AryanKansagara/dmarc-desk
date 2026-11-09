import { planRollout } from './engine/rollout.ts'
import type { TabProps } from './Project.tsx'
import { TrendChart } from './charts.tsx'
import { CopyButton, fmtDate, fmtPct, Link } from './ui.tsx'

const STATUS: Record<string, string> = { done: 'Done', current: 'You are here', ready: 'Ready', blocked: 'Blocked', upcoming: 'Upcoming' }

export default function Rollout({ project, x, update }: TabProps) {
  const { a, weekly } = x
  const reportPolicy = Object.entries(a.policies).sort((p, q) => q[1] - p[1])[0]?.[0]
  const fromReports = reportPolicy ? { p: reportPolicy.match(/p=(\w+)/)![1], pct: Number(reportPolicy.match(/pct=(\d+)/)?.[1] ?? 100) } : null
  const current = project.dns?.dmarc?.p ? { p: project.dns.dmarc.p, pct: project.dns.dmarc.pct } : fromReports
  const since = project.policySince ?? project.createdAt
  const plan = planRollout({
    domain: project.domain, current, since, now: Date.now(),
    rua: project.dns?.dmarc?.rua.length ? project.dns.dmarc.rua.map(u => u.replace(/^mailto:/, '').replace(/!.*$/, '')) : [project.rua],
    weekly, reporters: a.reporters.length,
    unreviewed: a.senders.filter(s => s.verdict === 'suspicious' && !s.overridden && s.share >= 0.01).length,
    threshold: project.threshold,
  })
  const next = plan.stages[plan.current + 1]
  return (
    <>
      <div className={`banner ${next?.status === 'ready' ? 'good' : next ? 'warn' : 'good'}`}><span><b>{plan.summary}</b></span>{next?.status === 'ready' && <CopyButton text={next.record} label="Copy next record" />}</div>
      <ol className="stages">
        {plan.stages.map((s, i) => (
          <li key={s.id} className={`stage s-${s.status}`}>
            <div className="stage-marker" aria-hidden="true">{s.status === 'done' ? '✓' : i + 1}</div>
            <div className="stage-body">
              <div className="row between wrap gap">
                <div><h3>{s.title}</h3><span className={`stage-status s-${s.status}`}>{STATUS[s.status]}</span>{Number.isFinite(s.start) && s.status !== 'done' && <span className="muted small"> · {s.status === 'current' ? 'since' : 'from'} {fmtDate(s.start)}{s.minWeeks ? ` · at least ${s.minWeeks} week${s.minWeeks > 1 ? 's' : ''}` : ''}</span>}</div>
              </div>
              <div className="code inline"><div className="code-head"><span>TXT _dmarc.{project.domain}</span><CopyButton text={s.record} /></div><pre><code>{s.record}</code></pre></div>
              <ul className="criteria">{s.criteria.map(c => <li key={c}>{c}</li>)}</ul>
              {s.blockers.length > 0 && <ul className="blockers">{s.blockers.map(b => <li key={b}>{b}</li>)}</ul>}
            </div>
          </li>
        ))}
      </ol>
      <div className="grid-2">
        <div className="panel">
          <h2>Readiness by week</h2>
          <TrendChart weekly={weekly} threshold={project.threshold} />
          <p className="small muted">Latest full week: {fmtPct(weekly.filter(w => w.volume).at(-1)?.readiness ?? 0, 1)}. Gate: two consecutive weeks at or above the target.</p>
        </div>
        <div className="panel">
          <h2>Plan settings</h2>
          <label className="field"><span>Current policy published on</span><input type="date" value={new Date(since).toISOString().slice(0, 10)} onChange={e => e.target.value && void update({ policySince: Date.parse(e.target.value) })} /></label>
          <label className="field"><span>Readiness target: {fmtPct(project.threshold, 1)}</span><input type="range" min="0.9" max="1" step="0.005" value={project.threshold} onChange={e => void update({ threshold: +e.target.value })} /></label>
          <p className="small muted">Current policy {current ? <code>p={current.p}{current.pct < 100 ? ` pct=${current.pct}` : ''}</code> : 'unknown'} ({project.dns?.dmarc ? 'from the live DNS check' : fromReports ? 'from the reports; run the DNS check to confirm' : 'run the DNS check'}). Unknown senders above 1% of volume must be reviewed on the <Link href={`/app/p/${project.id}/senders`}>Senders</Link> tab before moving on.</p>
          <p className="small muted">pct= is being replaced by t=y (testing) in the DMARCbis draft; every major receiver still honours pct today, and the planner will switch when they stop.</p>
        </div>
      </div>
    </>
  )
}
