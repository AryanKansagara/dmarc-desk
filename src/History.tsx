import { useState } from 'react'
import { compareSnapshots } from './engine/analyze.ts'
import { TrendChart } from './charts.tsx'
import type { TabProps } from './Project.tsx'
import { deleteSnapshotCloud } from './sync.ts'
import { Empty, fmtN, fmtPct, signed, toast } from './ui.tsx'

export default function History({ project, update }: TabProps) {
  const snaps = [...project.snapshots].sort((a, b) => a.period.localeCompare(b.period))
  const [aId, setA] = useState(snaps.at(0)?.id ?? '')
  const [bId, setB] = useState(snaps.at(-1)?.id ?? '')
  if (!snaps.length) return <Empty title="No snapshots yet"><p className="muted">Snapshots are saved for every week when you import reports, or press <kbd>S</kbd> on any week.</p></Empty>
  const A = snaps.find(s => s.id === aId) ?? snaps[0], B = snaps.find(s => s.id === bId) ?? snaps.at(-1)!
  const d = compareSnapshots(A, B)
  const pp = (n: number) => `${(n * 100).toFixed(1)} pts`
  const remove = (id: string) => {
    const before = project.snapshots
    void update({ snapshots: before.filter(s => s.id !== id) })
    toast('Snapshot deleted', { undo: () => void update({ snapshots: before }) })
    setTimeout(() => { if (!project.snapshots.some(s => s.id === id)) void deleteSnapshotCloud(id) }, 9000)
  }
  return (
    <>
      <div className="panel">
        <div className="panel-head"><h2>Aligned share of legitimate mail, by week</h2></div>
        <TrendChart weekly={snaps.map(s => ({ week: s.period, readiness: s.readiness, volume: s.total }))} threshold={project.threshold} height={220} width={1100} />
      </div>
      <div className="panel">
        <div className="panel-head">
          <h2>Compare</h2>
          <div className="row gap-sm wrap">
            <label className="sr-only" htmlFor="ca">From</label>
            <select id="ca" value={A.id} onChange={e => setA(e.target.value)}>{snaps.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}</select>
            <span aria-hidden="true">&rarr;</span>
            <label className="sr-only" htmlFor="cb">To</label>
            <select id="cb" value={B.id} onChange={e => setB(e.target.value)}>{snaps.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}</select>
          </div>
        </div>
        <div className="kpis">
          <div className="kpi"><small>Readiness</small><b>{fmtPct(B.readiness, 1)}</b><p className={d.readiness >= 0 ? 'good-text' : 'error'}>{signed(d.readiness, pp)} vs {fmtPct(A.readiness, 1)}</p></div>
          <div className="kpi"><small>Messages</small><b>{fmtN(B.total)}</b><p>{signed(d.total, fmtN)}</p></div>
          <div className="kpi"><small>Legit mail at risk</small><b>{fmtN(B.atRisk)}</b><p>was {fmtN(A.atRisk)}</p></div>
          <div className="kpi"><small>Unknown / spoofing</small><b>{fmtN(B.suspiciousVolume)}</b><p>was {fmtN(A.suspiciousVolume)}</p></div>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Sender</th><th className="num">Pass rate before</th><th className="num">After</th><th className="num">Change</th><th className="num">Messages</th></tr></thead>
            <tbody>
              {d.changed.map(c => <tr key={c.key}><td>{c.name}</td><td className="num">{fmtPct(c.before, 1)}</td><td className="num">{fmtPct(c.after, 1)}</td><td className={`num ${c.after > c.before ? 'good-text' : c.after < c.before ? 'error' : ''}`}>{signed(c.after - c.before, pp)}</td><td className="num">{fmtN(c.volumeBefore)} &rarr; {fmtN(c.volumeAfter)}</td></tr>)}
              {d.added.map(s => <tr key={s.key}><td>{s.name} <span className="badge">new</span></td><td className="num">—</td><td className="num">{fmtPct(s.volume ? s.pass / s.volume : 0, 1)}</td><td className="num">—</td><td className="num">{fmtN(s.volume)}</td></tr>)}
              {d.removed.map(s => <tr key={s.key}><td>{s.name} <span className="badge">gone</span></td><td className="num">{fmtPct(s.volume ? s.pass / s.volume : 0, 1)}</td><td className="num">—</td><td className="num">—</td><td className="num">{fmtN(s.volume)} &rarr; 0</td></tr>)}
              {!d.changed.length && !d.added.length && !d.removed.length && <tr><td colSpan={5} className="muted">No sender changed between these weeks.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      <div className="panel">
        <div className="panel-head"><h2>Snapshots</h2><span className="muted small">{snaps.length} saved</span></div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Week</th><th className="num">Messages</th><th className="num">Readiness</th><th className="num">Senders</th><th>Saved</th><th /></tr></thead>
            <tbody>{[...snaps].reverse().map(s => <tr key={s.id}><td>{s.label}</td><td className="num">{fmtN(s.total)}</td><td className="num">{fmtPct(s.readiness, 1)}</td><td className="num">{s.senders.length}</td><td className="small muted">{new Date(s.at).toLocaleDateString()}</td><td className="num"><button type="button" className="btn danger-ghost sm" onClick={() => remove(s.id)}>Delete</button></td></tr>)}</tbody>
          </table>
        </div>
      </div>
    </>
  )
}
