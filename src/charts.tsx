import { useState } from 'react'
import type { Analysis, Verdict } from './engine/analyze.ts'
import { fmtDay, fmtN, fmtPct, fmtPeriod } from './ui.tsx'

export const VERDICT_COLOR: Record<Verdict, string> = { legit: 'var(--c-legit)', forwarder: 'var(--c-fwd)', suspicious: 'var(--c-spoof)' }
export const VERDICT_LABEL: Record<Verdict, string> = { legit: 'Your sender', forwarder: 'Forwarder', suspicious: 'Unauthorised / unknown' }

interface FNode { id: string; label: string; sub?: string; value: number; color: string; col: number; y?: number; h?: number }
interface FLink { from: string; to: string; value: number; color: string }

/** Sources -> authentication -> DMARC result, as a small Sankey diagram driven by the real analysis. */
export function FlowDiagram({ a, maxSources = 5, compact = false }: { a: Analysis; maxSources?: number; compact?: boolean }) {
  const [hover, setHover] = useState<string | null>(null)
  if (!a.total) return null
  const top = a.senders.slice(0, maxSources)
  const rest = a.senders.slice(maxSources)
  const src: FNode[] = top.map(s => ({ id: s.key, label: s.name, sub: `${fmtPct(s.share)} · ${fmtPct(s.volume ? s.pass / s.volume : 0)} pass`, value: s.volume, color: VERDICT_COLOR[s.verdict], col: 0 }))
  const links: FLink[] = []
  const auth = { dkim: 0, spf: 0, none: 0 }
  const add = (key: string, s: { volume: number; pass: number; dkimAligned: number }, color: string) => {
    const dk = Math.min(s.dkimAligned, s.pass), sp = Math.max(0, s.pass - dk), no = s.volume - s.pass
    if (dk) links.push({ from: key, to: 'dkim', value: dk, color })
    if (sp) links.push({ from: key, to: 'spf', value: sp, color })
    if (no) links.push({ from: key, to: 'none', value: no, color })
    auth.dkim += dk; auth.spf += sp; auth.none += no
  }
  top.forEach(s => add(s.key, s, VERDICT_COLOR[s.verdict]))
  if (rest.length) {
    const agg = rest.reduce((t, s) => ({ volume: t.volume + s.volume, pass: t.pass + s.pass, dkimAligned: t.dkimAligned + s.dkimAligned }), { volume: 0, pass: 0, dkimAligned: 0 })
    src.push({ id: 'other', label: `${rest.length} other source${rest.length > 1 ? 's' : ''}`, value: agg.volume, color: 'var(--ink-3)', col: 0 })
    add('other', agg, 'var(--ink-3)')
  }
  const mid: FNode[] = [
    { id: 'dkim', label: 'DKIM aligned', value: auth.dkim, color: 'var(--good)', col: 1 },
    { id: 'spf', label: 'SPF aligned only', value: auth.spf, color: 'var(--warn)', col: 1 },
    { id: 'none', label: 'Not aligned', value: auth.none, color: 'var(--bad)', col: 1 },
  ].filter(n => n.value > 0)
  const pass = auth.dkim + auth.spf
  const end: FNode[] = [
    { id: 'pass', label: 'DMARC pass', sub: fmtPct(pass / a.total, 1), value: pass, color: 'var(--good)', col: 2 },
    { id: 'fail', label: 'DMARC fail', sub: fmtPct(auth.none / a.total, 1), value: auth.none, color: 'var(--bad)', col: 2 },
  ].filter(n => n.value > 0)
  if (auth.dkim) links.push({ from: 'dkim', to: 'pass', value: auth.dkim, color: 'var(--good)' })
  if (auth.spf) links.push({ from: 'spf', to: 'pass', value: auth.spf, color: 'var(--warn)' })
  if (auth.none) links.push({ from: 'none', to: 'fail', value: auth.none, color: 'var(--bad)' })

  const W = 720, H = compact ? 280 : 340, NW = 10, GAP = 14, PAD = 6
  const colX = [compact ? 150 : 190, compact ? 400 : 440, W - (compact ? 120 : 130)]
  const nodes = [src, mid, end]
  // One scale for every column so a ribbon has the same width at both ends.
  const scale = (H - PAD * 2 - GAP * (Math.max(...nodes.map(c => c.length)) - 1)) / a.total
  for (const col of nodes) {
    const used = col.reduce((s, n) => s + n.value * scale, 0) + GAP * (col.length - 1)
    let y = (H - used) / 2
    for (const n of col) { n.h = Math.max(1, n.value * scale); n.y = y; y += n.value * scale + GAP }
  }
  const all = new Map([...src, ...mid, ...end].map(n => [n.id, n]))
  const outOff = new Map<string, number>(), inOff = new Map<string, number>()
  const paths = links.map((l, i) => {
    const f = all.get(l.from)!, t = all.get(l.to)!
    const w = l.value * scale
    const y0 = f.y! + (outOff.get(f.id) ?? 0), y1 = t.y! + (inOff.get(t.id) ?? 0)
    outOff.set(f.id, (outOff.get(f.id) ?? 0) + w)
    inOff.set(t.id, (inOff.get(t.id) ?? 0) + w)
    const x0 = colX[f.col] + NW, x1 = colX[t.col], mx = (x0 + x1) / 2
    const d = `M${x0},${y0} C${mx},${y0} ${mx},${y1} ${x1},${y1} L${x1},${y1 + w} C${mx},${y1 + w} ${mx},${y0 + w} ${x0},${y0 + w} Z`
    const c = `M${x0},${y0 + w / 2} C${mx},${y0 + w / 2} ${mx},${y1 + w / 2} ${x1},${y1 + w / 2}`
    const dim = hover && hover !== l.from && hover !== l.to
    return (
      <g key={i} className={`flow-link${dim ? ' dim' : ''}`}>
        <path d={d} fill={l.color} opacity={0.22} />
        <path d={c} className="flow-pulse" stroke={l.color} strokeWidth={Math.min(2, w)} fill="none" style={{ animationDelay: `${(i % 5) * -0.6}s` }} />
        <title>{`${all.get(l.from)!.label} → ${all.get(l.to)!.label}: ${fmtN(l.value)} messages`}</title>
      </g>
    )
  })
  const label = (n: FNode) => {
    const left = n.col === 0
    const x = left ? colX[0] - 8 : n.col === 1 ? colX[1] + NW + 8 : colX[2] + NW + 8
    const cy = n.y! + n.h! / 2
    return (
      <g key={n.id} onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} className="flow-node">
        <rect x={colX[n.col]} y={n.y} width={NW} height={n.h} rx={2} fill={n.color} />
        <text x={x} y={cy - (n.sub ? 3 : -4)} textAnchor={left ? 'end' : 'start'} className="flow-label">{n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label}</text>
        {n.sub && <text x={x} y={cy + 12} textAnchor={left ? 'end' : 'start'} className="flow-sub">{n.sub}</text>}
        {!n.sub && n.col === 1 && <text x={x} y={cy + 18} className="flow-sub">{fmtN(n.value)}</text>}
      </g>
    )
  }
  return (
    <figure className="flow" aria-label={`Mail flow: ${fmtPct(pass / a.total, 1)} of ${fmtN(a.total)} messages pass DMARC`}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img">
        {paths}
        {[...src, ...mid, ...end].map(label)}
      </svg>
      <figcaption className="legend">
        <span><i style={{ background: VERDICT_COLOR.legit }} />Your senders</span>
        <span><i style={{ background: VERDICT_COLOR.forwarder }} />Forwarders</span>
        <span><i style={{ background: VERDICT_COLOR.suspicious }} />Unknown / spoofing</span>
      </figcaption>
    </figure>
  )
}

/** Weekly readiness line with the rollout threshold. */
export function TrendChart({ weekly, threshold, height = 160 }: { weekly: { week: string; readiness: number; volume: number }[]; threshold: number; height?: number }) {
  const pts = weekly.filter(w => w.volume > 0)
  if (pts.length < 2) return <p className="muted small">Import reports from at least two weeks to see a trend.</p>
  const W = 600, H = height, L = 36, R = 10, T = 10, B = 26
  const min = Math.max(0, Math.floor(Math.min(...pts.map(p => p.readiness), threshold) * 10) / 10 - 0.05)
  const x = (i: number) => L + (i / (pts.length - 1)) * (W - L - R)
  const y = (v: number) => T + (1 - (v - min) / (1 - min)) * (H - T - B)
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p.readiness)}`).join(' ')
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Readiness by week, from ${fmtPct(pts[0].readiness, 1)} to ${fmtPct(pts.at(-1)!.readiness, 1)}`}>
      {[min, (min + 1) / 2, 1].map(v => <g key={v}><line x1={L} x2={W - R} y1={y(v)} y2={y(v)} className="grid" /><text x={L - 6} y={y(v) + 4} textAnchor="end" className="axis">{Math.round(v * 100)}%</text></g>)}
      <line x1={L} x2={W - R} y1={y(threshold)} y2={y(threshold)} className="threshold" />
      <text x={W - R} y={y(threshold) - 5} textAnchor="end" className="axis accent">target {Math.round(threshold * 1000) / 10}%</text>
      <path d={`${line} L${x(pts.length - 1)},${H - B} L${x(0)},${H - B} Z`} className="area" />
      <path d={line} className="line" />
      {pts.map((p, i) => <g key={p.week}><circle cx={x(i)} cy={y(p.readiness)} r={3.5} className="dot"><title>{`${fmtPeriod(p.week)}: ${fmtPct(p.readiness, 1)}`}</title></circle>
        <text x={x(i)} y={H - 8} textAnchor="middle" className="axis">{fmtPeriod(p.week).replace('Week of ', '').replace(/, \d{4}$/, '')}</text></g>)}
    </svg>
  )
}

/** Daily volume: passing, failing (yours) and unknown/spoofing. */
export function DayBars({ days }: { days: Analysis['days'] }) {
  if (!days.length) return null
  const max = Math.max(...days.map(d => d.volume))
  return (
    <div className="daybars" role="img" aria-label="Messages per day by DMARC result">
      {days.map(d => {
        const fail = d.volume - d.pass - d.suspicious
        return (
          <div key={d.day} className="daybar" title={`${fmtDay(d.day)}: ${fmtN(d.pass)} pass, ${fmtN(Math.max(0, fail))} fail, ${fmtN(d.suspicious)} unknown/spoofing`}>
            <div className="stack" style={{ height: `${(d.volume / max) * 100}%` }}>
              <span style={{ flex: d.suspicious, background: 'var(--c-spoof)' }} />
              <span style={{ flex: Math.max(0, fail), background: 'var(--bad)' }} />
              <span style={{ flex: d.pass, background: 'var(--good)' }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

export function Ring({ value, size = 120, label }: { value: number; size?: number; label?: string }) {
  const r = size / 2 - 8, c = 2 * Math.PI * r
  const tone = value >= 0.98 ? 'var(--good)' : value >= 0.9 ? 'var(--warn)' : 'var(--bad)'
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="ring" role="img" aria-label={`${label ?? 'Readiness'} ${fmtPct(value, 1)}`}>
      <circle cx={size / 2} cy={size / 2} r={r} className="ring-bg" />
      <circle cx={size / 2} cy={size / 2} r={r} stroke={tone} className="ring-fg" strokeDasharray={`${c * value} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      <text x="50%" y="50%" dy="0.35em" textAnchor="middle" className="ring-text" style={{ fontSize: size / 4.6 }}>{(value * 100).toFixed(value >= 0.995 || value < 0.1 ? 0 : 1)}%</text>
    </svg>
  )
}
