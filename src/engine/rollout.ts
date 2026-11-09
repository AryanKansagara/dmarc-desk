// Staged DMARC rollout: none -> quarantine (10, 50, 100%) -> reject (50, 100%), gated on readiness.
import { generateDmarc } from './dmarc.ts'

export interface StageDef { id: string; p: 'none' | 'quarantine' | 'reject'; pct: number; minWeeks: number; title: string; criteria: string[] }

export const STAGES: StageDef[] = [
  { id: 'monitor', p: 'none', pct: 100, minWeeks: 2, title: 'Monitor', criteria: ['Reports arriving from at least two receivers', 'Every sender above 1% of volume identified', 'Readiness at or above the threshold for two weeks in a row'] },
  { id: 'q10', p: 'quarantine', pct: 10, minWeeks: 1, title: 'Quarantine 10%', criteria: ['No legitimate sender newly failing', 'No complaints of missing mail'] },
  { id: 'q50', p: 'quarantine', pct: 50, minWeeks: 1, title: 'Quarantine 50%', criteria: ['Readiness still at or above the threshold', 'Spam-folder complaints checked'] },
  { id: 'q100', p: 'quarantine', pct: 100, minWeeks: 2, title: 'Quarantine 100%', criteria: ['Two clean weeks at full quarantine', 'Forwarded mail still passing via DKIM'] },
  { id: 'r50', p: 'reject', pct: 50, minWeeks: 1, title: 'Reject 50%', criteria: ['No legitimate mail in quarantine dispositions'] },
  { id: 'r100', p: 'reject', pct: 100, minWeeks: 0, title: 'Reject 100%', criteria: ['Keep reading reports monthly; add new senders before they go live'] },
]

export interface Stage extends StageDef { record: string; start: number; status: 'done' | 'current' | 'ready' | 'blocked' | 'upcoming'; blockers: string[] }

export interface RolloutInput {
  domain: string
  current: { p: string; pct: number } | null
  /** When the current policy was published (defaults to the start date) */
  since?: number
  now: number
  rua: string[]
  /** Readiness per ISO week, oldest first */
  weekly: { week: string; readiness: number; volume: number }[]
  reporters: number
  /** Senders above 1% share that are not identified (unknown verdicts the user has not reviewed) */
  unreviewed: number
  threshold?: number
}

const WEEK = 7 * 86400000

export function stageIndex(cur: { p: string; pct: number } | null): number {
  if (!cur || cur.p === 'none') return 0
  let idx = 0
  STAGES.forEach((s, i) => { if ((s.p === cur.p && s.pct <= cur.pct) || (cur.p === 'reject' && s.p === 'quarantine')) idx = i })
  return idx
}

export function planRollout(inp: RolloutInput): { stages: Stage[]; current: number; threshold: number; readyIn: number | null; summary: string } {
  const threshold = inp.threshold ?? 0.98
  const cur = stageIndex(inp.current)
  const recent = inp.weekly.filter(w => w.volume > 0).slice(-2)
  const latest = recent.at(-1)?.readiness ?? 0
  const blockers: string[] = []
  if (!inp.weekly.some(w => w.volume > 0)) blockers.push('No aggregate reports imported yet')
  else {
    if (inp.reporters < 2) blockers.push(`Reports from ${inp.reporters} receiver so far; wait for at least two (Google and Microsoft usually arrive within 48 hours)`)
    if (recent.length < 2) blockers.push('Need two weeks of reports')
    const low = recent.filter(w => w.readiness < threshold)
    if (low.length) {
      const worst = Math.min(...low.map(w => w.readiness))
      blockers.push(low.length === recent.length || low.at(-1) === recent.at(-1)
        ? `Readiness ${Math.round(latest * 1000) / 10}% is below ${threshold * 100}% (fix the failing senders first)`
        : `Readiness ${Math.round(latest * 1000) / 10}% now, but ${Math.round(worst * 1000) / 10}% the week before: it needs two weeks in a row at or above ${threshold * 100}%`)
    }
  }
  if (inp.unreviewed) blockers.push(`${inp.unreviewed} significant sender${inp.unreviewed > 1 ? 's' : ''} not identified; mark each legitimate or unauthorized`)
  if (!inp.rua.length) blockers.push('Add an rua= address so you keep seeing reports while enforcing')
  const since = inp.since ?? inp.now
  let t = since
  const stages: Stage[] = STAGES.map((s, i) => {
    const record = generateDmarc({ p: s.p, pct: s.pct, rua: inp.rua.length ? inp.rua : [`dmarc@${inp.domain}`] })
    let status: Stage['status']
    if (i < cur) status = 'done'
    else if (i === cur) status = 'current'
    else if (i === cur + 1) status = blockers.length ? 'blocked' : 'ready'
    else status = 'upcoming'
    if (i === cur) t = since
    else if (i === cur + 1) t = Math.max(inp.now, since + STAGES[cur].minWeeks * WEEK)
    else if (i > cur + 1) t += STAGES[i - 1].minWeeks * WEEK
    return { ...s, record, start: i < cur ? NaN : t, status, blockers: i === cur + 1 ? blockers : [] }
  })
  const readyIn = blockers.length ? null : Math.max(0, Math.ceil((stages[Math.min(cur + 1, stages.length - 1)].start - inp.now) / 86400000))
  const summary = cur === STAGES.length - 1
    ? 'At p=reject. Spoofed mail is refused. Keep monitoring reports for new senders.'
    : blockers.length ? `Stay at ${STAGES[cur].title.toLowerCase()} for now: ${blockers[0].toLowerCase()}.`
      : `Ready to move to ${STAGES[cur + 1].title.toLowerCase()}${readyIn ? ` in ${readyIn} days` : ' now'}.`
  return { stages, current: cur, threshold, readyIn, summary }
}
