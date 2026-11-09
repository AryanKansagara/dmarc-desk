import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { snapshot } from './engine/analyze.ts'
import { defaultPeriod, periodOptions, useAnalysis, useProject } from './projectData.ts'
import { uuid, type Dataset, type Project } from './store.ts'
import { Empty, fmtN, fmtPeriod, go, isTyping, Link, Modal, SyntheticBadge, toast } from './ui.tsx'

const Overview = lazy(() => import('./Overview.tsx'))
const Senders = lazy(() => import('./Senders.tsx'))
const DnsTab = lazy(() => import('./DnsTab.tsx'))
const Records = lazy(() => import('./Records.tsx'))
const Rollout = lazy(() => import('./Rollout.tsx'))
const History = lazy(() => import('./History.tsx'))
const DataTab = lazy(() => import('./Data.tsx'))

export const TABS = [['overview', 'Overview'], ['senders', 'Senders'], ['dns', 'DNS check'], ['records', 'Records'], ['rollout', 'Rollout'], ['history', 'History'], ['data', 'Reports']] as const
export type Tab = (typeof TABS)[number][0]
const NEEDS_DATA: Tab[] = ['overview', 'senders', 'history']

export interface TabProps {
  project: Project
  ds: Dataset
  period: string
  x: NonNullable<ReturnType<typeof useAnalysis>>
  update(p: Partial<Project>): Promise<Project> | null | undefined
}

export const periodFromUrl = (opts: string[], def: string) => {
  const q = new URLSearchParams(location.search).get('p')
  return q && opts.includes(q) ? q : def
}

export default function ProjectView({ id, tab: rawTab }: { id: string; tab: string }) {
  const { loading, project, ds, update } = useProject(id)
  const tab = (TABS.some(t => t[0] === rawTab) ? rawTab : 'overview') as Tab
  const opts = useMemo(() => periodOptions(ds), [ds])
  const def = useMemo(() => defaultPeriod(ds), [ds])
  const period = periodFromUrl(opts, def)
  const x = useAnalysis(ds, project, period)
  const [help, setHelp] = useState(false)

  useEffect(() => { if (project) document.title = `${project.domain} · DMARC Desk` }, [project?.domain])

  const q = period === def ? '' : `?p=${period}`
  const setTab = (t: Tab) => go(`/app/p/${id}${t === 'overview' ? '' : '/' + t}${q}`, { keepScroll: true })
  const setPeriod = (p: string) => go(`${location.pathname}?p=${p}`, { replace: true, keepScroll: true })

  const saveSnapshot = () => {
    if (!project || !ds?.length || !x) return
    const week = period === 'all' ? opts[1] : period
    if (!week) return
    const prev = project.snapshots.find(s => s.period === week)
    const snap = snapshot(ds, x.opts, week, uuid())
    void update({ snapshots: [...project.snapshots.filter(s => s.period !== week), snap].sort((a, b) => a.period.localeCompare(b.period)) })
    toast(prev ? `Updated the ${fmtPeriod(week).toLowerCase()} snapshot` : `Saved a snapshot of the ${fmtPeriod(week).toLowerCase()}`, { tone: 'ok', undo: () => void update({ snapshots: project.snapshots }) })
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e) || e.metaKey || e.ctrlKey || e.altKey || document.querySelector('dialog[open]')) return
      const n = Number(e.key)
      if (n >= 1 && n <= TABS.length) { e.preventDefault(); setTab(TABS[n - 1][0]) }
      else if (e.key === '?') setHelp(true)
      else if (e.key === 's') saveSnapshot()
      else if (e.key === 'p') go(`/app/p/${id}/report${q}`)
      else if (e.key === '[' || e.key === ']') {
        const i = opts.indexOf(period)
        const j = e.key === '[' ? i + 1 : i - 1
        if (opts[j]) setPeriod(opts[j])
      }
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  })

  if (loading) return <div className="boot" role="status"><span className="spinner" /> Reading reports</div>
  if (!project || !ds || !x) return (
    <section className="page narrow center">
      <Empty title="Domain not found"><p className="muted">It may have been deleted, or it lives on another device.</p><Link href="/app" className="btn primary">All domains</Link></Empty>
    </section>
  )
  const empty = !ds.length
  const showData = tab === 'data' || (empty && NEEDS_DATA.includes(tab))
  const props: TabProps = { project, ds, period, x, update }

  return (
    <section className="page">
      <div className="proj-head">
        <div>
          <div className="eyebrow"><Link href="/app">Domains</Link></div>
          <h1 className="row gap wrap">{project.name} {project.sampleId && <SyntheticBadge />}</h1>
          <p className="muted small" style={{ margin: 0 }}><code>{project.domain}</code>{!empty && <> · {fmtN(x.a.total)} messages · {x.a.reports} reports · {fmtPeriod(period)}</>}</p>
        </div>
        {!empty && (
          <div className="toolbar">
            <label className="sr-only" htmlFor="period">Period</label>
            <select id="period" value={period} onChange={e => setPeriod(e.target.value)}>
              {opts.map(p => <option key={p} value={p}>{fmtPeriod(p)}</option>)}
            </select>
            <button type="button" className="btn outline" onClick={saveSnapshot} title="Save a snapshot of this week (S)">Save snapshot</button>
            <Link href={`/app/p/${id}/report${q}`} className="btn primary" title="Printable report (P)">Report</Link>
          </div>
        )}
      </div>
      <nav className="tabs" aria-label="Domain sections">
        {TABS.map(([t, l], i) => <Link key={t} href={`/app/p/${id}${t === 'overview' ? '' : '/' + t}${q}`} aria-current={t === tab ? 'page' : undefined} title={`${l} (${i + 1})`}>{l}</Link>)}
      </nav>
      <Suspense fallback={<div className="boot"><span className="spinner" /></div>}>
        {showData ? <DataTab {...props} />
          : tab === 'overview' ? <Overview {...props} />
            : tab === 'senders' ? <Senders {...props} />
              : tab === 'dns' ? <DnsTab {...props} />
                : tab === 'records' ? <Records {...props} />
                  : tab === 'rollout' ? <Rollout {...props} />
                    : <History {...props} />}
      </Suspense>
      <Modal open={help} onClose={() => setHelp(false)} title="Keyboard shortcuts">
        <Shortcuts />
      </Modal>
    </section>
  )
}

export const Shortcuts = () => (
  <dl className="shortcuts">
    <div><dt><kbd>1</kbd>&ndash;<kbd>7</kbd></dt><dd>Switch sections</dd></div>
    <div><dt><kbd>[</kbd> <kbd>]</kbd></dt><dd>Older / newer week</dd></div>
    <div><dt><kbd>S</kbd></dt><dd>Save a snapshot of this week</dd></div>
    <div><dt><kbd>P</kbd></dt><dd>Open the printable report</dd></div>
    <div><dt><kbd>&#8984;</kbd>/<kbd>Ctrl</kbd> <kbd>Z</kbd></dt><dd>Undo the last delete or change</dd></div>
    <div><dt><kbd>?</kbd></dt><dd>Show these shortcuts</dd></div>
  </dl>
)
