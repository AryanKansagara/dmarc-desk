import { useEffect, useState } from 'react'
import { isDomain, normDomain } from './engine/domain.ts'
import { SAMPLES } from './engine/sample.ts'
import { createBlankProject, createSampleProject, runDnsCheck } from './projectData.ts'
import { deleteProject, getProjects, saveProject, useProjects, type Project } from './store.ts'
import { useSync } from './sync.ts'
import { ask, fmtPct, go, Link, SyntheticBadge, toast } from './ui.tsx'

export async function openDomain(raw: string) {
  const d = normDomain(raw)
  if (!isDomain(d)) { toast(`"${raw}" is not a domain name`, { tone: 'error' }); return }
  const existing = getProjects().find(p => p.domain === d && !p.sampleId)
  const p = existing ?? await createBlankProject(d)
  go(`/app/p/${p.id}/dns`)
  if (!existing) void runDnsCheck(p).catch(e => toast(`DNS check failed: ${(e as Error).message}`, { tone: 'error' }))
}

export default function Workspace() {
  const list = useProjects()
  const sync = useSync()
  const [busy, setBusy] = useState<string | null>(null)

  // /app?sample=northwind opens (or creates) the sample; /app?domain=x.com opens a domain.
  useEffect(() => {
    const q = new URLSearchParams(location.search)
    const s = q.get('sample'), dom = q.get('domain')
    const tab = q.get('tab')?.replace(/[^a-z]/g, '')
    if (list === null || busy) return
    if (s && SAMPLES.some(x => x.id === s)) {
      setBusy(s)
      void createSampleProject(s).then(p => go(`/app/p/${p.id}${tab ? '/' + tab : ''}`, { replace: true }))
    } else if (dom) { setBusy(dom); void openDomain(dom) }
  }, [list, busy])

  const openSample = async (id: string) => { setBusy(id); const p = await createSampleProject(id); go(`/app/p/${p.id}`) }

  if (list === null || busy) return <div className="boot" role="status"><span className="spinner" /> {busy ? 'Loading reports and checking DNS' : 'Opening your domains'}</div>

  const addForm = (
    <form className="domain-form" onSubmit={e => { e.preventDefault(); void openDomain(String(new FormData(e.currentTarget).get('d'))) }}>
      <label className="sr-only" htmlFor="new-domain">Domain</label>
      <input id="new-domain" name="d" placeholder="yourcompany.com" autoComplete="off" spellCheck={false} required />
      <button className="btn primary">Add domain</button>
    </form>
  )

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Domains</h1>
          <p className="muted">One workspace per sending domain. Each keeps its reports, sender decisions, DNS results and weekly snapshots. {sync.user ? 'Synced to your account.' : 'Stored on this device.'}</p>
        </div>
        {list.length > 0 && addForm}
      </div>

      {list.length === 0 ? (
        <div className="onboard">
          <article className="onboard-card feature-card corners">
            <div className="eyebrow">Two minutes</div>
            <h2>Try the sample</h2>
            <p>Six weeks of synthetic aggregate reports from Google, Microsoft and Yahoo for fictional domains, with a real-looking mess: an unaligned newsletter tool, a forwarder, a spoofing source and an SPF record over the lookup limit.</p>
            <div className="stack-sm">
              {SAMPLES.map(s => (
                <button key={s.id} type="button" className="sample-btn" onClick={() => void openSample(s.id)}>
                  <span><strong>{s.name} <code>{s.domain}</code></strong><small>{s.blurb}</small></span><span aria-hidden="true">&rarr;</span>
                </button>
              ))}
            </div>
          </article>
          <article className="onboard-card">
            <div className="eyebrow">Your domain</div>
            <h2>Check your domain and import reports</h2>
            <p>Enter your domain for a live DNS check (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC). Then drop in the aggregate reports receivers email you: <code>.xml</code>, <code>.xml.gz</code> or <code>.zip</code>, as many as you like.</p>
            {addForm}
            <div className="row gap wrap" style={{ marginTop: 14 }}>
              <Link href="/docs#get-reports" className="btn ghost sm">How to get reports</Link>
            </div>
            <p className="muted small" style={{ marginTop: 12 }}>Reports are parsed in your browser and stay on this device unless you sign in to sync.</p>
          </article>
        </div>
      ) : (
        <>
          <div className="project-grid">
            {list.map(p => <ProjectCard key={p.id} p={p} />)}
          </div>
          <div className="samples-row">
            <span className="muted small">Samples:</span>
            {SAMPLES.map(s => <button key={s.id} type="button" className="linkish small" onClick={() => void openSample(s.id)}>{s.name}</button>)}
          </div>
        </>
      )}
    </section>
  )
}

function ProjectCard({ p }: { p: Project }) {
  const [renaming, setRenaming] = useState(false)
  const last = [...p.snapshots].sort((a, b) => a.period.localeCompare(b.period)).at(-1)
  const policy = p.dns?.dmarc ? `p=${p.dns.dmarc.p ?? '?'}${p.dns.dmarc.pct < 100 ? ` ${p.dns.dmarc.pct}%` : ''}` : p.dns ? 'none' : '—'
  return (
    <article className="project-card">
      <div className="row between gap">
        {renaming ? (
          <form onSubmit={e => { e.preventDefault(); const v = String(new FormData(e.currentTarget).get('n')).trim(); if (v) void saveProject({ ...p, name: v }); setRenaming(false) }}>
            <input name="n" defaultValue={p.name} autoFocus aria-label="Display name" onBlur={e => e.currentTarget.form?.requestSubmit()} />
          </form>
        ) : <div><h3><Link href={`/app/p/${p.id}`}>{p.name}</Link></h3><code className="muted small">{p.domain}</code></div>}
        <div className="row gap-sm">{p.sampleId && <SyntheticBadge />}{p.dns && <span className={`grade-chip g-${p.dns.grade}`} title={`DNS grade ${p.dns.grade} (${p.dns.score}/100)`}>{p.dns.grade}</span>}</div>
      </div>
      <dl className="mini-stats">
        <div><dt>Policy</dt><dd className="mono">{policy}</dd></div>
        <div><dt>Readiness</dt><dd>{last && last.total ? fmtPct(last.readiness, 1) : '—'}</dd></div>
        <div><dt>Reports</dt><dd>{p.imports.reduce((s, i) => s + i.reports, 0) || '—'}</dd></div>
        <div><dt>Senders</dt><dd>{last ? last.senders.length : '—'}</dd></div>
      </dl>
      {p.dataMissing && <p className="warn-text small">The raw reports live on another device. Re-import here to recompute.</p>}
      <div className="row between">
        <span className="muted small">Updated {new Date(p.updatedAt).toLocaleDateString()}</span>
        <div className="row gap-sm">
          <button type="button" className="btn ghost sm" onClick={() => setRenaming(true)}>Rename</button>
          <button type="button" className="btn danger-ghost sm" onClick={async () => {
            if (!(await ask(`Delete “${p.name}”?`, 'Removes the domain, its reports and its snapshots from this device (and the cloud, if you are signed in). You can undo for a few seconds.', 'Delete domain'))) return
            const undo = await deleteProject(p.id)
            toast(`Deleted ${p.name}`, { undo: () => void undo() })
          }}>Delete</button>
        </div>
      </div>
    </article>
  )
}
