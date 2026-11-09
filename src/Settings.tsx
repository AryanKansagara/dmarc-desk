import { useState } from 'react'
import { Shortcuts } from './Project.tsx'
import { deleteProject, getDefaults, getProjects, setDefaults, type Defaults } from './store.ts'
import { exportAll, RAW_SYNC_LIMIT, useSync } from './sync.ts'
import { ask, download, setTheme, toast, useDark } from './ui.tsx'

export default function Settings() {
  const [d, setD] = useState<Defaults>(getDefaults)
  const dark = useDark()
  const sync = useSync()
  const save = (p: Partial<Defaults>) => { const next = { ...d, ...p }; setD(next); setDefaults(next); toast('Saved', { tone: 'ok', ttl: 1500 }) }

  return (
    <section className="page narrow settings">
      <div className="eyebrow">Settings</div>
      <h1>Settings</h1>

      <div className="panel">
        <h2>Defaults for new domains</h2>
        <p className="muted small">Existing domains keep their own values (Records and Rollout tabs).</p>
        <div className="inline-fields">
          <label className="field"><span>Report mailbox name</span><input value={d.ruaLocal} onChange={e => save({ ruaLocal: e.target.value.replace(/[^\w.+-]/g, '') || 'dmarc' })} /></label>
          <label className="field"><span>Readiness target (%)</span><input type="number" min="90" max="100" step="0.5" value={Math.round(d.threshold * 1000) / 10} onChange={e => save({ threshold: Math.min(1, Math.max(0.9, Number(e.target.value) / 100)) })} /></label>
        </div>
        <label className="field"><span>Extra DKIM selectors to check on every domain</span><input value={d.selectors} placeholder="comma separated, e.g. mg, sel2025" onChange={e => save({ selectors: e.target.value })} /></label>
      </div>

      <div className="panel">
        <h2>Appearance</h2>
        <div className="seg-control" role="radiogroup" aria-label="Theme">
          <button type="button" role="radio" aria-checked={!dark} className={!dark ? 'on' : ''} onClick={() => setTheme('light')}>Light</button>
          <button type="button" role="radio" aria-checked={dark} className={dark ? 'on' : ''} onClick={() => setTheme('dark')}>Dark</button>
        </div>
      </div>

      <div className="panel">
        <h2>Your data</h2>
        <p>Domains live in this browser (IndexedDB). {sync.user ? <>Signed in as <b>{sync.user.email}</b>: sender decisions, DNS results, snapshots and report sets under {(RAW_SYNC_LIMIT / 1e6).toFixed(0)} MB per domain sync to your account.</> : 'Sign in from the account menu (top right) to sync across devices. It is optional.'}</p>
        <div className="row gap wrap">
          <button type="button" className="btn ghost" onClick={async () => download(`dmarc-desk-export-${new Date().toISOString().slice(0, 10)}.json`, await exportAll())}>Export all my data (JSON)</button>
          <button type="button" className="btn danger-ghost" onClick={async () => {
            const list = getProjects()
            if (!list.length) { toast('Nothing to delete'); return }
            if (!(await ask('Delete all local domains?', `Removes ${list.length} domain${list.length > 1 ? 's' : ''} from this browser${sync.user ? ' and from your cloud account' : ''}. You can undo for a few seconds.`, 'Delete everything'))) return
            const undos = await Promise.all(list.map(p => deleteProject(p.id)))
            toast(`Deleted ${list.length} domains`, { undo: () => { for (const u of undos) void u() } })
          }}>Delete all domains</button>
        </div>
      </div>

      <div className="panel">
        <h2>Keyboard shortcuts</h2>
        <Shortcuts />
      </div>
    </section>
  )
}
