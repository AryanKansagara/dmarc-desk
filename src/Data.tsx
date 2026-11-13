import { useMemo, useRef, useState } from 'react'
import { parseAggregate, reportKey, type Issue, type Report } from './engine/aggregate.ts'
import { isoWeek, snapshot, weeksOf } from './engine/analyze.ts'
import { orgDomain } from './engine/domain.ts'
import { sampleXml } from './engine/sample.ts'
import { unpack } from './engine/unpack.ts'
import type { TabProps } from './Project.tsx'
import { createBlankProject, resolvePtrs } from './projectData.ts'
import { getProjects, putData, saveProject, uuid, type Dataset, type Project } from './store.ts'
import { RAW_SYNC_LIMIT, useSync } from './sync.ts'
import { download, fmtDate, fmtN, go, Link, toast } from './ui.tsx'
import { storedZip } from './zipwrite.ts'

interface FileResult { file: string; entry: string; report: Report | null; issues: Issue[]; status: 'new' | 'duplicate' | 'other-domain' | 'invalid' }
interface Pending { id: string; results: FileResult[] }

export default function DataTab({ project, ds, update }: TabProps) {
  const [pending, setPending] = useState<Pending | null>(null)
  const [drag, setDrag] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [paste, setPaste] = useState('')
  const input = useRef<HTMLInputElement>(null)
  const sync = useSync()
  const rawSize = useMemo(() => project.sampleId ? 0 : JSON.stringify(ds).length, [ds, project.sampleId])

  const classify = (results: { file: string; entry: string; report: Report | null; issues: Issue[] }[]): FileResult[] => {
    const have = new Set((project.sampleId ? [] : ds).map(reportKey))
    return results.map(r => {
      if (!r.report) return { ...r, status: 'invalid' as const }
      if (orgDomain(r.report.domain) !== orgDomain(project.domain)) return { ...r, status: 'other-domain' as const }
      const k = reportKey(r.report)
      if (have.has(k)) return { ...r, status: 'duplicate' as const }
      have.add(k)
      return { ...r, status: 'new' as const }
    })
  }

  const readFiles = async (files: File[]) => {
    const out: { file: string; entry: string; report: Report | null; issues: Issue[] }[] = []
    let i = 0
    for (const f of files) {
      setBusy(`Reading ${++i} of ${files.length}: ${f.name}`)
      if (f.size > 300_000_000) { out.push({ file: f.name, entry: f.name, report: null, issues: [{ line: 0, level: 'error', msg: 'Over 300 MB; export a shorter date range.' }] }); continue }
      try {
        for (const e of await unpack(f.name, new Uint8Array(await f.arrayBuffer()))) {
          const r = parseAggregate(e.text)
          out.push({ file: f.name, entry: e.name, report: r.report, issues: r.issues })
        }
      } catch (e) { out.push({ file: f.name, entry: f.name, report: null, issues: [{ line: 0, level: 'error', msg: `Could not decompress: ${(e as Error).message}` }] }) }
    }
    setBusy(null)
    setPending({ id: uuid(), results: classify(out) })
  }

  const commit = async () => {
    if (!pending) return
    const fresh = pending.results.filter(r => r.status === 'new').map(r => r.report!)
    if (!fresh.length) { toast('Nothing new to import', { tone: 'error' }); return }
    // Samples are read-only: importing into one starts a new domain.
    const target: Project = project.sampleId ? await createBlankProject(fresh[0].domain) : project
    const before = { ds: project.sampleId ? [] : ds, imports: target.imports, snapshots: target.snapshots }
    const src = uuid()
    const merged: Dataset = [...before.ds, ...fresh.map(r => ({ ...r, src }))].sort((a, b) => a.begin - b.begin)
    await putData(target.id, merged)
    const opts = { domain: target.domain, overrides: target.overrides, ptr: target.ptr }
    const weeks = new Set(fresh.map(r => isoWeek(r.begin)))
    const snaps = [...target.snapshots.filter(s => !weeks.has(s.period)), ...[...weeks].map(w => snapshot(merged, opts, w, uuid()))].sort((a, b) => a.period.localeCompare(b.period))
    const meta = { id: src, fileName: pending.results.length === 1 ? pending.results[0].entry : `${new Set(pending.results.map(r => r.file)).size} files`, reports: fresh.length, rows: fresh.reduce((s, r) => s + r.rows.length, 0), messages: fresh.reduce((s, r) => s + r.rows.reduce((t, x) => t + x.count, 0), 0), skipped: pending.results.length - fresh.length, at: Date.now() }
    const saved = await saveProject({ ...target, imports: [...target.imports, meta], snapshots: snaps, dataMissing: false })
    setPending(null)
    toast(`Imported ${fresh.length} report${fresh.length > 1 ? 's' : ''} (${fmtN(meta.messages)} message${meta.messages === 1 ? '' : 's'})`, {
      tone: 'ok', undo: async () => { await putData(target.id, before.ds); await saveProject({ ...(getProjects().find(p => p.id === target.id) ?? saved), imports: before.imports, snapshots: before.snapshots }) },
    })
    void resolvePtrs(saved, merged).catch(() => null)
    go(`/app/p/${target.id}`)
  }

  const removeImport = async (id: string) => {
    const keep = ds.filter(r => r.src !== id)
    const before = { ds, imports: project.imports, snapshots: project.snapshots }
    await putData(project.id, keep)
    const opts = { domain: project.domain, overrides: project.overrides, ptr: project.ptr }
    const kept = new Set(weeksOf(keep))
    await update({ imports: project.imports.filter(i => i.id !== id), snapshots: [...project.snapshots.filter(s => kept.has(s.period)).map(s => snapshot(keep, opts, s.period, s.id))] })
    toast('Import removed', { undo: async () => { await putData(project.id, before.ds); await update({ imports: before.imports, snapshots: before.snapshots }) } })
  }

  const counts = pending ? pending.results.reduce((c, r) => ({ ...c, [r.status]: c[r.status] + 1 }), { new: 0, duplicate: 0, 'other-domain': 0, invalid: 0 }) : null
  const issues = pending ? pending.results.flatMap(r => r.issues.map(i => ({ ...i, entry: r.entry }))) : []

  return (
    <>
      {project.dataMissing && <div className="banner warn"><span><strong>This domain&rsquo;s raw reports are on another device.</strong> Sender decisions, DNS results and snapshots synced; report sets over {(RAW_SYNC_LIMIT / 1e6).toFixed(0)} MB stay where they were imported. Re-import here to recompute.</span></div>}
      {project.sampleId && <div className="banner"><span>This is a synthetic sample. Importing files here starts a new domain from them. Want to try the import? Download the sample reports, then drop the .zip below.</span><button type="button" className="btn ghost sm" onClick={() => download(`${project.domain}-synthetic-dmarc-reports.zip`, storedZip(sampleXml(project.sampleId!).slice(0, 63).map(f => ({ name: f.name, text: f.xml }))))}>Download sample .zip</button></div>}
      {!ds.length && !pending && (
        <div className="panel tint">
          <h2>Import aggregate reports for {project.domain}</h2>
          <p className="muted">Receivers like Google, Microsoft and Yahoo email one report per day to the address in your DMARC <code>rua=</code> tag, as <code>.xml.gz</code> or <code>.zip</code> attachments. Drop the attachments here, hundreds at once is fine, or skip saving them and drop the emails themselves (<code>.eml</code>) or a whole Google Takeout <code>.mbox</code>. <Link href="/docs#get-reports">How to get them out of Gmail or Outlook</Link>.</p>
          <p className="muted small">No reports yet? The DNS check and generated records work without them. Publish a DMARC record with rua= first (see Records), then come back in two days.</p>
        </div>
      )}
      <div className={`drop${drag ? ' over' : ''}`} onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
        onDrop={e => { e.preventDefault(); setDrag(false); void readFiles([...e.dataTransfer.files]) }} onClick={() => input.current?.click()} role="button" tabIndex={0}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.current?.click() } }} aria-label="Choose report files">
        <h3>{busy ?? 'Drop .xml, .xml.gz, .zip, .eml or .mbox files'}</h3>
        <p className="muted small" style={{ margin: 0 }}>or click to choose files. Decompressed and parsed in your browser; nothing is uploaded.</p>
        <input ref={input} type="file" multiple accept=".xml,.gz,.zip,.eml,.mbox,application/xml,text/xml,application/gzip,application/zip,message/rfc822,application/mbox" hidden onChange={e => { if (e.target.files) void readFiles([...e.target.files]); e.target.value = '' }} />
      </div>
      <details className="paste">
        <summary>Paste report XML instead</summary>
        <textarea rows={6} value={paste} onChange={e => setPaste(e.target.value)} placeholder="<?xml version=&quot;1.0&quot;?><feedback>..." aria-label="Report XML" />
        <button type="button" className="btn ghost sm" disabled={!paste.trim()} onClick={() => { const r = parseAggregate(paste); setPending({ id: uuid(), results: classify([{ file: 'pasted', entry: 'pasted XML', report: r.report, issues: r.issues }]) }); setPaste('') }}>Validate</button>
      </details>

      {pending && counts && (
        <div className="panel validation">
          <div className="panel-head"><h2>Validation report</h2><span className="muted small">{pending.results.length} report file{pending.results.length > 1 ? 's' : ''} found</span></div>
          <div className="kpis">
            <div className="kpi"><small>New reports</small><b className="good-text">{counts.new}</b></div>
            <div className="kpi"><small>Already imported</small><b>{counts.duplicate}</b></div>
            <div className="kpi"><small>Other domain</small><b>{counts['other-domain']}</b><p>not {orgDomain(project.domain)}</p></div>
            <div className="kpi"><small>Unreadable</small><b className={counts.invalid ? 'error' : ''}>{counts.invalid}</b></div>
          </div>
          {issues.length > 0 && <div className="issues" role="list">{issues.slice(0, 300).map((i, k) => <div key={k} role="listitem" className={i.level === 'error' ? 'error-row' : ''}><span className="ln">{i.line ? `line ${i.line}` : '—'}</span><span className="muted small">{i.entry}</span><span>{i.msg}</span></div>)}{issues.length > 300 && <div className="muted">{issues.length - 300} more</div>}</div>}
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead><tr><th>Report</th><th>Receiver</th><th>Day</th><th className="num">Rows</th><th className="num">Messages</th><th>Status</th></tr></thead>
              <tbody>{pending.results.slice(0, 60).map((r, i) => <tr key={i}><td className="small break">{r.entry}</td><td>{r.report?.org ?? '—'}</td><td className="small">{r.report ? fmtDate(r.report.begin) : '—'}</td><td className="num">{r.report?.rows.length ?? 0}</td><td className="num">{fmtN(r.report?.rows.reduce((s, x) => s + x.count, 0) ?? 0)}</td><td><span className={`badge st-${r.status}`}>{r.status === 'other-domain' ? r.report!.domain : r.status}</span></td></tr>)}</tbody>
            </table>
            {pending.results.length > 60 && <p className="muted small">and {pending.results.length - 60} more</p>}
          </div>
          <div className="row end gap" style={{ marginTop: 14 }}>
            <button type="button" className="btn ghost" onClick={() => setPending(null)}>Cancel</button>
            <button type="button" className="btn primary" disabled={!counts.new} onClick={() => void commit()}>Import {counts.new} report{counts.new === 1 ? '' : 's'}</button>
          </div>
        </div>
      )}

      {project.imports.length > 0 && (
        <div className="panel">
          <div className="panel-head"><h2>Imports</h2><span className="muted small">{fmtN(ds.length)} reports on this device{rawSize ? ` · ${(rawSize / 1e6).toFixed(1)} MB` : ''}</span></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Source</th><th className="num">Reports</th><th className="num">Messages</th><th className="num">Skipped</th><th>When</th><th /></tr></thead>
              <tbody>{[...project.imports].reverse().map(i => <tr key={i.id}><td className="small break">{i.fileName}</td><td className="num">{fmtN(i.reports)}</td><td className="num">{fmtN(i.messages)}</td><td className="num">{i.skipped}</td><td className="small muted">{new Date(i.at).toLocaleString()}</td><td className="num">{!project.sampleId && <button type="button" className="btn danger-ghost sm" onClick={() => void removeImport(i.id)}>Remove</button>}</td></tr>)}</tbody>
            </table>
          </div>
          {sync.user && !project.sampleId && <p className="small muted">{rawSize > RAW_SYNC_LIMIT ? `Reports are ${(rawSize / 1e6).toFixed(1)} MB, over the ${(RAW_SYNC_LIMIT / 1e6).toFixed(0)} MB sync cap: they stay on this device. Sender decisions, DNS results and snapshots still sync.` : 'Reports, sender decisions, DNS results and snapshots sync to your account.'}</p>}
        </div>
      )}
    </>
  )
}
