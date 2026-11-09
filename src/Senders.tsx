import { useState } from 'react'
import type { Override, Sender, Verdict } from './engine/analyze.ts'
import { VERDICT_COLOR, VERDICT_LABEL } from './charts.tsx'
import type { TabProps } from './Project.tsx'
import { resolvePtrs } from './projectData.ts'
import { download, fmtN, fmtPct, toast } from './ui.tsx'

const csvCell = (v: string | number) => /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v)

export default function Senders({ project, ds, x, update }: TabProps) {
  const { a } = x
  const [filter, setFilter] = useState<'all' | Verdict | 'failing'>('all')
  const [open, setOpen] = useState<string | null>(a.senders[0]?.key ?? null)
  const [ptrBusy, setPtrBusy] = useState<string | null>(null)
  const list = a.senders.filter(s => filter === 'all' || (filter === 'failing' ? s.pass < s.volume && s.verdict === 'legit' : s.verdict === filter))
  const missingPtr = !project.sampleId && a.senders.some(s => s.ips.some(i => !(i.ip in project.ptr)))

  const setOverride = (s: Sender, v: Override | 'auto') => {
    const before = project.overrides
    const next = { ...before }
    if (v === 'auto') delete next[s.key]; else next[s.key] = v
    void update({ overrides: next })
    toast(v === 'auto' ? `${s.name}: back to automatic` : `${s.name} marked ${v === 'legit' ? 'legitimate' : 'unauthorized'}`, { undo: () => void update({ overrides: before }) })
  }

  const exportCsv = () => {
    const head = ['sender', 'verdict', 'messages', 'share', 'dmarc_pass', 'dkim_aligned', 'spf_aligned', 'top_ip', 'ptr', 'dkim_domains', 'spf_domains', 'fix']
    const rows = a.senders.map(s => [s.name, s.verdict, s.volume, (s.share * 100).toFixed(2) + '%', s.pass, s.dkimAligned, s.spfAligned, s.ips[0]?.ip ?? '', s.ips[0]?.ptr ?? '', Object.keys(s.dkimDomains).join(' '), Object.keys(s.spfDomains).join(' '), s.fixes[0] ?? ''])
    download(`${project.domain}-senders.csv`, [head, ...rows].map(r => r.map(csvCell).join(',')).join('\n'))
  }

  return (
    <>
      <div className="row between wrap gap" style={{ marginBottom: 14 }}>
        <div className="seg-control" role="radiogroup" aria-label="Filter senders">
          {([['all', 'All'], ['failing', 'Yours, failing'], ['legit', 'Yours'], ['forwarder', 'Forwarders'], ['suspicious', 'Unknown / spoofing']] as const).map(([k, l]) => (
            <button key={k} type="button" role="radio" aria-checked={filter === k} className={filter === k ? 'on' : ''} onClick={() => setFilter(k)}>{l}</button>
          ))}
        </div>
        <div className="row gap-sm wrap">
          {missingPtr && <button type="button" className="btn outline sm" disabled={!!ptrBusy} onClick={async () => {
            setPtrBusy('Starting')
            try { const r = await resolvePtrs(project, ds, (d, t) => setPtrBusy(`${d}/${t}`)); toast(r ? 'Reverse DNS updated; senders regrouped' : 'Nothing new to look up', { tone: 'ok' }) } catch (e) { toast(`Reverse DNS failed: ${(e as Error).message}`, { tone: 'error' }) } finally { setPtrBusy(null) }
          }}>{ptrBusy ? `Looking up ${ptrBusy}` : 'Look up reverse DNS'}</button>}
          <button type="button" className="btn ghost sm" onClick={exportCsv}>Export CSV</button>
        </div>
      </div>
      {!list.length && <p className="muted">No senders match this filter in this period.</p>}
      <div className="sender-list">
        {list.map(s => <SenderRow key={s.key} s={s} open={open === s.key} toggle={() => setOpen(open === s.key ? null : s.key)} override={project.overrides[s.key]} setOverride={v => setOverride(s, v)} />)}
      </div>
    </>
  )
}

const pct = (n: number, d: number) => d ? n / d : 0
const WHY_DKIM: Record<string, string> = { aligned: 'Aligned', unaligned: 'Signed by another domain', none: 'No signature', fail: 'Signature failed' }
const WHY_SPF: Record<string, string> = { aligned: 'Aligned', unaligned: 'Passes for another domain', none: 'No SPF result', fail: 'Fails for your domain' }

function SenderRow({ s, open, toggle, override, setOverride }: { s: Sender; open: boolean; toggle(): void; override?: Override; setOverride(v: Override | 'auto'): void }) {
  const rate = pct(s.pass, s.volume)
  return (
    <article className={`sender${open ? ' open' : ''}`}>
      <button type="button" className="sender-head" aria-expanded={open} onClick={toggle}>
        <i className="dot" style={{ background: VERDICT_COLOR[s.verdict] }} aria-hidden="true" />
        <span className="sender-name"><b>{s.name}</b><small>{VERDICT_LABEL[s.verdict]}{s.overridden ? ' (your call)' : ''}{s.esp ? ` · ${s.esp.kind}` : ''} · {s.ips.length} IP{s.ips.length > 1 ? 's' : ''}</small></span>
        <span className="sender-vol tab-nums">{fmtN(s.volume)}<small>{fmtPct(s.share, 1)}</small></span>
        <span className="sender-rate"><span className="bbar" aria-hidden="true"><span style={{ width: `${rate * 100}%`, background: 'var(--good)' }} /><span style={{ width: `${(1 - rate) * 100}%`, background: s.verdict === 'suspicious' ? 'var(--c-spoof)' : 'var(--bad)' }} /></span><small className="tab-nums">{fmtPct(rate, rate > 0.99 || rate < 0.01 ? 0 : 1)} pass</small></span>
        <span className="chev" aria-hidden="true">{open ? '−' : '+'}</span>
      </button>
      {open && (
        <div className="sender-body">
          <div className="grid-3 tight">
            <div>
              <h4>DKIM</h4>
              <ul className="why">{Object.entries(s.why.dkim).filter(([, n]) => n).map(([k, n]) => <li key={k} className={k === 'aligned' ? 'ok' : 'no'}><span>{WHY_DKIM[k]}</span><b className="tab-nums">{fmtN(n)}</b></li>)}</ul>
              {Object.keys(s.dkimDomains).length > 0 && <p className="tiny muted">d= {Object.entries(s.dkimDomains).sort((p, q) => q[1] - p[1]).map(([d]) => d).join(', ')}</p>}
            </div>
            <div>
              <h4>SPF</h4>
              <ul className="why">{Object.entries(s.why.spf).filter(([, n]) => n).map(([k, n]) => <li key={k} className={k === 'aligned' ? 'ok' : 'no'}><span>{WHY_SPF[k]}</span><b className="tab-nums">{fmtN(n)}</b></li>)}</ul>
              {Object.keys(s.spfDomains).length > 0 && <p className="tiny muted">Return-Path: {Object.entries(s.spfDomains).sort((p, q) => q[1] - p[1]).map(([d]) => d).join(', ')}</p>}
            </div>
            <div>
              <h4>What receivers did</h4>
              <ul className="why">
                <li><span>Delivered (none)</span><b className="tab-nums">{fmtN(s.disposition.none)}</b></li>
                {s.disposition.quarantine > 0 && <li className="no"><span>Quarantined</span><b className="tab-nums">{fmtN(s.disposition.quarantine)}</b></li>}
                {s.disposition.reject > 0 && <li className="no"><span>Rejected</span><b className="tab-nums">{fmtN(s.disposition.reject)}</b></li>}
              </ul>
            </div>
          </div>
          <h4>How to fix</h4>
          <ol className="fixes">{s.fixes.map((f, i) => <li key={i}>{f}</li>)}</ol>
          <div className="row between wrap gap" style={{ marginTop: 12 }}>
            <div className="ips">
              {s.ips.slice(0, 6).map(i => <span key={i.ip} className="ip-chip" title={i.ptr ?? 'No reverse DNS'}><code>{i.ip}</code>{i.ptr && <small>{i.ptr.replace(/\.$/, '')}</small>}<small className="tab-nums">{fmtN(i.count)}</small></span>)}
              {s.ips.length > 6 && <span className="muted small">+{s.ips.length - 6} more</span>}
            </div>
            <label className="row gap-sm small">
              <span className="muted">Verdict</span>
              <select value={override ?? 'auto'} onChange={e => setOverride(e.target.value as Override | 'auto')} style={{ width: 'auto' }}>
                <option value="auto">Automatic</option>
                <option value="legit">Legitimate (mine)</option>
                <option value="unauthorized">Unauthorized</option>
              </select>
            </label>
          </div>
        </div>
      )}
    </article>
  )
}
