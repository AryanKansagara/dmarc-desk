import { useEffect, useState } from 'react'
import type { DomainCheck, Section } from './engine/checks.ts'
import type { SpfNode } from './engine/spf.ts'
import type { TabProps } from './Project.tsx'
import { runDnsCheck } from './projectData.ts'
import { Code, fmtDate, toast } from './ui.tsx'

const ICON: Record<Section['status'], string> = { pass: '✓', warn: '!', fail: '×', info: 'i' }

export function GradeCard({ check, compact = false }: { check: DomainCheck; compact?: boolean }) {
  return (
    <div className={`grade-card${compact ? ' compact' : ''}`}>
      <div className="grade-top">
        <div className={`grade-letter g-${check.grade}`} aria-label={`Grade ${check.grade}`}>{check.grade}</div>
        <div className="grade-meta">
          <code className="grade-domain">{check.domain}</code>
          <div className="small muted">{check.score}/100 · via {check.via} DNS-over-HTTPS</div>
          {check.capped && <div className="small warn-text">{check.capped}</div>}
        </div>
      </div>
      <ul className="checks">
        {check.sections.map(s => (
          <li key={s.id} className={`st-${s.status}`}>
            <span className="st" aria-label={s.status}>{ICON[s.status]}</span>
            <span className="ck-title">{s.title}</span>
            <span className="ck-sum">{s.summary}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function SpfTree({ n, depth = 0 }: { n: SpfNode; depth?: number }) {
  return (
    <li>
      <div className="spf-node"><code>{n.domain}</code> <span className="muted small">{n.error ? n.error : `${n.totalLookups + (depth ? 1 : 0)} lookup${n.totalLookups + (depth ? 1 : 0) === 1 ? '' : 's'}${n.ip4.length + n.ip6.length ? ` · ${n.ip4.length + n.ip6.length} ranges` : ''}`}</span></div>
      {n.children.length > 0 && <ul>{n.children.map(c => <SpfTree key={c.domain} n={c} depth={depth + 1} />)}</ul>}
    </li>
  )
}

export default function DnsTab({ project, update }: TabProps) {
  const [busy, setBusy] = useState(false)
  const [sel, setSel] = useState(project.selectors.join(', '))
  const c = project.dns
  const run = async () => {
    setBusy(true)
    try { await runDnsCheck(project) } catch (e) { toast(`DNS check failed: ${(e as Error).message}. Your network may block DNS-over-HTTPS.`, { tone: 'error' }) } finally { setBusy(false) }
  }
  useEffect(() => { if (!c && !busy) void run() }, [project.id])

  return (
    <>
      <div className="row between wrap gap" style={{ marginBottom: 16 }}>
        <p className="muted small" style={{ margin: 0 }}>{project.sampleId ? 'Sample domain: checks run against a synthetic zone that matches its reports.' : 'Live lookups from your browser over DNS-over-HTTPS (Cloudflare 1.1.1.1, Google 8.8.8.8 as fallback).'}{c && <> Last checked {fmtDate(c.at)} {new Date(c.at).toLocaleTimeString()}.</>}</p>
        <button type="button" className="btn primary sm" disabled={busy} onClick={run}>{busy ? 'Checking' : c ? 'Check again' : 'Run check'}</button>
      </div>
      {!c ? <div className="boot"><span className="spinner" /> Querying DNS for {project.domain}</div> : (
        <div className="dns-layout">
          <aside><div className="panel corners"><GradeCard check={c} /></div>
            <form className="panel" onSubmit={e => { e.preventDefault(); void update({ selectors: sel.split(/[\s,]+/).filter(Boolean) })?.then(p => p && runDnsCheck(p)) }}>
              <label className="field"><span>Extra DKIM selectors</span><input value={sel} onChange={e => setSel(e.target.value)} placeholder="e.g. 20240101pm, mg, sel2025" /></label>
              <p className="tiny muted">We try {36} common selectors plus any your reports show. Postmark, SES and some others use generated selectors: copy them from the provider.</p>
              <button className="btn ghost sm">Save and re-check</button>
            </form>
          </aside>
          <div>
            {c.sections.map(s => (
              <div key={s.id} className={`panel check-panel st-${s.status}`}>
                <div className="panel-head"><h2><span className="st" aria-hidden="true">{ICON[s.status]}</span> {s.title}</h2><span className="small muted">{s.summary} · {s.points}/{s.max}</span></div>
                {s.record && <Code code={s.record} label={s.id === 'spf' ? `TXT ${c.domain}` : s.id === 'dmarc' ? `TXT _dmarc.${c.domain}` : s.id === 'mta-sts' ? `TXT _mta-sts.${c.domain}` : s.id === 'tls-rpt' ? `TXT _smtp._tls.${c.domain}` : `TXT default._bimi.${c.domain}`} />}
                {s.id === 'spf' && c.spf.tree && c.spf.tree.children.length > 0 && <details className="spf-tree"><summary>Include tree ({c.spf.lookups} lookups)</summary><ul><SpfTree n={c.spf.tree} /></ul></details>}
                {s.id === 'dkim' && c.dkim.length > 0 && <div className="table-wrap"><table><thead><tr><th>Selector</th><th>Type</th><th>Key</th><th>Status</th></tr></thead><tbody>{c.dkim.map(k => <tr key={k.selector}><td><code>{k.selector}._domainkey</code></td><td>{k.keyType}</td><td>{k.bits ? `${k.bits}-bit` : '—'}</td><td>{k.revoked ? 'revoked' : k.testing ? 'testing' : 'active'}</td></tr>)}</tbody></table></div>}
                {s.details.length > 0 && <ul className="details">{s.details.map((d, i) => <li key={i} className={d.startsWith('Error') ? 'error' : d.startsWith('Warning') ? 'warn-text' : ''}>{d}</li>)}</ul>}
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  )
}
