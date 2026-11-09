import { useEffect, useMemo, useState } from 'react'
import { generateDmarc } from './engine/dmarc.ts'
import { ESPS } from './engine/esps.ts'
import { mtaStsPolicy, stsId, stsWorker, zoneSnippet, type DnsRecord } from './engine/records.ts'
import { buildSpf, expandSpf, type SpfNode } from './engine/spf.ts'
import { STAGES } from './engine/rollout.ts'
import type { TabProps } from './Project.tsx'
import { resolverFor } from './projectData.ts'
import type { SpfPlan } from './store.ts'
import { Code, Link } from './ui.tsx'

function initialPlan(p: TabProps['project'], senders: TabProps['x']['a']['senders']): SpfPlan {
  if (p.spf) return p.spf
  const terms = p.dns?.spf.tree?.terms ?? []
  const includes = terms.filter(t => t.kind === 'include' && t.qualifier === '+').map(t => t.value.toLowerCase())
  for (const s of senders) if (s.verdict === 'legit' && s.esp?.spfInclude && !s.esp.spfInclude.includes('<') && s.why.spf.fail > 0 && !includes.includes(s.esp.spfInclude)) includes.push(s.esp.spfInclude)
  return {
    includes,
    ip4: terms.filter(t => t.kind === 'ip4').map(t => t.value),
    ip6: terms.filter(t => t.kind === 'ip6').map(t => t.value),
    mx: terms.some(t => t.kind === 'mx'), a: terms.some(t => t.kind === 'a'),
    all: p.dns?.spf.all === '-all' ? '-all' : '~all',
  }
}

export default function Records({ project, x, update }: TabProps) {
  const domain = project.domain
  const [plan, setPlanState] = useState<SpfPlan>(() => initialPlan(project, x.a.senders))
  const setPlan = (p: SpfPlan) => { setPlanState(p); void update({ spf: p }) }
  const [expanded, setExpanded] = useState<Record<string, SpfNode | undefined>>({})
  const [newInc, setNewInc] = useState('')
  const [newIp, setNewIp] = useState('')
  const cur = project.dns?.dmarc
  const curIdx = cur ? STAGES.findIndex(s => s.p === cur.p && s.pct === cur.pct) : 0
  const [stage, setStage] = useState(Math.min(STAGES.length - 1, Math.max(0, curIdx) + (cur ? 1 : 0)))
  const [rua, setRua] = useState(project.rua)

  useEffect(() => {
    let on = true
    const res = resolverFor(project)
    void Promise.all(plan.includes.filter(i => !(i in expanded)).map(async i => [i, (await expandSpf(i, res).catch(() => null))?.tree ?? undefined] as const))
      .then(r => { if (on && r.length) setExpanded(e => ({ ...e, ...Object.fromEntries(r) })) })
    return () => { on = false }
  }, [plan.includes.join(','), project.id])

  const pending = plan.includes.some(i => !(i in expanded))
  const built = useMemo(() => buildSpf({ domain, ...plan, expanded }), [plan, expanded, domain])
  const st = STAGES[stage]
  const dmarc = generateDmarc({ p: st.p, pct: st.pct, rua: rua ? rua.split(/[\s,]+/).filter(Boolean) : [], fo: '1' })
  const mx = project.dns?.mx.length ? project.dns.mx : [`mx.${domain}`]
  const policy = mtaStsPolicy(mx)
  const id = stsId(Date.now())
  const records: DnsRecord[] = [
    ...built.records.map(r => ({ host: r.host, type: 'TXT' as const, value: r.value, note: r.host === domain ? 'SPF' : 'SPF (flattened addresses)' })),
    { host: `_dmarc.${domain}`, type: 'TXT', value: dmarc, note: `DMARC (${st.title})` },
    { host: `_mta-sts.${domain}`, type: 'TXT', value: `v=STSv1; id=${id}`, note: 'MTA-STS (change id whenever the policy file changes)' },
    { host: `_smtp._tls.${domain}`, type: 'TXT', value: `v=TLSRPTv1; rua=mailto:${(rua.split(/[\s,]+/)[0] || `dmarc@${domain}`).replace(/^mailto:/, '').replace(/^[^@]+/, 'tls-reports')}`, note: 'TLS-RPT' },
  ]
  const knownIncludes = ESPS.filter(e => e.spfInclude && !e.spfInclude.includes('<')).map(e => [e.spfInclude!, e.name] as const)

  return (
    <>
      <div className="panel">
        <div className="panel-head"><h2>SPF builder</h2><span className={`small tab-nums ${built.lookups > 10 ? 'error' : built.lookups >= 9 ? 'warn-text' : 'good-text'}`}>{pending ? 'Counting lookups' : `${built.lookups}/10 lookups`}</span></div>
        <p className="muted small">Pick the services that send with your domain as the Return-Path. Services with custom DKIM and their own bounce domain (SendGrid domain authentication, SES custom MAIL FROM, Postmark Return-Path) do not need to be in your root SPF at all.</p>
        <div className="include-list">
          {plan.includes.map(i => (
            <span key={i} className="inc-chip">
              <code>include:{i}</code>
              <small className="muted">{expanded[i] ? `${expanded[i]!.totalLookups + 1} lookups` : i in expanded ? 'no record' : '…'}</small>
              {built.flattened.includes(i) && <small className="badge synthetic">flattened</small>}
              <button type="button" aria-label={`Remove ${i}`} onClick={() => setPlan({ ...plan, includes: plan.includes.filter(x => x !== i) })}>&times;</button>
            </span>
          ))}
          {[...plan.ip4.map(v => ['ip4', v] as const), ...plan.ip6.map(v => ['ip6', v] as const)].map(([k, v]) => (
            <span key={v} className="inc-chip"><code>{k}:{v}</code><button type="button" aria-label={`Remove ${v}`} onClick={() => setPlan({ ...plan, ip4: plan.ip4.filter(x => x !== v), ip6: plan.ip6.filter(x => x !== v) })}>&times;</button></span>
          ))}
        </div>
        <div className="spf-controls">
          <form onSubmit={e => { e.preventDefault(); const v = newInc.trim().replace(/^include:/, '').toLowerCase(); if (v && !plan.includes.includes(v)) setPlan({ ...plan, includes: [...plan.includes, v] }); setNewInc('') }} className="row gap-sm">
            <label className="sr-only" htmlFor="inc">Add include</label>
            <input id="inc" list="known-inc" value={newInc} onChange={e => setNewInc(e.target.value)} placeholder="Add include, e.g. _spf.google.com" />
            <datalist id="known-inc">{knownIncludes.map(([v, n]) => <option key={v} value={v}>{n}</option>)}</datalist>
            <button className="btn ghost sm">Add</button>
          </form>
          <form onSubmit={e => { e.preventDefault(); const v = newIp.trim().replace(/^ip[46]:/, ''); if (!v) return; if (v.includes(':')) setPlan({ ...plan, ip6: [...plan.ip6, v] }); else setPlan({ ...plan, ip4: [...plan.ip4, v] }); setNewIp('') }} className="row gap-sm">
            <label className="sr-only" htmlFor="ip">Add IP range</label>
            <input id="ip" value={newIp} onChange={e => setNewIp(e.target.value)} placeholder="Add IP or CIDR, e.g. 192.0.2.10" />
            <button className="btn ghost sm">Add</button>
          </form>
          <div className="row gap wrap small">
            <label className="row gap-sm"><input type="checkbox" checked={plan.mx} onChange={e => setPlan({ ...plan, mx: e.target.checked })} /> mx</label>
            <label className="row gap-sm"><input type="checkbox" checked={plan.a} onChange={e => setPlan({ ...plan, a: e.target.checked })} /> a</label>
            <div className="seg-control" role="radiogroup" aria-label="All qualifier">
              {(['~all', '-all'] as const).map(v => <button key={v} type="button" role="radio" aria-checked={plan.all === v} className={plan.all === v ? 'on' : ''} onClick={() => setPlan({ ...plan, all: v })}>{v}</button>)}
            </div>
          </div>
        </div>
        {built.records.map(r => <Code key={r.host} code={r.value} label={`TXT ${r.host}`} />)}
        {built.warnings.map((w, i) => <p key={i} className="small warn-text">{w}</p>)}
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head"><h2>DMARC</h2><Link href={`/app/p/${project.id}/rollout`} className="small">Rollout plan</Link></div>
          <div className="inline-fields">
            <label className="field"><span>Stage</span><select value={stage} onChange={e => setStage(+e.target.value)}>{STAGES.map((s, i) => <option key={s.id} value={i}>{s.title}</option>)}</select></label>
            <label className="field"><span>Report mailbox (rua)</span><input value={rua} onChange={e => setRua(e.target.value)} onBlur={() => rua !== project.rua && void update({ rua })} /></label>
          </div>
          <Code code={dmarc} label={`TXT _dmarc.${domain}`} />
          <p className="tiny muted">fo=1 asks for failure details when either SPF or DKIM fails. If the mailbox is on another domain, that domain must publish <code>{domain}._report._dmarc.&lt;its domain&gt;</code> with <code>v=DMARC1</code>.</p>
        </div>
        <div className="panel">
          <div className="panel-head"><h2>TLS-RPT</h2></div>
          <Code code={records[records.length - 1].value} label={`TXT _smtp._tls.${domain}`} />
          <p className="tiny muted">Receivers like Google and Microsoft send a daily JSON report when they cannot establish TLS to your MX.</p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><h2>MTA-STS</h2><span className="muted small">Start in testing mode; switch to enforce after two clean weeks of TLS reports</span></div>
        <div className="grid-2 tight">
          <div><Code code={`v=STSv1; id=${id}`} label={`TXT _mta-sts.${domain}`} /><Code code={policy} label={`https://mta-sts.${domain}/.well-known/mta-sts.txt`} /></div>
          <div><Code code={stsWorker(policy)} label="Cloudflare Worker (route: mta-sts.yourdomain/*)" /></div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><h2>Zone file snippet</h2><span className="muted small">Cloudflare: DNS &gt; Records &gt; Import and Export. Any BIND-compatible host works.</span></div>
        <Code code={zoneSnippet(records)} label="BIND" />
      </div>
    </>
  )
}
