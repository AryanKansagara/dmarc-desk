import { useEffect, useMemo, useState } from 'react'
import { parseAggregate, type Report } from './engine/aggregate.ts'
import { analyze, isoWeek, snapshot, weeksOf } from './engine/analyze.ts'
import { checkDomain } from './engine/checks.ts'
import { dohResolver, fakeResolver, ofType, type Resolver } from './engine/dns.ts'
import { ptrName } from './engine/domain.ts'
import { SAMPLE_PTR, SAMPLES, sampleXml, sampleZone } from './engine/sample.ts'
import { getData, getDefaults, getProjects, saveProject, useProjects, uuid, type Dataset, type Project } from './store.ts'

const sampleCache = new Map<string, Report[]>()
export function sampleReports(id: string): Report[] | null {
  if (!SAMPLES.some(s => s.id === id)) return null
  if (!sampleCache.has(id)) sampleCache.set(id, sampleXml(id).map(f => parseAggregate(f.xml).report!))
  return sampleCache.get(id)!
}

let live: Resolver | null = null
export const liveResolver = () => live ??= dohResolver()
export const resolverFor = (p: Pick<Project, 'sampleId'>): Resolver => p.sampleId ? fakeResolver(sampleZone(p.sampleId), { ad: p.sampleId === 'fieldstone' ? ['example.org', '_dmarc.example.org'] : [] }) : liveResolver()

/** MTA-STS policy files are rarely CORS-enabled, so ask our tiny proxy function first; direct fetch is the fallback for local dev. */
export async function fetchStsPolicy(domain: string): Promise<string | null> {
  try { const r = await fetch(`/api/mta-sts?domain=${encodeURIComponent(domain)}`); if (r.ok && r.headers.get('content-type')?.startsWith('text/plain')) return await r.text(); if (r.status === 404) return null } catch { /* not deployed */ }
  try { const r = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`); if (r.ok) return await r.text() } catch { /* CORS or offline */ }
  return null
}

export async function runDnsCheck(p: Project): Promise<Project> {
  const dns = await checkDomain(p.domain, resolverFor(p), {
    selectors: [...p.selectors, ...getDefaults().selectors.split(/[\s,]+/), ...selectorsSeen(p)],
    fetchPolicy: p.sampleId ? async () => 'version: STSv1\nmode: testing\nmx: example-org.mail.protection.outlook.com\nmax_age: 86400\n' : fetchStsPolicy,
  })
  if (p.sampleId) dns.via = 'Synthetic zone'
  return saveProject({ ...(getProjects().find(x => x.id === p.id) ?? p), dns })
}

/** DKIM selectors the reports show this domain using, so the DNS check finds non-standard ones. */
let seenCache: { id: string; list: string[] } | null = null
export const rememberSelectors = (id: string, ds: Dataset, domain: string) => {
  const s = new Set<string>()
  for (const r of ds) for (const row of r.rows) for (const d of row.dkim) if (d.selector && (d.domain === domain || d.domain.endsWith('.' + domain))) s.add(d.selector)
  seenCache = { id, list: [...s].slice(0, 20) }
}
const selectorsSeen = (p: Project) => seenCache?.id === p.id ? seenCache.list : []

export async function createSampleProject(sampleId: string): Promise<Project> {
  const existing = getProjects().find(p => p.sampleId === sampleId)
  if (existing) return existing
  const def = SAMPLES.find(s => s.id === sampleId)!
  const reports = sampleReports(sampleId)!
  const opts = { domain: def.domain, ptr: SAMPLE_PTR }
  const snapshots = weeksOf(reports).map(w => snapshot(reports, opts, w, uuid()))
  const now = Date.now()
  const rows = reports.reduce((s, r) => s + r.rows.length, 0)
  const p = await saveProject({
    id: uuid(), name: def.name, domain: def.domain, createdAt: now, updatedAt: now, snapshots, sampleId,
    overrides: {}, selectors: [], ptr: { ...SAMPLE_PTR }, rua: `dmarc@${def.domain}`, threshold: getDefaults().threshold,
    policySince: def.policy.p === 'none' ? Date.UTC(2026, 8, 14) : Date.UTC(2026, 9, 19),
    imports: [{ id: uuid(), fileName: 'synthetic aggregate reports (Google, Microsoft, Yahoo; Sep 21 to Nov 1 2026)', reports: reports.length, rows, messages: reports.reduce((s, r) => s + r.rows.reduce((t, x) => t + x.count, 0), 0), skipped: 0, at: now }],
  })
  return runDnsCheck(p).catch(() => p)
}

export async function createBlankProject(domain: string, name?: string): Promise<Project> {
  const now = Date.now()
  const d = getDefaults()
  return saveProject({ id: uuid(), name: name || domain, domain, createdAt: now, updatedAt: now, snapshots: [], imports: [], overrides: {}, selectors: [], ptr: {}, rua: `${d.ruaLocal}@${domain}`, threshold: d.threshold })
}

export function useProject(id: string) {
  const list = useProjects()
  const project = list?.find(p => p.id === id) ?? null
  const [ds, setDs] = useState<Dataset | null>(null)
  const importsKey = project ? project.imports.map(i => i.id).join(',') : ''
  useEffect(() => {
    if (!project) return
    let on = true
    if (project.sampleId) { setDs(sampleReports(project.sampleId) ?? []); return }
    void getData(project.id).then(d => { if (on) setDs(d ?? []) })
    return () => { on = false }
  }, [project?.id, project?.sampleId, importsKey])
  useEffect(() => { if (project && ds) rememberSelectors(project.id, ds, project.domain) }, [project?.id, ds])
  const update = (patch: Partial<Project>) => project && saveProject({ ...getProjects().find(p => p.id === project.id) ?? project, ...patch })
  return { loading: list === null || (project !== null && ds === null), project, ds, update }
}

export const periodOptions = (ds: Dataset | null) => ds?.length ? ['all', ...weeksOf(ds).reverse()] : ['all']
/** Latest week with at least 5 days of reports, else the latest week. */
export function defaultPeriod(ds: Dataset | null): string {
  if (!ds?.length) return 'all'
  const weeks = weeksOf(ds).reverse()
  const full = weeks.find(w => new Set(ds.filter(r => isoWeek(r.begin) === w).map(r => new Date(r.begin).toISOString().slice(0, 10))).size >= 5)
  return full ?? weeks[0]
}

export function useAnalysis(ds: Dataset | null, project: Project | null, period: string) {
  return useMemo(() => {
    if (!ds || !project) return null
    const opts = { domain: project.domain, overrides: project.overrides, ptr: project.ptr }
    const inPeriod = period === 'all' ? ds : ds.filter(r => isoWeek(r.begin) === period)
    const a = analyze(inPeriod, opts)
    const weekly = weeksOf(ds).map(w => { const x = analyze(ds.filter(r => isoWeek(r.begin) === w), opts); return { week: w, readiness: x.readiness, volume: x.total, pass: x.pass, legit: x.legitVolume, suspicious: x.suspiciousVolume } })
    return { a, weekly, opts }
  }, [ds, project?.domain, project?.overrides, project?.ptr, period])
}

/** Reverse DNS for source IPs not yet in the cache (max 80 per run, 6 at a time). */
export async function resolvePtrs(p: Project, ds: Dataset, onProgress?: (done: number, total: number) => void): Promise<Project | null> {
  if (p.sampleId) return null
  const counts = new Map<string, number>()
  for (const r of ds) for (const row of r.rows) counts.set(row.ip, (counts.get(row.ip) ?? 0) + row.count)
  const todo = [...counts.entries()].filter(([ip]) => !(ip in p.ptr)).sort((a, b) => b[1] - a[1]).slice(0, 80).map(([ip]) => ip)
  if (!todo.length) return null
  const res = liveResolver()
  const found: Record<string, string | null> = {}
  let done = 0
  const worker = async () => {
    while (todo.length) {
      const ip = todo.shift()!
      const name = ptrName(ip)
      try { found[ip] = name ? (ofType(await res(name, 'PTR'), 'PTR')[0] ?? null) : null } catch { /* network: retry next time */ }
      onProgress?.(++done, done + todo.length)
    }
  }
  await Promise.all(Array.from({ length: 6 }, worker))
  const cur = getProjects().find(x => x.id === p.id) ?? p
  return saveProject({ ...cur, ptr: { ...cur.ptr, ...found } })
}
