import { readFileSync } from 'node:fs'
import { expect, test as base, type Download, type Page, type Route } from '@playwright/test'

type RRType = 'A' | 'AAAA' | 'MX' | 'TXT'
type Zone = Record<string, Partial<Record<RRType, string[]>>>

const TYPE_CODE: Record<string, number> = { A: 1, MX: 15, TXT: 16, AAAA: 28 }

/**
 * A fake DNS-over-HTTPS service for both providers the app uses (Cloudflare and Google). Names missing from
 * `zone` answer NXDOMAIN, names in `fail` answer HTTP 502 from both providers, so the app sees a failed lookup
 * rather than an empty answer.
 */
export class Dns {
  zone: Zone = {}
  /** `name` (every type) or `name TYPE` that cannot be looked up at all. */
  fail = new Set<string>()
  /** Names whose answers carry the DNSSEC "authenticated data" flag. */
  signed = new Set<string>()
  /** MTA-STS policy files by domain, served by the app's own `/api/mta-sts` proxy route. */
  policies: Record<string, string> = {}
  /** Every `name TYPE` asked for, in order. */
  queries: string[] = []

  set(zone: Zone) { this.zone = Object.fromEntries(Object.entries(zone).map(([k, v]) => [k.toLowerCase(), v])); return this }
  failing(...names: string[]) {
    for (const n of names) { const [name, type] = n.split(' '); this.fail.add(type ? `${name.toLowerCase()} ${type.toUpperCase()}` : name.toLowerCase()) }
    return this
  }
  asked(name: string, type: RRType) { return this.queries.includes(`${name.toLowerCase()} ${type}`) }

  handle(route: Route) {
    const u = new URL(route.request().url())
    const name = (u.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '')
    const type = (u.searchParams.get('type') ?? '').toUpperCase()
    this.queries.push(`${name} ${type}`)
    if (this.fail.has(name) || this.fail.has(`${name} ${type}`)) return route.fulfill({ status: 502, body: 'upstream failure' })
    const z = this.zone[name]
    if (!z) return route.fulfill({ contentType: 'application/dns-json', json: { Status: 3 } })
    const data = z[type as RRType] ?? []
    return route.fulfill({
      contentType: 'application/dns-json',
      json: { Status: 0, AD: this.signed.has(name), Answer: data.map((d) => ({ name, type: TYPE_CODE[type], TTL: 300, data: type === 'TXT' ? `"${d}"` : d })) },
    })
  }
}

/**
 * Every test gets a page that cannot reach the network. DNS-over-HTTPS, the MTA-STS proxy and Google Fonts are
 * stubbed; any other request that is not the preview server is aborted and fails the test afterwards, as does
 * any uncaught page error. Each test starts signed out with an empty browser profile.
 */
export const test = base.extend<{ dns: Dns }>({
  dns: async ({}, use) => { await use(new Dns()) },
  page: async ({ page, baseURL, dns }, use) => {
    const origin = new URL(baseURL!).origin
    const blocked: string[] = []
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))
    await page.route(/^https?:/, (route) => {
      const url = new URL(route.request().url())
      if (url.origin === origin) {
        // The app asks its own MTA-STS proxy for policy files; there is no function behind `vite preview`, so serve it here.
        if (url.pathname === '/api/mta-sts') {
          const policy = dns.policies[url.searchParams.get('domain') ?? '']
          return policy ? route.fulfill({ contentType: 'text/plain', body: policy }) : route.fulfill({ status: 404, body: 'no policy' })
        }
        return route.fallback()
      }
      if (url.hostname === 'cloudflare-dns.com' || url.hostname === 'dns.google') return dns.handle(route)
      if (url.hostname === 'fonts.googleapis.com') return route.fulfill({ contentType: 'text/css', body: '' })
      if (url.hostname === 'fonts.gstatic.com') return route.fulfill({ status: 204, body: '' })
      blocked.push(route.request().url())
      return route.abort()
    })
    await use(page)
    expect(errors, 'uncaught page errors').toEqual([])
    expect(blocked, 'requests that left the app unstubbed').toEqual([])
  },
})

export { expect }

const fixtureDir = new URL('../src/engine/fixtures/', import.meta.url)
export const fixture = (name: string) => readFileSync(new URL(name, fixtureDir))

export const MIME: Record<string, string> = { xml: 'text/xml', gz: 'application/gzip', zip: 'application/zip', eml: 'message/rfc822' }
export const reportFile = (name: string, buffer: Buffer | string) => ({ name, mimeType: MIME[name.split('.').at(-1)!] ?? 'application/octet-stream', buffer: Buffer.from(buffer) })
export const fixtureFile = (name: string) => reportFile(name, fixture(name))

export const sections = (page: Page) => page.getByRole('navigation', { name: 'Domain sections' })
export const openTab = (page: Page, name: string) => sections(page).getByRole('link', { name, exact: true }).click()
export const readiness = (page: Page) => page.getByRole('img', { name: /^Readiness \d/ })
export const toastText = (page: Page) => page.locator('.toasts .toast')

/** From the empty Domains page: add your own domain; lands on its DNS tab. */
export async function addDomain(page: Page, domain: string) {
  await page.goto('/app')
  await page.getByLabel('Domain', { exact: true }).fill(domain)
  await page.getByRole('button', { name: 'Add domain' }).click()
  await expect(page).toHaveURL(/\/app\/p\/[\w-]+\/dns$/)
}

/** Reports tab: pick files and wait for the validation report. */
export async function chooseFiles(page: Page, ...files: ReturnType<typeof reportFile>[]) {
  await page.locator('input[type=file]').setInputFiles(files)
  await expect(page.getByRole('heading', { name: 'Validation report' })).toBeVisible()
}

/** The four counters of the validation report. */
export async function validation(page: Page) {
  const kpi = (label: string) => page.locator('.validation .kpi', { has: page.getByText(label, { exact: true }) }).locator('b')
  return {
    new: Number(await kpi('New reports').textContent()),
    duplicate: Number(await kpi('Already imported').textContent()),
    otherDomain: Number(await kpi('Other domain').textContent()),
    unreadable: Number(await kpi('Unreadable').textContent()),
  }
}

/** Starts a download with `click` and returns the file's name and contents. */
export async function downloaded(page: Page, click: () => Promise<void>) {
  const [d]: [Download, void] = await Promise.all([page.waitForEvent('download'), click()])
  const body = readFileSync(await d.path())
  return { name: d.suggestedFilename(), body, text: body.toString('utf8') }
}

/** The synthetic sample's report archive, as the app offers it for download on a sample's Reports tab. */
export async function sampleZip(page: Page) {
  await page.goto('/app?sample=northwind')
  await openTab(page, 'Reports')
  const zip = await downloaded(page, () => page.getByRole('button', { name: 'Download sample .zip' }).click())
  return reportFile(zip.name, zip.body)
}
