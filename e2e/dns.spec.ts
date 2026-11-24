import type { Page } from '@playwright/test'
import { addDomain, expect, openTab, test, toastText } from './fixtures.ts'

const KEY = 'v=DKIM1; k=rsa; p=' + 'A'.repeat(400) // a 2048-bit-sized key

// A domain that is nearly done: enforcing DMARC, one DKIM key, MTA-STS enforced, TLS-RPT, BIMI, DNSSEC.
const STRONG = {
  'strong.test': { MX: ['10 aspmx.l.google.com.'], TXT: ['v=spf1 include:_spf.google.com -all'] },
  '_spf.google.com': { TXT: ['v=spf1 ip4:35.190.247.0/24 ~all'] },
  '_dmarc.strong.test': { TXT: ['v=DMARC1; p=reject; rua=mailto:dmarc@strong.test'] },
  'google._domainkey.strong.test': { TXT: [KEY] },
  '_mta-sts.strong.test': { TXT: ['v=STSv1; id=20260101'] },
  '_smtp._tls.strong.test': { TXT: ['v=TLSRPTv1; rua=mailto:tls@strong.test'] },
  'default._bimi.strong.test': { TXT: ['v=BIMI1; l=https://strong.test/logo.svg'] },
}
const STRONG_POLICY = 'version: STSv1\nmode: enforce\nmx: aspmx.l.google.com\nmax_age: 604800\n'

// A domain in mid-rollout: two SPF includes, DMARC at quarantine 50%, one DKIM key. Grade C, 65/100.
const midway = (d: string) => ({
  [d]: { MX: ['10 aspmx.l.google.com.'], TXT: ['v=spf1 include:_spf.google.com include:spf.vendor.test -all'] },
  '_spf.google.com': { TXT: ['v=spf1 ip4:35.190.247.0/24 ~all'] },
  'spf.vendor.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 ~all'] },
  [`_dmarc.${d}`]: { TXT: [`v=DMARC1; p=quarantine; pct=50; rua=mailto:d@${d}`] },
  [`google._domainkey.${d}`]: { TXT: [KEY] },
})
const MIDWAY = midway('midway.test')

const check = (page: Page, title: string) => page.locator('.check-panel', { has: page.getByRole('heading', { name: new RegExp(`${title}$`) }) })
const row = (page: Page, title: string) => page.locator('.grade-card .checks li', { hasText: title })
const grade = (page: Page) => page.locator('.grade-card .grade-letter')

test.describe('live DNS grading, against stubbed DNS-over-HTTPS', () => {
  test('a domain with everything in place grades A, record by record', async ({ page, dns }) => {
    dns.set(STRONG).signed.add('strong.test')
    dns.policies['strong.test'] = STRONG_POLICY
    await addDomain(page, 'strong.test')

    await expect(grade(page)).toHaveText('A')
    await expect(page.locator('.grade-card .grade-meta')).toContainText('100/100 · via Cloudflare DNS-over-HTTPS')
    for (const [title, summary] of [
      ['MX', '1 mail server (Google Workspace)'],
      ['SPF', '1/10 lookups, -all'],
      ['DMARC', 'p=reject, reports on'],
      ['DKIM', '1 key: google (2048-bit)'],
      ['MTA-STS', 'mode: enforce'],
      ['TLS-RPT', 'Reporting on'],
      ['DNSSEC', 'Signed and validated (AD flag set)'],
      ['BIMI', 'Logo record published'],
    ]) {
      await expect(row(page, title), title).toHaveClass(/st-pass/)
      await expect(row(page, title), title).toContainText(summary)
    }
    await expect(check(page, 'DMARC')).toContainText('v=DMARC1; p=reject; rua=mailto:dmarc@strong.test')
    await expect(check(page, 'MTA-STS')).toContainText('mode: enforce')
    expect(dns.asked('_dmarc.strong.test', 'TXT')).toBe(true)
    expect(dns.asked('google._domainkey.strong.test', 'TXT')).toBe(true)
  })

  test('a domain mid-rollout gets findings, not just a letter', async ({ page, dns }) => {
    dns.set(MIDWAY)
    await addDomain(page, 'midway.test')

    await expect(grade(page)).toHaveText('C')
    await expect(page.locator('.grade-card .grade-meta')).toContainText('65/100')
    await expect(row(page, 'DMARC')).toContainText('p=quarantine pct=50, reports on')
    await expect(row(page, 'MTA-STS')).toHaveClass(/st-info/)
    await expect(check(page, 'DMARC')).toContainText('pct=50: the policy applies to 50% of failing mail')
    await expect(check(page, 'SPF')).toContainText('v=spf1 include:_spf.google.com include:spf.vendor.test -all')
    await page.getByText('Include tree (2 lookups)').click()
    await expect(check(page, 'SPF').locator('.spf-tree')).toContainText('spf.vendor.test')
  })

  test('a name that genuinely does not exist is graded as a missing record', async ({ page, dns }) => {
    const { ['_dmarc.midway.test']: _, ...zone } = MIDWAY
    dns.set(zone)
    await addDomain(page, 'midway.test')

    await expect(row(page, 'DMARC')).toHaveClass(/st-fail/)
    await expect(row(page, 'DMARC')).toContainText('Missing')
    await expect(grade(page)).toHaveText('F')
    await expect(page.locator('.grade-card .grade-meta')).toContainText('45/100')
    await expect(check(page, 'DMARC')).toContainText('No record at _dmarc.midway.test')
  })

  test('a failed DMARC lookup is not graded as a missing DMARC record; run again once DNS answers', async ({ page, dns }) => {
    dns.set(MIDWAY).failing('_dmarc.midway.test')
    await addDomain(page, 'midway.test')
    await expect(toastText(page).first()).toContainText('DNS check failed')

    await expect(grade(page)).toHaveCount(0)
    await expect(page.getByText('No record at _dmarc.midway.test')).toHaveCount(0)
    await expect(page.getByText('Missing')).toHaveCount(0)

    await expect(page.getByRole('button', { name: 'Run check' })).toBeEnabled()
    dns.fail.clear()
    await page.getByRole('button', { name: 'Run check' }).click()
    await expect(grade(page)).toHaveText('C')
    await expect(row(page, 'DMARC')).toContainText('p=quarantine pct=50')
  })

  test('a failed MX lookup is not graded as "No MX records"', async ({ page, dns }) => {
    dns.set(MIDWAY).failing('midway.test MX')
    await addDomain(page, 'midway.test')
    await expect(toastText(page).first()).toContainText('DNS check failed')
    await expect(grade(page)).toHaveCount(0)
    await expect(page.getByText('No MX records')).toHaveCount(0)
  })

  test('your own DKIM selectors are looked up and shown', async ({ page, dns }) => {
    dns.set({ ...MIDWAY, 'custom1._domainkey.midway.test': { TXT: ['v=DKIM1; k=ed25519; p=' + 'B'.repeat(43)] } })
    await addDomain(page, 'midway.test')
    await expect(row(page, 'DKIM')).toContainText('1 key: google (2048-bit)')
    expect(dns.asked('custom1._domainkey.midway.test', 'TXT')).toBe(false)

    await page.getByLabel('Extra DKIM selectors').fill('custom1')
    await page.getByRole('button', { name: 'Save and re-check' }).click()
    await expect(row(page, 'DKIM')).toContainText('2 keys: custom1 (256-bit), google (2048-bit)')
    expect(dns.asked('custom1._domainkey.midway.test', 'TXT')).toBe(true)

    // The selector is remembered for the domain.
    await page.reload()
    await expect(page.getByLabel('Extra DKIM selectors')).toHaveValue('custom1')
  })

  test('the sample domain is graded from its own synthetic zone, without any DNS request', async ({ page, dns }) => {
    await page.goto('/app?sample=northwind')
    await openTab(page, 'DNS check')
    await expect(grade(page)).toBeVisible()
    await expect(page.locator('.grade-card .grade-meta')).toContainText('synthetic zone, no network')
    expect(dns.queries).toEqual([])
  })

  // Known bugs, filed as issues. Each test states what the app should do and is expected to fail until it does.
  // When one is fixed this test starts passing, Playwright reports "expected to fail", and `test.fail()` goes.
  test.describe('known bug: a failed SPF lookup is graded as a missing record', () => {
    // https://github.com/AryanKansagara/dmarc-desk/issues/2
    test('the SPF record of the domain itself', async ({ page, dns }) => {
      test.fail()
      dns.set(MIDWAY).failing('midway.test TXT')
      await addDomain(page, 'midway.test')
      await expect(check(page, 'SPF')).toContainText('Lookup failed') // true today
      await expect(row(page, 'SPF')).not.toContainText('Missing')
    })

    test('an include of the record', async ({ page, dns }) => {
      test.fail()
      dns.set(MIDWAY).failing('spf.vendor.test')
      await addDomain(page, 'midway.test')
      await expect(check(page, 'SPF')).toContainText('spf.vendor.test: lookup failed') // true today
      await expect(check(page, 'SPF')).not.toContainText('has no SPF record')
    })
  })
})

test.describe('the landing page check', () => {
  test('checks a domain live, then opens it in the app', async ({ page, dns }) => {
    dns.set({ ...STRONG, ...midway('cloudflare.com') })
    await page.goto('/')
    // It starts with the first example.
    await expect(page.locator('.hero-grade .grade-domain')).toHaveText('cloudflare.com')
    await expect(page.locator('.hero-grade .grade-letter')).toHaveText('C')

    await page.getByLabel('Your domain').fill('strong.test')
    await page.getByRole('button', { name: 'Check DNS' }).click()
    await expect(page.locator('.hero-grade .grade-domain')).toHaveText('strong.test')
    await expect(page.locator('.hero-grade .grade-letter')).toHaveText('B') // DNSSEC and MTA-STS policy are not in this stub

    await page.getByRole('button', { name: /Open strong.test in the app/ }).click()
    await expect(page).toHaveURL(/\/app\/p\/[\w-]+\/dns$/)
    await expect(grade(page)).toHaveText('B')
  })

  test('a lookup failure is reported as one, not as a grade', async ({ page, dns }) => {
    dns.set(MIDWAY).failing('cloudflare.com MX')
    await page.goto('/')
    await expect(page.getByRole('alert')).toContainText('Lookup failed')
    await expect(page.getByRole('alert')).toContainText('Your network may block DNS-over-HTTPS')
    await expect(page.locator('.hero-grade .grade-letter')).toHaveCount(0)

    await page.getByLabel('Your domain').fill('midway.test')
    await page.getByRole('button', { name: 'Check DNS' }).click()
    await expect(page.locator('.hero-grade .grade-letter')).toHaveText('C')
    await expect(page.getByRole('alert')).toHaveCount(0)
  })

  test('something that is not a domain is rejected before any lookup', async ({ page, dns }) => {
    await page.goto('/')
    await expect(page.locator('.hero-grade .grade-letter')).toBeVisible() // the default example settled
    const asked = dns.queries.length
    await page.getByLabel('Your domain').fill('not a domain')
    await page.getByRole('button', { name: 'Check DNS' }).click()
    await expect(page.getByRole('alert')).toContainText('"not a domain" is not a domain name')
    expect(dns.queries.length).toBe(asked)
  })
})
