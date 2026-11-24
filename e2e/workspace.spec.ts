import type { Page } from '@playwright/test'
import { addDomain, chooseFiles, downloaded, expect, fixtureFile, openTab, readiness, test, toastText } from './fixtures.ts'

const cards = (page: Page) => page.locator('.project-card')

test.describe('domains', () => {
  test('a domain you add is kept across a reload, can be renamed, and can be deleted with undo', async ({ page }) => {
    await addDomain(page, 'Example.COM.') // normalised
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('example.com')

    await page.goto('/app')
    await expect(cards(page)).toHaveCount(1)
    await expect(cards(page).first()).toContainText('example.com')
    await page.reload()
    await expect(cards(page)).toHaveCount(1)

    await page.getByRole('button', { name: 'Rename' }).click()
    await page.getByLabel('Display name').fill('Acme mail')
    await page.getByLabel('Display name').press('Enter')
    await expect(cards(page).first().getByRole('heading', { name: 'Acme mail' })).toBeVisible()
    await page.reload()
    await expect(cards(page).first().getByRole('heading', { name: 'Acme mail' })).toBeVisible()

    // Adding the same domain again opens the existing one rather than making a second.
    await page.getByLabel('Domain', { exact: true }).fill('example.com')
    await page.getByRole('button', { name: 'Add domain' }).click()
    await expect(page).toHaveURL(/\/dns$/)
    await page.goto('/app')
    await expect(cards(page)).toHaveCount(1)

    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete domain' }).click()
    await expect(page.getByText('Try the sample')).toBeVisible()
    await toastText(page).getByRole('button', { name: 'Undo' }).click()
    await expect(cards(page)).toHaveCount(1)

    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete domain' }).click()
    await expect(toastText(page).first()).toContainText('Deleted Acme mail') // the toast comes once the data is gone from storage
    await page.reload()
    await expect(page.getByText('Try the sample')).toBeVisible()
    await expect(cards(page)).toHaveCount(0)
  })

  test('something that is not a domain name is refused', async ({ page, dns }) => {
    await page.goto('/app')
    await page.getByLabel('Domain', { exact: true }).fill('not a domain')
    await page.getByRole('button', { name: 'Add domain' }).click()
    await expect(toastText(page).first()).toContainText('"not a domain" is not a domain name')
    await expect(page).toHaveURL(/\/app$/)
    expect(dns.queries).toEqual([])
  })

  test('imported reports and the domain they belong to are kept across a reload', async ({ page }) => {
    await addDomain(page, 'twlnet.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, fixtureFile('google-multipart-zip.eml'))
    await page.getByRole('button', { name: 'Import 1 report' }).click()
    await expect(readiness(page)).toHaveAccessibleName('Readiness 100.0%')

    await page.goto('/app')
    await expect(cards(page).first()).toContainText('twlnet.com')
    await expect(cards(page).first().locator('.mini-stats div', { hasText: 'Reports' }).locator('dd')).toHaveText('1')
    await page.reload()
    await expect(cards(page).first().locator('.mini-stats div', { hasText: 'Reports' }).locator('dd')).toHaveText('1')
    await cards(page).first().getByRole('link', { name: 'twlnet.com' }).click()
    await expect(readiness(page)).toHaveAccessibleName('Readiness 100.0%')
  })

  test('deleting all domains from Settings removes them and their reports', async ({ page }) => {
    await addDomain(page, 'twlnet.com')
    await page.goto('/settings')
    await page.getByRole('button', { name: 'Delete all domains' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete everything' }).click()
    await expect(toastText(page).first()).toContainText('Deleted 1 domains')
    await page.goto('/app')
    await expect(page.getByText('Try the sample')).toBeVisible()
  })
})

test.describe('records', () => {
  test('generated records can be copied, follow the chosen rollout stage, and the mailbox is kept', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await page.goto('/app?sample=northwind&tab=records')
    const dmarc = page.locator('.code', { hasText: 'TXT _dmarc.example.com' })
    await expect(dmarc).toContainText('v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc@example.com; fo=1')

    await dmarc.getByRole('button', { name: 'Copy' }).click()
    await expect(dmarc.getByRole('button', { name: 'Copied' })).toBeVisible()
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc@example.com; fo=1')

    await page.getByLabel('Stage').selectOption({ label: 'Reject 100%' })
    await expect(dmarc).toContainText('v=DMARC1; p=reject; rua=mailto:dmarc@example.com; fo=1')
    await page.getByLabel('Report mailbox (rua)').fill('reports@example.com')
    await page.getByLabel('Report mailbox (rua)').blur()
    await expect(dmarc).toContainText('rua=mailto:reports@example.com')

    // The zone file snippet carries the same records, quoted for BIND.
    const zone = page.locator('.code', { hasText: 'BIND' })
    await expect(zone).toContainText('_dmarc.example.com.\t3600\tIN\tTXT\t"v=DMARC1; p=reject; rua=mailto:reports@example.com; fo=1"')

    await page.reload()
    await expect(page.getByLabel('Report mailbox (rua)')).toHaveValue('reports@example.com')
  })

  test('taking an include out of the SPF builder changes the record', async ({ page }) => {
    await page.goto('/app?sample=northwind&tab=records')
    const spf = page.locator('.code', { hasText: /^TXT example\.com/ })
    await expect(spf).toContainText('include:sendgrid.net')
    await page.getByRole('button', { name: 'Remove sendgrid.net' }).click()
    await expect(spf).not.toContainText('include:sendgrid.net')
    await expect(spf).toContainText('include:servers.mcsv.net')
  })
})

test.describe('settings and data', () => {
  test('exports everything as JSON, including the imported reports', async ({ page }) => {
    await addDomain(page, 'twlnet.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, fixtureFile('google-multipart-zip.eml'))
    await page.getByRole('button', { name: 'Import 1 report' }).click()
    await expect(readiness(page)).toBeVisible()

    await page.goto('/settings')
    const file = await downloaded(page, () => page.getByRole('button', { name: 'Export all my data (JSON)' }).click())
    expect(file.name).toMatch(/^dmarc-desk-export-\d{4}-\d{2}-\d{2}\.json$/)
    const data = JSON.parse(file.text)
    expect(data.app).toBe('dmarc-desk')
    expect(data.projects).toHaveLength(1)
    expect(data.projects[0]).toMatchObject({ domain: 'twlnet.com', imports: [{ reports: 1, messages: 1 }] })
    expect(data.projects[0].dataset).toHaveLength(1)
    expect(data.projects[0].dataset[0]).toMatchObject({ org: 'google.com', domain: 'twlnet.com', id: '1627703331531660819' })
  })

  test('the theme and the defaults for new domains are kept across a reload', async ({ page }) => {
    await page.goto('/settings')
    await page.getByRole('radio', { name: 'Dark' }).click()
    await expect(page.locator('html')).toHaveAttribute('data-theme-mode', 'dark')
    await page.getByLabel('Report mailbox name').fill('rua-reports')

    await page.reload()
    await expect(page.locator('html')).toHaveAttribute('data-theme-mode', 'dark')
    await expect(page.getByRole('radio', { name: 'Dark' })).toBeChecked()
    await expect(page.getByLabel('Report mailbox name')).toHaveValue('rua-reports')

    await addDomain(page, 'example.com')
    await openTab(page, 'Records')
    await expect(page.getByLabel('Report mailbox (rua)')).toHaveValue('rua-reports@example.com')
  })
})

test.describe('routes', () => {
  test('an unknown page is a 404 with a way out', async ({ page }) => {
    await page.goto('/nope')
    await expect(page.getByRole('heading', { name: 'NXDOMAIN' })).toBeVisible()
    await page.getByRole('link', { name: 'Your domains' }).click()
    await expect(page).toHaveURL(/\/app$/)
  })

  test('a domain id that does not exist says so', async ({ page }) => {
    await page.goto('/app/p/00000000-0000-0000-0000-000000000000')
    await expect(page.getByRole('heading', { name: 'Domain not found' })).toBeVisible()
    await page.getByRole('link', { name: 'All domains' }).click()
    await expect(page).toHaveURL(/\/app$/)
  })

  test('keyboard shortcuts switch sections and open the printable report', async ({ page }) => {
    await page.goto('/app?sample=northwind')
    await expect(readiness(page)).toBeVisible()
    await page.keyboard.press('5')
    await expect(page).toHaveURL(/\/rollout$/)
    await page.keyboard.press('2')
    await expect(page).toHaveURL(/\/senders$/)
    await page.keyboard.press('p')
    await expect(page).toHaveURL(/\/report$/)
    await expect(page.getByRole('button', { name: 'Download CSV' })).toBeVisible()
  })
})
