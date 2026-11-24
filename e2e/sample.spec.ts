import type { Page } from '@playwright/test'
import { downloaded, expect, openTab, readiness, sections, test, toastText } from './fixtures.ts'

// The synthetic "Northwind Coffee" workspace is generated from a fixed seed, so its numbers are exact.
// Open it the way a visitor does, from the empty Domains page.
async function openNorthwind(page: Page) {
  await page.goto('/app')
  await page.getByRole('button', { name: /Northwind Coffee/ }).click()
  await expect(page.getByRole('heading', { level: 1, name: /Northwind Coffee/ })).toBeVisible()
  await expect(readiness(page)).toBeVisible()
}

const sender = (page: Page, name: string) => page.locator('.sender-head', { hasText: new RegExp(`^\\s*${name}`) })

test.describe('sample domain', () => {
  test('shows readiness, senders and the rollout planner', async ({ page }) => {
    await openNorthwind(page)
    await expect(page.getByText('Synthetic').first()).toBeVisible()
    await expect(page.getByText('example.com · 6,251 messages · 21 reports')).toBeVisible()

    // Readiness for the latest full week.
    await expect(readiness(page)).toHaveAccessibleName('Readiness 100.0%')
    await expect(page.getByRole('heading', { name: 'Ready to tighten the policy' })).toBeVisible()
    await expect(page.locator('.kpi', { hasText: 'Unknown or spoofing' }).locator('b')).toHaveText('957')
    await expect(page.locator('.kpi', { hasText: 'Forwarded' }).locator('b')).toHaveText('154')

    // Senders: identified by service, with their own pass rates, and filterable.
    await openTab(page, 'Senders')
    await expect(sender(page, 'SendGrid')).toContainText('2,599')
    await expect(sender(page, 'Google Workspace')).toContainText('2,267')
    await expect(sender(page, 'Unknown \\(203.0.113.0/24\\)')).toContainText('0% pass')
    await expect(sender(page, 'Forwarder')).toContainText('66.2% pass')
    await page.getByRole('radio', { name: 'Unknown / spoofing' }).click()
    await expect(page.locator('.sender-head')).toHaveCount(1)
    await expect(sender(page, 'Unknown')).toBeVisible()
    await expect(sender(page, 'SendGrid')).toBeHidden()

    // Rollout: the plan starts at monitor and says what blocks the next stage.
    await openTab(page, 'Rollout')
    const stages = page.locator('.stages > li')
    await expect(stages).toHaveCount(6)
    await expect(stages.nth(0)).toContainText('Monitor')
    await expect(stages.nth(0)).toContainText('You are here')
    await expect(stages.nth(1)).toContainText('Quarantine 10%')
    await expect(stages.nth(1)).toContainText('Blocked')
    await expect(stages.nth(1)).toContainText('1 significant sender not identified')
    await expect(stages.nth(1)).toContainText('v=DMARC1; p=quarantine; pct=10;')
    await expect(stages.nth(5)).toContainText('Reject 100%')
    await expect(stages.nth(5)).toContainText('Upcoming')
  })

  test('a sender decision changes readiness and is still there after a reload', async ({ page }) => {
    await openNorthwind(page)
    await openTab(page, 'Senders')
    await sender(page, 'Unknown').click()
    await page.getByLabel('Verdict').selectOption('legit')
    await expect(toastText(page).first()).toContainText('marked legitimate')

    await openTab(page, 'Overview')
    await expect(readiness(page)).toHaveAccessibleName('Readiness 84.6%')
    await expect(page.getByRole('heading', { name: '957 legitimate messages would fail' })).toBeVisible()

    await page.reload()
    await expect(readiness(page)).toHaveAccessibleName('Readiness 84.6%')
    await expect(page.getByRole('heading', { name: '957 legitimate messages would fail' })).toBeVisible()
  })

  test('the period selector and the report page follow the chosen week, and the CSV matches', async ({ page }) => {
    await openNorthwind(page)
    await page.getByLabel('Period').selectOption({ label: 'Week of Oct 5, 2026' })
    await expect(page.getByText('example.com · 6,256 messages')).toBeVisible()
    await expect(readiness(page)).toHaveAccessibleName('Readiness 50.1%')

    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(page.getByRole('button', { name: 'Download CSV' })).toBeVisible()
    const csv = await downloaded(page, () => page.getByRole('button', { name: 'Download CSV' }).click())
    expect(csv.name).toBe('example.com-senders-2026-W41.csv')
    const [head, ...rows] = csv.text.split('\n')
    expect(head).toBe('sender,verdict,messages,share,dmarc_pass_rate,next_step')
    expect(rows.find((r) => r.startsWith('SendGrid,legit,'))).toMatch(/^SendGrid,legit,2\d{3},4\d\.\d%,0\.0%,/)
  })

  test('snapshots are saved per week and survive a reload', async ({ page }) => {
    await openNorthwind(page)
    await openTab(page, 'History')
    const rows = page.getByRole('heading', { name: 'Snapshots' }).locator('xpath=ancestor::div[contains(@class,"panel")]').locator('tbody tr')
    await expect(rows).toHaveCount(6)
    await page.reload()
    await expect(rows).toHaveCount(6)
    await expect(sections(page).getByRole('link', { name: 'History' })).toHaveAttribute('aria-current', 'page')
  })
})
