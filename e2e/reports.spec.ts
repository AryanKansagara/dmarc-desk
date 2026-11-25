import type { Page } from '@playwright/test'
import { addDomain, chooseFiles, expect, fixture, fixtureFile, openTab, readiness, reportFile, sampleZip, test, toastText, validation } from './fixtures.ts'

// One real report per file type, from the parsedmarc sample set in src/engine/fixtures.
const FORMATS = [
  { file: 'outlook-com.xml', kind: '.xml', domain: 'example.com', org: 'Outlook.com' },
  { file: 'fastmail.xml.gz', kind: '.xml.gz', domain: 'indemed.com', org: 'FastMail Pty Ltd' },
  { file: 'gob-mx.xml.zip', kind: '.zip', domain: 'example.com', org: 'XYZ Corporation' },
  { file: 'google-multipart-zip.eml', kind: '.eml with a zip attachment', domain: 'twlnet.com', org: 'google.com' },
  { file: 'mimecast-gzip-trailing-crlf.eml', kind: '.eml with a gzip attachment', domain: 'ab.id.au', org: 'Mimecast' },
]

const imports = (page: Page) => page.getByRole('heading', { name: 'Imports' }).locator('xpath=ancestor::div[contains(@class,"panel")]').locator('tbody tr')
const importButton = (page: Page) => page.getByRole('button', { name: /^Import \d+ reports?$/ })
// What the overview says about the reports, without the DNS-dependent "Policy in reports" tile.
async function overviewOf(page: Page) {
  await expect(readiness(page)).toBeVisible()
  const kpis = await page.locator('.kpi', { hasNotText: 'Policy in reports' }).allInnerTexts()
  return { readiness: await readiness(page).getAttribute('aria-label'), heading: await page.locator('.readiness-card h2').innerText(), head: await page.locator('.proj-head p').innerText(), kpis }
}
const cell = (row: ReturnType<typeof imports>, i: number) => row.locator('td').nth(i)

test.describe('importing reports', () => {
  for (const f of FORMATS) {
    test(`${f.kind}: imports ${f.file}, and importing it again changes nothing`, async ({ page }) => {
      await addDomain(page, f.domain)
      await openTab(page, 'Reports')
      await chooseFiles(page, fixtureFile(f.file))
      expect(await validation(page)).toEqual({ new: 1, duplicate: 0, otherDomain: 0, unreadable: 0 })
      await expect(page.locator('.validation tbody tr')).toContainText([f.org])
      await importButton(page).click()
      await expect(toastText(page).first()).toContainText(/Imported 1 report \(\d+ messages?\)/)

      await openTab(page, 'Reports')
      await expect(imports(page)).toHaveCount(1)
      await expect(cell(imports(page), 1)).toHaveText('1')
      const imported = await imports(page).innerText()
      const overview = async () => { await openTab(page, 'Overview'); return overviewOf(page) }
      const before = await overview()

      // The same file again is recognised, and the import button is disabled.
      await openTab(page, 'Reports')
      await chooseFiles(page, fixtureFile(f.file))
      expect(await validation(page)).toEqual({ new: 0, duplicate: 1, otherDomain: 0, unreadable: 0 })
      await expect(page.locator('.validation tbody tr')).toContainText(['duplicate'])
      await expect(page.getByRole('button', { name: 'Import 0 reports' })).toBeDisabled()
      await page.getByRole('button', { name: 'Cancel' }).click()
      await expect(imports(page)).toHaveCount(1)
      expect(await imports(page).innerText()).toBe(imported)
      expect(await overview()).toEqual(before)

      // And it is all still there after a reload.
      await page.reload()
      await expect(readiness(page)).toBeVisible()
      await openTab(page, 'Reports')
      expect(await imports(page).innerText()).toBe(imported)
    })
  }

  test('a mixed batch: new reports import, copies and other domains are skipped, quirks are reported', async ({ page }) => {
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await chooseFiles(
      page,
      fixtureFile('outlook-com.xml'),
      reportFile('outlook-com-copy.xml', fixture('outlook-com.xml')), // the same report under another name
      fixtureFile('gob-mx.xml.zip'),
      fixtureFile('rfc9990-sample.xml'),
      fixtureFile('empty-org-name.xml'),
      fixtureFile('unescaped-lt.xml'),
      fixtureFile('fastmail.xml.gz'), // indemed.com
      fixtureFile('ikea-unclosed-wrapper.xml'), // example.de, and an unclosed wrapper element
    )
    expect(await validation(page)).toEqual({ new: 5, duplicate: 1, otherDomain: 2, unreadable: 0 })
    await expect(page.getByText('Ignored malformed XML around the report')).toBeVisible()
    await expect(page.locator('.validation tbody tr', { hasText: 'outlook-com-copy.xml' })).toContainText('duplicate')
    await expect(page.locator('.validation tbody tr', { hasText: 'fastmail' }).locator('.badge')).toHaveText('indemed.com')
    await expect(page.locator('.validation .badge.st-other-domain')).toHaveCount(2)
    await importButton(page).click()
    await expect(toastText(page).first()).toContainText('Imported 5 reports (127 messages)')

    await openTab(page, 'Reports')
    const row = imports(page)
    await expect(row).toHaveCount(1)
    await expect(cell(row, 0)).toHaveText('8 files')
    await expect(cell(row, 1)).toHaveText('5')
    await expect(cell(row, 2)).toHaveText('127')
    await expect(cell(row, 3)).toHaveText('3')
  })

  test('a report for another domain is not imported into this one', async ({ page }) => {
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, fixtureFile('fastmail.xml.gz'))
    expect(await validation(page)).toEqual({ new: 0, duplicate: 0, otherDomain: 1, unreadable: 0 })
    await expect(page.getByText('not example.com')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Import 0 reports' })).toBeDisabled()
  })

  test('a bulk import computes readiness and senders, which survive a reload; a second import of it adds nothing', async ({ page }) => {
    const zip = await sampleZip(page)
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, zip)
    expect(await validation(page)).toEqual({ new: 63, duplicate: 0, otherDomain: 0, unreadable: 0 })
    await importButton(page).click()
    await expect(toastText(page).first()).toContainText('Imported 63 reports (19,729 messages)')

    // Three weeks of reports; the latest week is the default. SendGrid is not yet aligned in them.
    await expect(page.getByText('example.com · 6,256 messages · 21 reports · Week of Oct 5, 2026')).toBeVisible()
    await expect(readiness(page)).toHaveAccessibleName('Readiness 50.1%')
    await expect(page.getByRole('heading', { name: '2,600 legitimate messages would fail' })).toBeVisible()
    await openTab(page, 'Senders')
    await expect(page.locator('.sender-head', { hasText: /^\s*SendGrid/ })).toContainText('0% pass')
    await expect(page.locator('.sender-head', { hasText: /^\s*Google Workspace/ })).toContainText('100% pass')

    await page.reload()
    await expect(page.locator('.sender-head', { hasText: /^\s*SendGrid/ })).toContainText('0% pass')
    await openTab(page, 'Overview')
    await expect(readiness(page)).toHaveAccessibleName('Readiness 50.1%')

    await openTab(page, 'Reports')
    await chooseFiles(page, zip)
    expect(await validation(page)).toEqual({ new: 0, duplicate: 63, otherDomain: 0, unreadable: 0 })
    await expect(page.getByRole('button', { name: 'Import 0 reports' })).toBeDisabled()
    await page.getByRole('button', { name: 'Cancel' }).click()
    await expect(imports(page)).toHaveCount(1)
    await expect(cell(imports(page), 1)).toHaveText('63')
    await openTab(page, 'Overview')
    await expect(readiness(page)).toHaveAccessibleName('Readiness 50.1%')
  })
})

test.describe('reports that cannot be read', () => {
  const GOOD = fixture('outlook-com.xml')
  const BAD = [
    { file: reportFile('empty.xml', ''), line: 'line 1', msg: 'No <feedback> element' },
    { file: reportFile('truncated.xml', GOOD.subarray(0, 700)), line: 'line 25', msg: 'Not well-formed XML: Unclosed tag' },
    { file: reportFile('not-a-report.xml', '<html><body>Hello</body></html>'), line: 'line 1', msg: 'No <feedback> element' },
    { file: reportFile('notes.xml', 'plain text, not XML at all'), line: 'line 1', msg: 'does not look like a DMARC aggregate' },
    { file: reportFile('truncated.zip', fixture('gob-mx.xml.zip').subarray(0, 300)), line: '—', msg: 'Could not decompress: Not a valid zip file' },
    { file: reportFile('no-rows.xml', '<feedback><report_metadata><org_name>x</org_name></report_metadata></feedback>'), line: 'line 1', msg: 'Missing <policy_published>' },
    { file: reportFile('no-report.eml', 'From: a@example.com\nContent-Type: text/plain\n\nhello\n'), line: '—', msg: 'no report attachment found in this email' },
  ]

  // A domain with real data, so any damage to the readiness would show.
  async function domainWithReports(page: Page) {
    const zip = await sampleZip(page)
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, zip)
    await importButton(page).click()
    await expect(readiness(page)).toHaveAccessibleName('Readiness 50.1%')
    const overview = await overviewOf(page)
    await openTab(page, 'Reports')
    return overview
  }

  test('empty, truncated, malformed and wrong files say what is wrong and change nothing', async ({ page }) => {
    const overview = await domainWithReports(page)
    await expect(imports(page)).toHaveCount(1)
    const imported = await imports(page).innerText()

    for (const { file, line, msg } of BAD) {
      await chooseFiles(page, file)
      expect(await validation(page), file.name).toEqual({ new: 0, duplicate: 0, otherDomain: 0, unreadable: 1 })
      const issue = page.locator('.issues [role=listitem]', { hasText: msg })
      await expect(issue, file.name).toHaveCount(1)
      await expect(issue.locator('.ln'), file.name).toHaveText(line)
      await expect(issue, file.name).toContainText(file.name)
      await expect(page.getByRole('button', { name: 'Import 0 reports' }), file.name).toBeDisabled()
      await page.getByRole('button', { name: 'Cancel' }).click()
    }

    expect(await imports(page).innerText()).toBe(imported)
    await openTab(page, 'Overview')
    await expect(readiness(page)).toHaveAccessibleName('Readiness 50.1%')
    expect(await overviewOf(page)).toEqual(overview)
    await page.reload()
    expect(await overviewOf(page)).toEqual(overview)
  })

  test('pasted XML that is truncated is rejected the same way', async ({ page }) => {
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await page.getByText('Paste report XML instead').click()
    await page.getByLabel('Report XML').fill(GOOD.subarray(0, 700).toString())
    await page.getByRole('button', { name: 'Validate' }).click()
    await expect(page.getByRole('heading', { name: 'Validation report' })).toBeVisible()
    expect(await validation(page)).toEqual({ new: 0, duplicate: 0, otherDomain: 0, unreadable: 1 })
    await expect(page.locator('.issues')).toContainText('Not well-formed XML: Unclosed tag')
    await expect(page.getByRole('button', { name: 'Import 0 reports' })).toBeDisabled()
  })

  test('unreadable files do not stop a good report in the same batch', async ({ page }) => {
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, reportFile('empty.xml', ''), fixtureFile('outlook-com.xml'), reportFile('truncated.xml', GOOD.subarray(0, 700)))
    expect(await validation(page)).toEqual({ new: 1, duplicate: 0, otherDomain: 0, unreadable: 2 })
    await importButton(page).click()
    await expect(toastText(page).first()).toContainText('Imported 1 report (1 message)')
    await openTab(page, 'Reports')
    await expect(cell(imports(page), 1)).toHaveText('1')
    await expect(cell(imports(page), 3)).toHaveText('2')
  })

  // https://github.com/AryanKansagara/dmarc-desk/issues/3
  test('a truncated .xml.gz says the file is damaged, not "Failed to fetch"', async ({ page }) => {
    await addDomain(page, 'indemed.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, reportFile('truncated.xml.gz', fixture('fastmail.xml.gz').subarray(0, 100)))
    expect(await validation(page)).toEqual({ new: 0, duplicate: 0, otherDomain: 0, unreadable: 1 })
    await expect(page.locator('.issues')).toContainText('Could not decompress: The gzip file is damaged or cut short')
    await expect(page.locator('.issues')).not.toContainText('Failed to fetch')
    await expect(page.getByRole('button', { name: 'Import 0 reports' })).toBeDisabled()
  })

  // Known bugs in how reports are judged. Each states what the app should do and is expected to fail until it does.
  const oddReport = (id: string, count: string) => `<?xml version="1.0"?><feedback><report_metadata><org_name>Odd Org</org_name><email>a@odd.test</email><report_id>${id}</report_id><date_range><begin>1760000000</begin><end>1760086400</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>`

  // https://github.com/AryanKansagara/dmarc-desk/issues/5
  test('a report whose only row is rejected is not offered as a new report', async ({ page }) => {
    test.fail()
    await addDomain(page, 'example.com')
    await openTab(page, 'Reports')
    await chooseFiles(page, reportFile('rejected-row.xml', oddReport('b', '1.5')))
    await expect(page.locator('.issues')).toContainText('Invalid message count "1.5"; row skipped.') // true today
    expect(await validation(page)).toMatchObject({ new: 0 })
  })

  // https://github.com/AryanKansagara/dmarc-desk/issues/6
  for (const count of ['99999999999999999999', '0x10', '1e3', '+7']) {
    test(`a message count of ${count} is rejected`, async ({ page }) => {
      test.fail()
      await addDomain(page, 'example.com')
      await openTab(page, 'Reports')
      await chooseFiles(page, reportFile('odd-count.xml', oddReport('c', count)))
      await expect(page.locator('.issues')).toContainText(`Invalid message count "${count}"`)
    })
  }
})
