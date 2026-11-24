import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseAggregate, reportKey } from './aggregate.ts'

const record = (ip: string, count: string) => `<record><row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>`
const report = (...records: string[]) => `<?xml version="1.0"?><feedback><report_metadata><org_name>Odd Org</org_name><email>a@odd.test</email><report_id>b</report_id><date_range><begin>1760000000</begin><end>1760086400</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published>${records.join('')}</feedback>`

test('a report whose every row is rejected is unreadable: it is not imported and does not occupy the duplicate key', () => {
  for (const [what, rows] of [
    ['non-integer count', [record('192.0.2.1', '1.5')]],
    ['invalid source_ip', [record('999.1.1.1', '5')]],
    ['negative count', [record('192.0.2.1', '-3')]],
    ['missing source_ip', [record('', '5')]],
    ['several different rejections', [record('192.0.2.1', '1.5'), record('nope', '2'), record('192.0.2.3', '-1')]],
  ] as const) {
    const r = parseAggregate(report(...rows))
    assert.equal(r.report, null, what)
    const errors = r.issues.filter(i => i.level === 'error')
    assert.equal(errors.length, rows.length + 1, `${what}: each rejected row, then the summary`)
    assert.match(errors.at(-1)!.msg, /rejected, so none of this report can be counted/, what)
  }
  assert.match(parseAggregate(report(record('192.0.2.1', '1.5'))).issues.map(i => i.msg).join('\n'), /Invalid message count "1.5"; row skipped\.\nAll 1 row was rejected/)
  // The corrected report is a new report, with the key the rejected one did not take.
  const fixed = parseAggregate(report(record('192.0.2.1', '5')))
  assert.equal(fixed.report!.rows.length, 1)
  assert.equal(reportKey(fixed.report!), 'Odd Org|b|example.com')
})

test('a report that keeps at least one row, or has none to begin with, is read as before', () => {
  const some = parseAggregate(report(record('192.0.2.1', '1.5'), record('192.0.2.2', '7')))
  assert.equal(some.report!.rows.length, 1)
  assert.equal(some.report!.rows[0].count, 7)
  assert.equal(some.issues.filter(i => i.level === 'error').length, 1)
  // Zero is a valid count; a report that saw no mail is a valid, empty report.
  assert.equal(parseAggregate(report(record('192.0.2.1', '0'))).report!.rows[0].count, 0)
  const none = parseAggregate(report())
  assert.equal(none.report!.rows.length, 0)
  assert.ok(none.issues.every(i => i.level !== 'error'))
  // Other problems keep their own message: a report without a domain is still just that.
  const bad = parseAggregate(report(record('192.0.2.1', '1.5')).replace('<domain>example.com</domain>', ''))
  assert.equal(bad.report, null)
})
