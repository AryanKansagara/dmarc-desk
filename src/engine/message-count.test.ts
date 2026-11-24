import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseAggregate } from './aggregate.ts'

const report = (...counts: string[]) => `<?xml version="1.0"?><feedback><report_metadata><org_name>Odd Org</org_name><email>a@odd.test</email><report_id>c</report_id><date_range><begin>1760000000</begin><end>1760086400</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published>${counts.map((c, i) => `<record><row><source_ip>192.0.2.${i + 1}</source_ip><count>${c}</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>`).join('')}</feedback>`
/** The message counts that were kept, and the counts named in "Invalid message count" errors. */
const read = (...counts: string[]) => {
  const r = parseAggregate(report('7', ...counts)) // a good row first, so the report itself stays readable
  return { kept: r.report!.rows.slice(1).map(x => x.count), rejected: r.issues.filter(i => /^Invalid message count/.test(i.msg)).map(i => i.msg.match(/"(.*)"/)![1]) }
}

test('message counts are plain decimal integers within the safe range; anything else is rejected with "Invalid message count"', () => {
  const bad = ['99999999999999999999', '9007199254740992', '0x10', '1e3', '1E3', '+7', '1.5', '1.0', '-3', '-0', '', '0b11', '0o7', '1_000', '1,000', 'Infinity', 'NaN', '7 messages', '٣', '１２']
  const r = read(...bad)
  assert.deepEqual(r.kept, [])
  assert.deepEqual(r.rejected, bad)
})

test('plain counts are kept as they are, including 0, leading zeros, the largest safe integer and surrounding whitespace', () => {
  assert.deepEqual(read('0', '1', '12', '007', '4294967296', '9007199254740991', ' 42 ', '\n5\n').kept, [0, 1, 12, 7, 4294967296, 9007199254740991, 42, 5])
  assert.deepEqual(read('0', '1').rejected, [])
})

test('a rejected count is reported once per row and the report keeps its other rows', () => {
  const r = parseAggregate(report('5', '0x10', '3', '1e3'))
  assert.deepEqual(r.report!.rows.map(x => x.count), [5, 3])
  assert.equal(r.issues.filter(i => i.level === 'error').length, 2)
})
