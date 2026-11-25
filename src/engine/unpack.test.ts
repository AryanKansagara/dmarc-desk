import { test } from 'node:test'
import assert from 'node:assert/strict'
import { deflateRawSync, gzipSync } from 'node:zlib'
import { readFileSync } from 'node:fs'
import { unpack } from './unpack.ts'

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)))
const DAMAGED = 'The gzip file is damaged or cut short'

test('a truncated or damaged .xml.gz says so; it never leaks the browser\'s "Failed to fetch"', async () => {
  const gz = fixture('fastmail.xml.gz')
  const flipped = Uint8Array.from(gz); flipped[flipped.length - 6] ^= 0xff // CRC32 in the trailer
  const garbage = Uint8Array.from(gz); garbage.fill(0x55, 40, 200) // inside the compressed data
  const cases: [string, Uint8Array][] = [
    ['cut at 100 bytes', gz.subarray(0, 100)], ['cut at 20', gz.subarray(0, 20)], ['header only', gz.subarray(0, 10)], ['two bytes', gz.subarray(0, 2)],
    ['trailer cut by 1', gz.subarray(0, gz.length - 1)], ['trailer missing', gz.subarray(0, gz.length - 8)], ['wrong CRC', flipped], ['garbage in the data', garbage],
  ]
  for (const [what, bytes] of cases) {
    await assert.rejects(unpack('x.xml.gz', bytes), (e: Error) => e.message === DAMAGED, what)
  }
  // The same inside an email, which keeps reporting the file and the reason.
  const eml = `From: a@example.com\nContent-Type: multipart/mixed; boundary="b"\n\n--b\nContent-Type: application/gzip; name="r.xml.gz"\nContent-Transfer-Encoding: base64\n\n${Buffer.from(gz.subarray(0, 100)).toString('base64')}\n--b--\n`
  await assert.rejects(unpack('r.eml', new TextEncoder().encode(eml)), (e: Error) => e.message === DAMAGED)
})

test('a damaged zip entry says which entry; a truncated zip keeps its own message', async () => {
  const data = Buffer.from('<feedback>' + 'x'.repeat(2000) + '</feedback>')
  const body = deflateRawSync(data).subarray(0, 10) // cut short, but the central directory is intact
  const name = Buffer.from('report.xml')
  const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26)
  const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28)
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(46 + name.length, 12); end.writeUInt32LE(30 + name.length + body.length, 16)
  const zip = new Uint8Array(Buffer.concat([lh, name, body, ch, name, end]))
  await assert.rejects(unpack('r.zip', zip), (e: Error) => e.message === 'The zip entry report.xml is damaged or cut short')
  await assert.rejects(unpack('r.zip', fixture('gob-mx.xml.zip').subarray(0, 300)), /Not a valid zip file/)
})

test('gzip and zip files that are intact still unpack, including a stray CRLF after the trailer', async () => {
  const gz = fixture('fastmail.xml.gz')
  const plain = await unpack('fastmail.xml.gz', gz)
  assert.equal(plain.length, 1)
  assert.match(plain[0].text, /<feedback/)
  for (const tail of [[0x0d, 0x0a], [0x0a], [0, 0, 0, 0], new Array(16).fill(0x0a)]) {
    const r = await unpack('fastmail.xml.gz', Uint8Array.from([...gz, ...tail]))
    assert.equal(r[0].text, plain[0].text, `${tail.length} trailing bytes`)
  }
  assert.equal((await unpack('gob-mx.xml.zip', fixture('gob-mx.xml.zip'))).length, 1)
  assert.equal((await unpack('a.xml.gz', new Uint8Array(gzipSync('<feedback/>'))))[0].text, '<feedback/>')
  assert.deepEqual(await unpack('empty.xml.gz', new Uint8Array(gzipSync(''))), [{ name: 'empty.xml', text: '' }])
})
