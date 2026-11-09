// Decompresses report attachments in the browser (and Node 22) with the native DecompressionStream:
// .xml, .xml.gz (Google, Yahoo) and .zip (Microsoft, many others). No dependency needed.

export interface Unpacked { name: string; text: string }

async function inflate(data: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream(format))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

const dec = new TextDecoder()
export const kindOf = (b: Uint8Array) => b[0] === 0x1f && b[1] === 0x8b ? 'gzip' : b[0] === 0x50 && b[1] === 0x4b ? 'zip' : 'text'

export async function unpack(name: string, bytes: Uint8Array, depth = 0): Promise<Unpacked[]> {
  const kind = kindOf(bytes)
  if (kind === 'text') return [{ name, text: dec.decode(bytes).replace(/^﻿/, '') }]
  if (depth > 2) throw new Error('Archive nested too deeply')
  if (kind === 'gzip') return unpack(name.replace(/\.gz$/i, ''), await inflate(bytes, 'gzip'), depth + 1)
  const out: Unpacked[] = []
  for (const e of zipEntries(bytes)) {
    if (e.name.endsWith('/')) continue
    const raw = e.method === 0 ? e.data : e.method === 8 ? await inflate(e.data, 'deflate-raw') : null
    if (!raw) throw new Error(`${e.name}: unsupported zip compression method ${e.method}`)
    out.push(...await unpack(e.name, raw, depth + 1))
  }
  return out
}

/** Reads entries from the central directory (sizes there are reliable even when local headers use data descriptors). */
function zipEntries(b: Uint8Array): { name: string; method: number; data: Uint8Array }[] {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength)
  let eocd = -1
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) throw new Error('Not a valid zip file (no end of central directory)')
  const n = v.getUint16(eocd + 10, true)
  let p = v.getUint32(eocd + 16, true)
  const out = []
  for (let k = 0; k < n; k++) {
    if (v.getUint32(p, true) !== 0x02014b50) throw new Error('Corrupt zip central directory')
    const method = v.getUint16(p + 10, true)
    const csize = v.getUint32(p + 20, true)
    const nlen = v.getUint16(p + 28, true), xlen = v.getUint16(p + 30, true), clen = v.getUint16(p + 32, true)
    const local = v.getUint32(p + 42, true)
    const name = dec.decode(b.subarray(p + 46, p + 46 + nlen))
    const lstart = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true)
    out.push({ name, method, data: b.subarray(lstart, lstart + csize) })
    p += 46 + nlen + xlen + clen
  }
  return out
}
