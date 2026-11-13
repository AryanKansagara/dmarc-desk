// Decompresses report attachments in the browser (and Node 22) with the native DecompressionStream:
// .xml, .xml.gz (Google, Yahoo) and .zip (Microsoft, many others), plus whole report emails
// (.eml as saved from Outlook or Gmail "Download message") and .mbox files (Google Takeout). No dependency needed.

export interface Unpacked { name: string; text: string }

async function inflate(data: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream(format))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

// Some senders (Mimecast) append a stray CRLF after the gzip trailer, which DecompressionStream rejects
// as junk. Retry with up to 16 trailing bytes trimmed before giving up.
async function gunzip(data: Uint8Array): Promise<Uint8Array> {
  let first: unknown
  for (let k = 0; k <= 16 && k < data.length - 18; k++) {
    try { return await inflate(k ? data.subarray(0, data.length - k) : data, 'gzip') } catch (e) { first ??= e }
  }
  throw first instanceof Error && first.message ? first : new Error('Corrupt gzip data')
}

const dec = new TextDecoder()
export const kindOf = (b: Uint8Array) => b[0] === 0x1f && b[1] === 0x8b ? 'gzip' : b[0] === 0x50 && b[1] === 0x4b ? 'zip' : 'text'

export async function unpack(name: string, bytes: Uint8Array, depth = 0): Promise<Unpacked[]> {
  const kind = kindOf(bytes)
  if (kind === 'text') {
    const text = dec.decode(bytes).replace(/^\uFEFF/, '')
    if (!looksLikeMail(text)) return [{ name, text }]
    if (depth > 2) throw new Error('Archive nested too deeply')
    const out: Unpacked[] = []
    for (const a of mailAttachments(text)) out.push(...await unpack(a.name || name, a.bytes, depth + 1))
    if (!out.length) throw new Error(`${name}: no report attachment found in this email`)
    return out
  }
  if (depth > 2) throw new Error('Archive nested too deeply')
  if (kind === 'gzip') return unpack(name.replace(/\.gz$/i, ''), await gunzip(bytes), depth + 1)
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

/** An email or mbox rather than a bare report: starts with header lines, not with "<". */
export const looksLikeMail = (t: string) => /^(From |[A-Za-z][\w-]*:)/.test(t) && /^content-type:/im.test(t.slice(0, 200_000))

/** Every report-like part of an email or mbox: base64 attachments and inline XML bodies. */
export function mailAttachments(text: string): { name: string; bytes: Uint8Array }[] {
  const t = text.replace(/\r\n/g, '\n')
  // mbox: messages start with a "From " line at the beginning of a line
  const msgs = t.startsWith('From ') ? t.split(/\n(?=From \S)/).map(m => m.slice(m.indexOf('\n') + 1)) : [t]
  const out: { name: string; bytes: Uint8Array }[] = []
  const walk = (part: string, depth: number) => {
    const sep = part.search(/\n\n/)
    const head = (sep < 0 ? part : part.slice(0, sep)).replace(/\n[ \t]+/g, ' ')
    const body = sep < 0 ? '' : part.slice(sep + 2)
    const h = (k: string) => head.match(new RegExp(`^${k}:\\s*(.*)$`, 'im'))?.[1] ?? ''
    const type = h('content-type').toLowerCase()
    const boundary = h('content-type').match(/boundary="?([^";]+)"?/i)?.[1]
    if (type.startsWith('multipart/') && boundary && depth < 5) {
      const marker = `--${boundary}`
      const pieces = body.split('\n' + marker)
      // first piece is the preamble (or starts with the marker itself when there is no preamble)
      if (pieces[0].startsWith(marker)) pieces[0] = pieces[0].slice(marker.length)
      else pieces.shift()
      for (const p of pieces) { if (p.startsWith('--')) break; walk(p.replace(/^[ \t]*\n/, ''), depth + 1) }
      return
    }
    const fname = (h('content-disposition') + ';' + h('content-type')).match(/(?:file)?name\*?="?([^";]+)"?/i)?.[1]?.trim() ?? ''
    const enc = h('content-transfer-encoding').toLowerCase()
    const isReport = /gzip|zip|xml|octet-stream/.test(type) || /\.(xml|gz|zip)$/i.test(fname)
    if (!isReport) return
    if (enc === 'base64') {
      try { out.push({ name: fname, bytes: Uint8Array.from(atob(body.replace(/[^A-Za-z0-9+/=]/g, '')), c => c.charCodeAt(0)) }) } catch { /* not base64 after all */ }
    } else if (body.trimStart().startsWith('<')) out.push({ name: fname, bytes: new TextEncoder().encode(body) })
  }
  for (const m of msgs) walk(m, 0)
  return out
}
