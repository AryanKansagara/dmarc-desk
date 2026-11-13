// Minimal XML reader for DMARC aggregate reports. Works in the browser and in Node (no DOMParser),
// keeps the line number of every element for validation messages.

export interface XNode { name: string; line: number; children: XNode[]; text: string }

const ENT: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }
const decode = (s: string) => s.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e: string) =>
  e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : +e.slice(1)) : ENT[e] ?? m)

export class XmlError extends Error {
  line: number
  constructor(message: string, line: number) { super(message); this.line = line }
}

export function parseXml(src: string): XNode {
  const root: XNode = { name: '#root', line: 1, children: [], text: '' }
  const stack = [root]
  let i = 0, line = 1
  const advance = (to: number) => { for (let k = i; k < to; k++) if (src.charCodeAt(k) === 10) line++; i = to }
  while (i < src.length) {
    const lt = src.indexOf('<', i)
    if (lt < 0) { stack.at(-1)!.text += decode(src.slice(i)); break }
    if (lt > i) stack.at(-1)!.text += decode(src.slice(i, lt))
    advance(lt)
    if (src.startsWith('<!--', i)) { const e = src.indexOf('-->', i); if (e < 0) throw new XmlError('Unclosed comment', line); advance(e + 3); continue }
    if (src.startsWith('<![CDATA[', i)) { const e = src.indexOf(']]>', i); if (e < 0) throw new XmlError('Unclosed CDATA', line); stack.at(-1)!.text += src.slice(i + 9, e); advance(e + 3); continue }
    if (src.startsWith('<?', i) || src.startsWith('<!', i)) { const e = src.indexOf('>', i); if (e < 0) throw new XmlError('Unclosed declaration', line); advance(e + 1); continue }
    const gt = src.indexOf('>', i)
    if (gt < 0) throw new XmlError('Unclosed tag', line)
    const raw = src.slice(i + 1, gt)
    // Unescaped "<" in text, as in <email><someone@example.net></email> or bad<host.net from some reporters: keep it as text.
    if (!/^\/?[A-Za-z_][\w.:-]*(\s|\/?$)/.test(raw)) { stack.at(-1)!.text += '<'; advance(i + 1); continue }
    const startLine = line
    advance(gt + 1)
    if (raw[0] === '/') {
      const name = local(raw.slice(1).trim())
      const top = stack.pop()
      if (!top || top === root || top.name !== name) throw new XmlError(`Unexpected </${name}>${top && top !== root ? `, expected </${top.name}>` : ''}`, startLine)
      top.text = top.text.trim()
      continue
    }
    const selfClose = raw.endsWith('/')
    const name = local(raw.replace(/\/$/, '').trim().split(/\s/)[0])
    if (!name) throw new XmlError('Empty tag name', startLine)
    const node: XNode = { name, line: startLine, children: [], text: '' }
    stack.at(-1)!.children.push(node)
    if (!selfClose) stack.push(node)
  }
  if (stack.length > 1) throw new XmlError(`<${stack.at(-1)!.name}> is never closed`, stack.at(-1)!.line)
  return root
}

// Drops namespace prefixes ("dmarc:record" -> "record"); aggregate reports are matched on local names.
const local = (n: string) => n.includes(':') ? n.slice(n.indexOf(':') + 1) : n

export const child = (n: XNode | undefined, name: string) => n?.children.find(c => c.name === name)
export const kids = (n: XNode | undefined, name: string) => n?.children.filter(c => c.name === name) ?? []
export const txt = (n: XNode | undefined, ...path: string[]) => {
  let cur = n
  for (const p of path) cur = child(cur, p)
  return cur?.text ?? ''
}
