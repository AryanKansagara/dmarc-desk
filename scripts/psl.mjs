// Regenerates src/engine/psl.ts from the Public Suffix List (ICANN section, two-label rules).
// Usage: curl -sL https://publicsuffix.org/list/public_suffix_list.dat -o /tmp/psl.dat && node scripts/psl.mjs /tmp/psl.dat
import { readFileSync, writeFileSync } from 'node:fs'
const src = readFileSync(process.argv[2], 'utf8')
const version = src.match(/VERSION: (\S+)/)?.[1] ?? 'unknown'
const icann = src.slice(src.indexOf('===BEGIN ICANN DOMAINS==='), src.indexOf('===END ICANN DOMAINS==='))
const byTld = {}
for (const line of icann.split('\n')) {
  const r = line.trim()
  if (!r || r.startsWith('//') || /[*!]/.test(r)) continue
  const parts = r.split('.')
  if (parts.length !== 2 || /[^\x00-\x7f]/.test(r)) continue
  ;(byTld[parts[1]] ??= []).push(parts[0])
}
const body = Object.keys(byTld).sort().map(t => `${t}:${byTld[t].sort().join(',')}`).join(';')
writeFileSync(new URL('../src/engine/psl.ts', import.meta.url), `// Two-label public suffixes (e.g. co.uk, com.au, id.au) from the ICANN section of the Public Suffix List,
// https://publicsuffix.org/list/public_suffix_list.dat, version ${version}.
// This file is subject to the terms of the Mozilla Public License, v. 2.0, https://mozilla.org/MPL/2.0/.
// Regenerate with scripts/psl.mjs.
export const PSL_VERSION = '${version}'
const RAW = '${body}'
export const SUFFIXES2 = new Set(RAW.split(';').flatMap(g => { const [tld, labels] = g.split(':'); return labels.split(',').map(l => \`\${l}.\${tld}\`) }))
`)
console.log('tlds', Object.keys(byTld).length, 'bytes', body.length)
