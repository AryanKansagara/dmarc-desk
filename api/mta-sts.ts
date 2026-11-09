// Fetches https://mta-sts.<domain>/.well-known/mta-sts.txt for the browser (those files do not send CORS headers).
export default async function handler(req: { url?: string }, res: { status(n: number): { send(b: string): void }; setHeader(k: string, v: string): void }) {
  const domain = new URL(req.url ?? '/', 'http://x').searchParams.get('domain')?.toLowerCase() ?? ''
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return res.status(400).send('Invalid domain')
  try {
    const r = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { redirect: 'error', signal: AbortSignal.timeout(5000) })
    const text = (await r.text()).slice(0, 4000)
    res.setHeader('content-type', 'text/plain; charset=utf-8')
    res.setHeader('cache-control', 'public, max-age=300')
    return res.status(r.ok ? 200 : 404).send(r.ok ? text : 'No policy')
  } catch {
    return res.status(404).send('No policy')
  }
}
