import { useEffect } from 'react'
import { Code, Link } from './ui.tsx'

const GMAIL_SEARCH = `has:attachment (from:noreply-dmarc-support@google.com OR from:dmarcreport@microsoft.com OR from:dmarchelp@yahooinc.com OR subject:"Report domain:")`

const IMAP = `# Save every DMARC report attachment from a mailbox (Python 3, standard library only)
import imaplib, email, os
M = imaplib.IMAP4_SSL("imap.gmail.com")          # or outlook.office365.com
M.login("dmarc@yourdomain.com", os.environ["APP_PASSWORD"])
M.select("INBOX")
_, ids = M.search(None, '(SINCE "01-Oct-2026" SUBJECT "Report domain")')
os.makedirs("rua", exist_ok=True)
for i in ids[0].split():
    _, data = M.fetch(i, "(RFC822)")
    for part in email.message_from_bytes(data[0][1]).walk():
        name = part.get_filename()
        if name and name.lower().endswith((".zip", ".gz", ".xml")):
            open(os.path.join("rua", name), "wb").write(part.get_payload(decode=True))`

const DMARC_START = `_dmarc.yourdomain.com.  3600  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1"`

const SECTIONS = [['get-reports', 'Getting reports'], ['export', 'Exporting attachments'], ['read', 'Reading the results'], ['still-failing', '"I fixed it but it still fails"'], ['forwarding', 'Forwarding'], ['rollout', 'Rollout'], ['rules', 'Receiver rules (dated)'], ['privacy', 'Privacy and limits']] as const

export default function Docs() {
  useEffect(() => { const h = location.hash.slice(1); if (h) document.getElementById(h)?.scrollIntoView() }, [])
  return (
    <section className="page narrow docs">
      <div className="eyebrow">Docs</div>
      <h1>From p=none to p=reject</h1>
      <p className="lede">DMARC Desk reads the daily aggregate (RUA) reports that receivers send you, works out which services send as your domain and why each one passes or fails, and tells you when it is safe to enforce.</p>
      <nav className="toc" aria-label="On this page">{SECTIONS.map(([id, l]) => <a key={id} href={`#${id}`}>{l}</a>)}</nav>

      <h2 id="get-reports">1. Start receiving aggregate reports</h2>
      <ol>
        <li>Create a mailbox (or a Google group / M365 shared mailbox) such as <code>dmarc@yourdomain.com</code>. Expect 3 to 30 emails a day, so keep it out of anyone&rsquo;s main inbox.</li>
        <li>Publish a monitoring record. On Cloudflare: DNS &gt; Records &gt; Add record, type TXT, name <code>_dmarc</code>, content as below. The <Link href="/app">Records tab</Link> generates this for your domain.</li>
      </ol>
      <Code code={DMARC_START} label="BIND" />
      <ol start={3}>
        <li>Wait 24 to 72 hours. Google, Microsoft (Outlook.com and Enterprise Outlook), Yahoo, Comcast, Mail.ru and others each send one report per day, attached as <code>.xml.gz</code> (Google, Yahoo) or <code>.zip</code> (Microsoft).</li>
        <li>If the mailbox is on a different domain (for example a reporting service), that domain must publish <code>yourdomain.com._report._dmarc.theirdomain.com TXT "v=DMARC1"</code>. The DNS check verifies this.</li>
      </ol>

      <h2 id="export">2. Export the attachments</h2>
      <h3>Gmail / Google Workspace</h3>
      <ol>
        <li>Search the mailbox for reports:</li>
      </ol>
      <Code code={GMAIL_SEARCH} label="Gmail search" />
      <ol start={2}>
        <li>Open each message and use <b>Download all attachments</b>, or for months of reports use <a href="https://takeout.google.com" target="_blank" rel="noreferrer">Google Takeout</a> &gt; Mail &gt; filter by a label you apply to the search above, then unzip the <code>.mbox</code> with any mail client.</li>
        <li>Drop the downloaded <code>.zip</code>, <code>.gz</code> and <code>.xml</code> files on the Reports tab, all at once. Duplicates are detected and skipped.</li>
      </ol>
      <h3>Outlook / Microsoft 365</h3>
      <ol>
        <li>Create a rule: subject contains <code>Report domain:</code> &gt; move to a folder named DMARC.</li>
        <li>Classic Outlook: select all messages in the folder, then File &gt; Save Attachments. New Outlook and OWA: open each message &gt; attachment menu &gt; Download.</li>
        <li>Power Automate alternative: trigger <i>When a new email arrives (V3)</i> on the folder, action <i>Create file</i> in OneDrive for each attachment. Then drag the OneDrive folder&rsquo;s files in here.</li>
      </ol>
      <h3>Any IMAP mailbox</h3>
      <Code code={IMAP} label="Python" />

      <h2 id="read">3. Reading the results</h2>
      <ul>
        <li><b>DMARC passes</b> when SPF <i>or</i> DKIM passes <i>and</i> the passing domain aligns with the visible From domain. Relaxed alignment (the default) accepts subdomains: <code>em123.yourdomain.com</code> aligns with <code>yourdomain.com</code>.</li>
        <li><b>&ldquo;Signed by another domain&rdquo;</b>: the service signs DKIM with its own domain (<code>d=sendgrid.net</code>, <code>d=yourdomain.20230601.gappssmtp.com</code>, <code>d=tenant.onmicrosoft.com</code>). DKIM passes, but does not align. The fix is always to turn on custom DKIM in that service; each sender card says where.</li>
        <li><b>&ldquo;Passes for another domain&rdquo;</b> on SPF: the service uses its own bounce (Return-Path) domain. Adding its include to your SPF does nothing for alignment. Set up a custom Return-Path, or rely on DKIM.</li>
        <li><b>Readiness</b> is the share of your legitimate mail (your senders plus forwarded mail that kept its DKIM signature) that passes. Unknown sources that fail are excluded: that is the mail enforcement is meant to stop. Mark a source legitimate or unauthorized on the Senders tab to override.</li>
        <li>Senders are identified from the DKIM and Return-Path domains in the report, a bundled list of service netblocks (published ranges as of November 2026) and reverse DNS looked up over DNS-over-HTTPS.</li>
      </ul>

      <h2 id="still-failing">4. &ldquo;I fixed it but reports still show failures&rdquo;</h2>
      <p>Each aggregate report covers a 24-hour window, usually midnight to midnight UTC, and arrives one to three days later. A fix made on Tuesday afternoon shows up as a mixed Tuesday report and a clean report on Thursday or Friday. DMARC Desk marks a sender <i>Looks fixed since &lt;day&gt;</i> once every later report is aligned. Other common causes: the DNS change has a long TTL, the service caches its DKIM verification (click Verify again), or a second system you forgot also sends as you.</p>

      <h2 id="forwarding">5. Forwarding and mailing lists</h2>
      <p>When mail is forwarded (alumni addresses, a user&rsquo;s auto-forward to Gmail, a ticketing system relaying), the forwarder&rsquo;s IP is not in your SPF, so SPF fails. DKIM usually survives, so DMARC still passes. Mailing lists that add footers or change the subject break DKIM too; receivers that support ARC often deliver these anyway. DMARC Desk separates both cases and excludes broken forwards from readiness, because nothing in your DNS can fix them. This is also why DKIM on every sender matters more than SPF.</p>

      <h2 id="rollout">6. The rollout</h2>
      <ol>
        <li><b>p=none</b> for at least two weeks, until every sender above 1% of volume is identified and readiness is at or above 98% for two weeks running.</li>
        <li><b>p=quarantine; pct=10</b>, then 50, then 100: failing mail goes to spam for a growing share. Watch for complaints and new senders.</li>
        <li><b>p=reject; pct=50</b>, then 100. Keep reading reports monthly and add new services (with custom DKIM) before they go live.</li>
      </ol>
      <p>The planner on the Rollout tab dates each step from when your current policy was published and blocks the next step until its criteria are met. The DMARCbis draft replaces <code>pct</code> with a <code>t=y</code> testing flag; as of November 2026 the major receivers still honour <code>pct</code>.</p>

      <h2 id="rules">7. Receiver rules (as of November 2026)</h2>
      <ul>
        <li><b>Gmail</b> (since February 2024, enforcement tightened November 2025): bulk senders (5,000+ messages a day to Gmail) need SPF and DKIM, a DMARC record (p=none is enough), alignment of the From domain with SPF or DKIM, one-click unsubscribe, and a spam rate under 0.3%. Non-compliant mail is temporarily or permanently rejected.</li>
        <li><b>Yahoo</b> (since February 2024): the same requirements for bulk senders.</li>
        <li><b>Outlook.com, Hotmail, Live</b> (since May 5, 2025): domains sending 5,000+ messages a day must pass SPF, DKIM and DMARC (at least p=none, aligned). Failing mail is rejected with <code>550 5.7.515 Access denied, sending domain does not meet the required authentication level</code>.</li>
        <li>Everyone else benefits too: spoofed invoices and password resets from your domain stop at p=reject.</li>
      </ul>

      <h2 id="privacy">8. Privacy and limits</h2>
      <ul>
        <li>Reports are decompressed and parsed in your browser (native DecompressionStream). Nothing is uploaded. Projects are stored in IndexedDB on this device.</li>
        <li>Signing in is optional. It syncs domains, sender decisions, DNS results and weekly snapshots, plus the raw reports if they are under 2 MB per domain. Larger report sets stay on the device that imported them.</li>
        <li>DNS lookups go from your browser to Cloudflare (<code>cloudflare-dns.com</code>) and, as a fallback, Google (<code>dns.google</code>) public DNS-over-HTTPS. MTA-STS policy files are fetched through a small proxy because they do not allow cross-origin reads.</li>
        <li>Only common DKIM selectors are probed; add yours in the DNS check. Forensic (RUF) reports and TLS-RPT JSON reports are not parsed. The organisational-domain logic uses a short list of multi-label suffixes (co.uk, com.au and similar) instead of the full Public Suffix List.</li>
        <li>Sample domains (<code>example.com</code>, <code>example.org</code>) and their reports are synthetic. Invented IPs use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).</li>
      </ul>
    </section>
  )
}
