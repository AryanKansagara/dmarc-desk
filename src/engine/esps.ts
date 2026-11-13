// Known sending services: netblocks, reverse-DNS patterns and the domains they authenticate with.
// Netblocks include every ip4/ip6 range in each service's published SPF include (resolved recursively over
// DNS on 2026-11-13: _spf.google.com, spf.protection.outlook.com, sendgrid.net, amazonses.com, spf.mtasv.net,
// mail.zendesk.com, mailgun.org, spf.brevo.com, zoho.com, servers.mcsv.net). They are a hint, not a guarantee;
// rDNS and the DKIM/SPF domains in the report usually identify a service even when its ranges move.

export interface Esp {
  id: string
  name: string
  kind: 'mailbox' | 'marketing' | 'transactional' | 'helpdesk' | 'crm'
  cidrs: string[]
  rdns: RegExp
  /** Domains the service signs DKIM or sets as Return-Path with when you have not set up your own */
  authDomains: RegExp
  spfInclude?: string
  /** How to get DKIM aligned (custom signing domain) */
  dkimFix: string
  /** How to get SPF aligned (custom Return-Path / MAIL FROM), if the service supports it */
  spfFix?: string
}

export const ESPS: Esp[] = [
  {
    id: 'google', name: 'Google Workspace', kind: 'mailbox',
    cidrs: ['209.85.128.0/17', '74.125.0.0/16', '64.233.160.0/19', '66.102.0.0/20', '66.249.80.0/20', '72.14.192.0/18', '108.177.8.0/21', '173.194.0.0/16', '216.58.192.0/19', '172.217.0.0/19', '35.190.247.0/24', '2607:f8b0::/32', '2a00:1450::/32', '2404:6800::/32', '2001:4860:4864::/56', '2800:3f0:4864::/56', '2c0f:fb50:4864::/56'],
    rdns: /(^|\.)(google\.com|googlemail\.com)$/, authDomains: /(^|\.)(gappssmtp\.com|google\.com|googlemail\.com)$/,
    spfInclude: '_spf.google.com',
    dkimFix: 'Admin console > Apps > Google Workspace > Gmail > Authenticate email. Generate a 2048-bit key with selector "google", publish the TXT record at google._domainkey, wait for it to resolve, then click Start authentication. Until then Google signs with d=<your-domain>.<date>.gappssmtp.com, which never aligns.',
  },
  {
    id: 'm365', name: 'Microsoft 365', kind: 'mailbox',
    cidrs: ['40.92.0.0/15', '40.107.0.0/16', '52.100.0.0/14', '104.47.0.0/17', '2a01:111:f400::/48', '2a01:111:f403::/48'],
    rdns: /(^|\.)(outbound\.protection\.outlook\.com|protection\.outlook\.com|outlook\.com|hotmail\.com)$/, authDomains: /(^|\.)(onmicrosoft\.com|outlook\.com|protection\.outlook\.com)$/,
    spfInclude: 'spf.protection.outlook.com',
    dkimFix: 'Microsoft Defender portal > Email & collaboration > Policies & rules > Threat policies > Email authentication settings > DKIM. Select your domain, publish the two CNAMEs it shows (selector1._domainkey and selector2._domainkey), then switch "Sign messages for this domain with DKIM signatures" on. Until then M365 signs with your tenant\'s onmicrosoft.com domain.',
  },
  {
    id: 'sendgrid', name: 'SendGrid', kind: 'marketing',
    cidrs: ['167.89.0.0/17', '149.72.0.0/16', '168.245.0.0/17', '50.31.32.0/19', '198.37.144.0/20', '208.117.48.0/20', '192.254.112.0/20', '159.183.0.0/16', '198.21.0.0/21', '134.128.64.0/18', '159.26.176.0/20', '223.165.113.0/24', '223.165.115.0/24', '223.165.118.0/23', '223.165.120.0/23', '137.22.245.0/24', '137.22.246.0/24'],
    rdns: /(^|\.)sendgrid\.net$/, authDomains: /(^|\.)sendgrid\.(net|com)$/,
    spfInclude: 'sendgrid.net',
    dkimFix: 'SendGrid > Settings > Sender Authentication > Authenticate Your Domain. Pick your DNS host, enter your domain, keep "Use automated security" on, and publish the three CNAMEs it gives you (em1234, s1._domainkey, s2._domainkey). Click Verify. This turns on custom DKIM (d=your domain) and a branded Return-Path, so both SPF and DKIM align.',
    spfFix: 'Covered by the same Domain Authentication: the emXXXX CNAME becomes the Return-Path, aligning SPF. You do not need include:sendgrid.net in your root SPF once this is done.',
  },
  {
    id: 'mailchimp', name: 'Mailchimp / Mandrill', kind: 'marketing',
    cidrs: ['205.201.128.0/20', '198.2.128.0/18', '148.105.0.0/16'],
    rdns: /(^|\.)(mcsv\.net|mcdlv\.net|rsgsv\.net|mandrillapp\.com|mailchimp\.com)$/, authDomains: /(^|\.)(mcsv\.net|mcdlv\.net|rsgsv\.net|mandrillapp\.com|mailchimp\.com|mailchimpapp\.net)$/,
    spfInclude: 'servers.mcsv.net',
    dkimFix: 'Mailchimp > Website > Domains > select your domain > Start authentication. Publish the CNAMEs k2._domainkey and k3._domainkey (and the DMARC record if it asks), then Verify. For Mandrill: Settings > Sending Domains > add the domain and publish the mandrill._domainkey TXT.',
  },
  {
    id: 'ses', name: 'Amazon SES', kind: 'transactional',
    cidrs: ['54.240.0.0/18', '23.249.208.0/20', '23.251.224.0/19', '76.223.128.0/19', '199.255.192.0/22', '199.127.232.0/22', '69.169.224.0/20', '76.223.176.0/20', '54.240.64.0/18', '216.221.160.0/19', '206.55.144.0/20', '24.110.64.0/18', '98.77.0.0/16'],
    rdns: /(^|\.)(amazonses\.com|smtp-out\.amazonses\.com)$/, authDomains: /(^|\.)amazonses\.com$/,
    spfInclude: 'amazonses.com',
    dkimFix: 'SES console > Identities > your domain > Authentication > Easy DKIM. Publish the three CNAMEs (<token>._domainkey). Make sure messages are sent from a verified domain identity, not just an email-address identity.',
    spfFix: 'SES > Identities > your domain > Custom MAIL FROM domain, e.g. bounce.yourdomain. Publish the MX and "v=spf1 include:amazonses.com ~all" TXT it lists, so the Return-Path aligns.',
  },
  {
    id: 'postmark', name: 'Postmark', kind: 'transactional',
    cidrs: ['50.31.156.0/23', '104.245.209.192/26', '3.134.147.250/32', '3.21.198.23/32', '50.31.205.0/24', '147.160.158.0/24'],
    rdns: /(^|\.)(mtasv\.net|postmarkapp\.com)$/, authDomains: /(^|\.)(mtasv\.net|postmarkapp\.com)$/,
    spfInclude: 'spf.mtasv.net',
    dkimFix: 'Postmark > Sender Signatures > your domain > DNS settings. Publish the DKIM TXT (<date>pm._domainkey) and Verify.',
    spfFix: 'Same page: publish the Return-Path CNAME (pm-bounces.yourdomain -> pm.mtasv.net) and Verify, so SPF aligns.',
  },
  {
    id: 'hubspot', name: 'HubSpot', kind: 'crm',
    cidrs: ['158.247.16.0/20', '143.244.80.0/20'],
    rdns: /(^|\.)(hubspotemail\.net|hubspot\.(com|net))$/, authDomains: /(^|\.)(hubspotemail\.net|hubspot\.(com|net)|hs-sites\.com)$/,
    spfInclude: '<portal-id>.spf<n>.hubspotemail.net',
    dkimFix: 'HubSpot > Settings > Content > Domains & URLs > Email sending domains > Connect a sending domain. Publish the two DKIM CNAMEs (hs1-<id>._domainkey and hs2-<id>._domainkey) and the SPF/Return-Path CNAME it lists, then Verify.',
  },
  {
    id: 'salesforce', name: 'Salesforce', kind: 'crm',
    cidrs: ['13.108.0.0/14', '96.43.144.0/20', '136.146.0.0/15', '13.111.0.0/16'],
    rdns: /(^|\.)(salesforce\.com|exacttarget\.com|exct\.net|sfmc-|mc\.salesforce\.com)/, authDomains: /(^|\.)(salesforce\.com|exacttarget\.com|exct\.net|bnc\.salesforce\.com)$/,
    spfInclude: '_spf.salesforce.com',
    dkimFix: 'Salesforce Setup > Email > DKIM Keys > Create New Key (2048-bit, choose a selector and alternate selector, domain = your domain). Publish the two CNAMEs it shows, wait for "Published", then Activate. Marketing Cloud uses a Sender Authentication Package instead, set up by Salesforce support.',
  },
  {
    id: 'zendesk', name: 'Zendesk', kind: 'helpdesk',
    cidrs: ['192.161.144.0/20', '216.198.0.0/18', '103.151.192.0/23', '185.12.80.0/22', '188.172.128.0/20'],
    rdns: /(^|\.)(zendesk\.com|zdsys\.com)$/, authDomains: /(^|\.)(zendesk\.com|zdsys\.com)$/,
    spfInclude: 'mail.zendesk.com',
    dkimFix: 'Zendesk Admin Center > Channels > Talk and email > Email > Email settings > Digital signatures (DKIM). Publish the CNAMEs zendesk1._domainkey and zendesk2._domainkey, then turn digital signatures on for each support address.',
    spfFix: 'Publish the four CNAMEs from Admin Center > Email > "Allow Zendesk to send email on your behalf" (zendesk1..4), which also sets an aligned Return-Path.',
  },
  {
    id: 'mailgun', name: 'Mailgun', kind: 'transactional',
    cidrs: ['209.61.151.0/24', '166.78.68.0/22', '198.61.254.0/23', '69.72.32.0/20', '159.135.224.0/20', '161.38.192.0/20', '204.220.90.0/23', '204.220.92.0/22', '204.220.89.0/24', '143.55.224.0/21', '143.55.232.0/22', '159.112.240.0/20', '198.244.48.0/20', '204.220.168.0/21', '204.220.176.0/20', '141.193.32.0/23', '87.253.232.0/21', '185.189.236.0/22', '185.211.120.0/22', '185.250.236.0/22', '143.55.236.0/22', '198.244.60.0/22', '204.220.160.0/20'],
    rdns: /(^|\.)mailgun\.(net|org|info)$/, authDomains: /(^|\.)mailgun\.(net|org|info)$/,
    spfInclude: 'mailgun.org',
    dkimFix: 'Mailgun > Sending > Domains > add your domain (or a subdomain like mg.yourdomain) and publish the DKIM TXT (<selector>._domainkey) shown under DNS records. Send from that domain.',
    spfFix: 'Publish the SPF TXT and the email.<domain> CNAME on the sending domain; Mailgun then uses it as the Return-Path.',
  },
  {
    id: 'brevo', name: 'Brevo (Sendinblue)', kind: 'marketing',
    cidrs: ['185.41.28.0/22', '212.146.192.0/21', '77.32.128.0/18', '94.143.16.0/21', '185.24.144.0/22', '153.92.224.0/19', '213.32.128.0/18', '185.107.232.0/22', '77.32.192.0/19', '212.146.192.0/18', '172.246.0.0/18'],
    rdns: /(^|\.)(sendinblue\.com|brevo\.com|sender-sib\.com)$/, authDomains: /(^|\.)(sendinblue\.com|brevo\.com|sender-sib\.com|brevosend\.com)$/,
    spfInclude: 'spf.brevo.com',
    dkimFix: 'Brevo > Senders, Domains & Dedicated IPs > Domains > Authenticate. Publish the brevo-code TXT and the two DKIM CNAMEs (brevo1._domainkey, brevo2._domainkey).',
  },
  {
    id: 'zoho', name: 'Zoho Mail', kind: 'mailbox',
    cidrs: ['136.143.176.0/20', '204.141.32.0/23', '165.173.128.0/18', '135.84.80.0/22', '8.39.54.0/23', '204.141.42.0/23', '8.40.222.0/23', '65.154.166.0/24', '199.67.80.0/21', '199.67.88.0/23', '169.148.128.0/18'],
    rdns: /(^|\.)(zoho\.(com|eu|in)|zohomail\.com)$/, authDomains: /(^|\.)(zoho\.(com|eu|in)|zohomail\.com)$/,
    spfInclude: 'zoho.com',
    dkimFix: 'Zoho Mail Admin Console > Domains > your domain > Email configuration > DKIM > Add selector, publish the TXT, then Verify and enable.',
  },
  {
    id: 'klaviyo', name: 'Klaviyo', kind: 'marketing',
    cidrs: ['168.245.0.0/17'],
    rdns: /(^|\.)klaviyomail\.com$/, authDomains: /(^|\.)(klaviyomail\.com|klaviyo\.com|send\.klaviyomail\.com)$/,
    dkimFix: 'Klaviyo > Settings > Domains > Set up branded sending domain. Publish the CNAMEs (including kl._domainkey and kl2._domainkey) and Verify.',
  },
  {
    id: 'intercom', name: 'Intercom', kind: 'helpdesk',
    cidrs: [],
    rdns: /(^|\.)intercom-mail\.com$/, authDomains: /(^|\.)(intercom-mail\.com|intercom\.io)$/,
    dkimFix: 'Intercom > Settings > Channels > Email > Domains. Add your domain and publish the two DKIM CNAMEs (intercom._domainkey and the bounce CNAME), then Verify.',
  },
]

export const espById = (id: string) => ESPS.find(e => e.id === id)
