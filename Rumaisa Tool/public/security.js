/* CurlSec — findings engine: built-in passive checks + AI-powered deep analysis */

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_WEIGHT = { critical: 25, high: 15, medium: 7, low: 3, info: 0 };
// Every finding is one of three kinds, so hardening advice never looks like a real vulnerability:
//   vuln      — evidence of an actual, exploitable problem
//   review    — might be a problem; a human has to confirm it
//   hardening — not a vulnerability; extra protection that is good practice
const KINDS = ['vuln', 'review', 'hardening'];
const KIND_META = {
  vuln: { icon: 'alert', title: 'Vulnerabilities', sub: 'Real problems with evidence in the response. Fix these first.' },
  review: { icon: 'search', title: 'Needs review', sub: 'Could be a problem, but it can\'t be confirmed automatically. Check these by hand.' },
  hardening: { icon: 'shield', title: 'Hardening tips', sub: 'Not vulnerabilities. Extra layers of protection that are good practice — nobody can attack the site just because these are missing.' },
};
const sec = { quick: [], ai: [], aiRaw: '', aiSummary: '', aiRating: '', controller: null, aiMeta: null, showQuick: false };

const maskSecret = (s) => (s.length <= 12 ? s.slice(0, 3) + '•••' : s.slice(0, 6) + '•'.repeat(Math.min(12, s.length - 10)) + s.slice(-4));
const clip = (s, n = 160) => (s.length > n ? s.slice(0, n) + '…' : s);
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;

/* =====================================================================
   1. BUILT-IN QUICK SCAN (runs locally, no API key needed)
   ===================================================================== */

const SECRET_RULES = [
  { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, sev: 'critical' },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, sev: 'critical' },
  { name: 'OpenAI API key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, sev: 'critical' },
  { name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g, sev: 'critical' },
  { name: 'Stripe secret key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g, sev: 'critical' },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{40,}\b/g, sev: 'critical' },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, sev: 'critical' },
  { name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, sev: 'critical' },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, sev: 'critical' },
  { name: 'Database connection string with password', re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s"'<>:]+:[^\s"'<>@]+@[^\s"'<>]+/g, sev: 'critical' },
  { name: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g, sev: 'high' },
  { name: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g, sev: 'high' },
  { name: 'Twilio API key', re: /\bSK[0-9a-f]{32}\b/g, sev: 'high' },
  { name: 'Mailgun API key', re: /\bkey-[0-9a-zA-Z]{32}\b/g, sev: 'high' },
  { name: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, sev: 'medium', kind: 'review',
    note: 'It may be a harmless sample or public token — decode it (e.g. jwt.io) and check whether it is a real, unexpired session token.' },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, sev: 'low', kind: 'review',
    note: 'Browser-side Google keys (Maps, Firebase) are public by design. It is only a problem if the key is NOT restricted by HTTP referrer / API scope in Google Cloud.' },
];

const PLACEHOLDER = /^(\*+|x+|\.+|your|enter|example|placeholder|changeme|null|undefined|true|false|password|secret|string|value|\$\{|\{\{|<)/i;

function addFinding(list, f) {
  const key = f.title + '|' + (f.evidence || '');
  if (list.some((x) => x.title + '|' + (x.evidence || '') === key)) return;
  // Hardening tips are never rated above "low".
  if (f.kind === 'hardening' && SEV.indexOf(f.sev) < SEV.indexOf('low')) f.sev = 'low';
  list.push({ source: 'quick', ...f });
}

function scanSecrets(text, out) {
  const seen = new Set();
  for (const r of SECRET_RULES) {
    for (const m of text.matchAll(r.re)) {
      if (seen.has(m.index)) continue;
      seen.add(m.index);
      addFinding(out, {
        kind: r.kind || 'vuln', sev: r.sev, category: 'Sensitive Data Exposure', title: r.name + ' exposed in source',
        detail: (r.note ? r.note + ' ' : '') + `Found on line ${lineOf(text, m.index)}. Anything shipped to the browser is readable by every visitor.`,
        evidence: maskSecret(m[0]), find: m[0],
        fix: r.kind === 'review' ? 'Confirm whether this value is sensitive; if it is, rotate it and keep it server-side.' : 'Revoke/rotate this credential immediately, move it to a server-side environment variable and proxy the calls through your backend.',
      });
    }
  }
  const credRe = /["']?\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{6,})["']/gi;
  for (const m of text.matchAll(credRe)) {
    if (PLACEHOLDER.test(m[2]) || seen.has(m.index)) continue;
    addFinding(out, {
      kind: 'review', sev: 'high', category: 'Sensitive Data Exposure', title: `Possible hard-coded ${m[1].toLowerCase()}`,
      detail: `A value assigned to "${m[1]}" is embedded in the code (line ${lineOf(text, m.index)}). It could be a real credential or just a label/test value — check it.`,
      evidence: m[0].replace(m[2], maskSecret(m[2])), find: m[0],
      fix: 'Never ship credentials to the client. Keep them server-side and rotate this value if it is real.',
    });
  }
}

function scanDisclosure(text, isHttps, out) {
  const firstMatch = (re) => { re.lastIndex = 0; return re.exec(text); };
  const listOf = (re, max = 8) => [...new Set([...text.matchAll(re)].map((m) => m[0]))].slice(0, max);

  const err = firstMatch(/(Traceback \(most recent call last\)|Fatal error:|Warning: [^\n]{0,80} on line \d+|SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|Exception in thread|at [\w.$]+\([\w./]+\.java:\d+\)|Microsoft OLE DB|Stack trace:)/g);
  if (err) addFinding(out, { kind: 'vuln', sev: 'medium', category: 'Information Disclosure', title: 'Error message / stack trace in response',
    detail: 'Verbose errors disclose file paths, frameworks and query structure that help attackers.', evidence: clip(text.substr(err.index, 160)), find: err[0],
    fix: 'Disable debug output in production and return generic error pages; log details server-side.' });

  if (isHttps) {
    const mixed = listOf(/<(?:script|iframe|form|embed|object)\b[^>]+(?:src|action)\s*=\s*["']http:\/\/[^"']+/gi, 6);
    if (mixed.length) addFinding(out, { kind: 'vuln', sev: 'medium', category: 'Insecure Transport', title: 'Scripts/forms loaded over plain HTTP (mixed content)',
      detail: 'Active content over HTTP on an HTTPS page can be modified by a network attacker.', evidence: mixed.map((m) => clip(m, 140)).join('\n'), find: mixed[0],
      fix: 'Load every resource over HTTPS.' });
  }

  const ips = listOf(/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g);
  if (ips.length) addFinding(out, { kind: 'review', sev: 'low', category: 'Information Disclosure', title: 'Internal IP addresses referenced',
    detail: 'Private network addresses can reveal internal infrastructure. Could also be harmless (e.g. a version number or example).', evidence: ips.join(', '), find: ips[0],
    fix: 'Remove internal hostnames/IPs from client-facing code and responses.' });

  const local = listOf(/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"'<>)]*/g);
  if (local.length) addFinding(out, { kind: 'review', sev: 'low', category: 'Information Disclosure', title: 'Localhost / development URLs left in code',
    detail: 'Leftover dev endpoints hint at debug builds and internal tooling.', evidence: local.join('\n'), find: local[0],
    fix: 'Strip development URLs from production builds (use environment-based config).' });

  const sm = firstMatch(/[#@]\s*sourceMappingURL=(\S+)/g);
  if (sm && !sm[1].startsWith('data:')) addFinding(out, { kind: 'review', sev: 'low', category: 'Information Disclosure', title: 'Source map reference exposed',
    detail: 'If the .map file is publicly downloadable, anyone can read your original source code and comments. Open the URL to check.', evidence: sm[0], find: sm[0],
    fix: 'Do not deploy .map files publicly, or restrict them to internal access.' });

  const comments = [...text.matchAll(/<!--([\s\S]*?)-->/g)].filter((m) => /\b(todo|fixme|hack|password|passwd|admin|debug|api[_ ]?key|secret|token|internal|staging|credentials?)\b/i.test(m[1]));
  if (comments.length) addFinding(out, { kind: 'review', sev: 'low', category: 'Information Disclosure', title: `${comments.length} HTML comment(s) with sensitive keywords`,
    detail: 'Developer comments are visible to every visitor via View Source. Read them to see if they reveal anything useful.', evidence: comments.slice(0, 4).map((m) => clip(m[0].replace(/\s+/g, ' '), 140)).join('\n'), find: comments[0][0].split('\n')[0],
    fix: 'Strip comments from production HTML (most minifiers can do this).' });

  const dbg = firstMatch(/\b(?:debug|isDebug|DEBUG|debugMode)\s*[:=]\s*(?:true|1|["']true["'])/g);
  if (dbg) addFinding(out, { kind: 'review', sev: 'low', category: 'Security Misconfiguration', title: 'Debug flag enabled in client code',
    detail: 'A debug switch is on in shipped code. Often harmless (a library default), sometimes it unlocks verbose logging or hidden features.', evidence: dbg[0], find: dbg[0],
    fix: 'Ensure production builds set debug flags to false.' });

  const buckets = listOf(/\b[a-z0-9.-]+\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b|\bs3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\/[a-z0-9._-]+|\bstorage\.googleapis\.com\/[a-z0-9._-]+|\b[a-z0-9-]+\.blob\.core\.windows\.net\b|\b[a-z0-9-]+\.firebaseio\.com\b/g);
  if (buckets.length) addFinding(out, { kind: 'review', sev: 'info', category: 'Attack Surface', title: 'Cloud storage endpoints referenced',
    detail: 'Normal for most sites. Only a problem if a bucket/database allows anonymous listing or writing.', evidence: buckets.join('\n'), find: buckets[0],
    fix: 'Verify bucket ACLs / Firebase rules deny anonymous list and write access.' });

  const emails = listOf(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, 10).filter((e) => !/\.(png|jpe?g|gif|svg|webp|js|css)$/i.test(e) && !/@\d/.test(e));
  if (emails.length) addFinding(out, { kind: 'hardening', sev: 'info', category: 'Privacy', title: `${emails.length} email address(es) visible`,
    detail: 'Public emails can be harvested by spammers. Usually intentional (contact addresses).', evidence: emails.join(', '), find: emails[0],
    fix: 'Use contact forms or obfuscation for addresses that do not need to be public.' });

  const endpoints = listOf(/["'`](\/(?:api|v\d+|graphql|admin|internal|private|debug|backend)\b[\w\-./?=&{}$:]*)["'`]/g, 15).map((s) => s.slice(1, -1));
  if (endpoints.length) {
    const admin = endpoints.filter((e) => /admin|internal|private|debug/i.test(e));
    addFinding(out, { kind: admin.length ? 'review' : 'hardening', sev: admin.length ? 'low' : 'info', category: 'Attack Surface', title: `${endpoints.length} API / backend endpoint(s) discovered`,
      detail: (admin.length ? 'Includes administrative or internal-looking routes — check they require login. ' : 'Normal for web apps. ') + 'Every endpoint must enforce authentication and authorization on the server.',
      evidence: endpoints.join('\n'), find: endpoints[0],
      fix: 'Review each endpoint for auth checks, rate limiting and object-level authorization (IDOR).' });
  }
}

function scanCodePatterns(text, out) {
  // Frameworks like Next.js use these APIs internally for their own (server-controlled) data — not a finding.
  const isNext = /__NEXT_DATA__|\/_next\/static\/|self\.__next_f/.test(text);
  const hasSource = /\blocation\.(?:hash|search|href)|document\.(?:URL|referrer|documentURI)|URLSearchParams/.test(text);
  const sinks = [
    { re: /\.(?:inner|outer)HTML\s*\+?=(?!=)/g, name: 'innerHTML / outerHTML assignment' },
    { re: /\binsertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML' },
    { re: /\bdocument\.write(?:ln)?\s*\(/g, name: 'document.write' },
    { re: /\beval\s*\(/g, name: 'eval()' },
    { re: /\bnew\s+Function\s*\(/g, name: 'new Function()' },
    { re: /dangerouslySetInnerHTML/g, name: 'dangerouslySetInnerHTML', skip: isNext },
  ];
  const hits = sinks.filter((s) => !s.skip).map((s) => ({ ...s, ms: [...text.matchAll(s.re)] })).filter((s) => s.ms.length);
  if (hits.length) {
    const m = hits[0].ms[0];
    const names = hits.map((h) => `${h.name}${h.ms.length > 1 ? ` (${h.ms.length}×)` : ''}`).join(', ');
    if (hasSource) {
      addFinding(out, { kind: 'review', sev: 'medium', category: 'XSS / Injection', title: 'Possible DOM-based XSS — URL data and HTML sinks in the same code',
        detail: `The page reads URL-controlled data (location / URLSearchParams) and also uses ${names}. It is only a vulnerability if the URL data reaches one of these sinks without sanitising — trace it, or run the AI analysis.`,
        evidence: clip(text.substr(Math.max(0, m.index - 40), 160).replace(/\s+/g, ' ')), find: m[0],
        fix: 'Use textContent / safe DOM APIs or a sanitizer (e.g. DOMPurify); never pass untrusted data to HTML or code sinks.' });
    } else {
      addFinding(out, { kind: 'hardening', sev: 'info', category: 'XSS / Injection', title: `Uses raw-HTML APIs: ${names}`,
        detail: 'Common in normal code and not a vulnerability by itself. It only matters if user-controlled data ever reaches these calls.',
        evidence: clip(text.substr(Math.max(0, m.index - 40), 160).replace(/\s+/g, ' ')), find: m[0],
        fix: 'Prefer textContent and safe templating; sanitize any HTML built from user data.' });
    }
  }

  const rules = [
    { re: /(?:localStorage|sessionStorage)\.setItem\(\s*["'`][^"'`]*(?:token|jwt|auth|password|secret|session)[^"'`]*["'`]/gi, sev: 'medium',
      title: 'Auth token / secret stored in Web Storage', cat: 'Sensitive Data Exposure',
      detail: 'If the site ever has an XSS bug, tokens in localStorage can be stolen. Not exploitable on its own.',
      fix: 'Prefer HttpOnly, Secure, SameSite cookies for session tokens.' },
    { re: /\b(?:isAdmin|is_admin|isSuperuser|userRole|role)\s*(?:===?|!==?)\s*["']?(?:admin|true|superuser|root)\b/g, sev: 'low',
      title: 'Client-side authorization check', cat: 'Business Logic',
      detail: 'Role checks in the browser only hide UI. It is a vulnerability only if the server does not re-check the role.',
      fix: 'Make sure every privileged action is re-authorized on the server.' },
    { re: /\b(?:price|amount|total|discount|quantity)\s*[:=]\s*(?:parseFloat|parseInt|Number)?\(?\s*(?:document\.|\$\(|params|query|location)/gi, sev: 'low',
      title: 'Price / amount derived from client input', cat: 'Business Logic',
      detail: 'A vulnerability only if the server trusts this value when charging or placing orders.',
      fix: 'Never trust prices, totals or discounts sent from the browser — recompute them server-side.' },
  ];
  for (const r of rules) {
    const ms = [...text.matchAll(r.re)];
    if (!ms.length) continue;
    addFinding(out, { kind: 'review', sev: r.sev, category: r.cat, title: r.title + (ms.length > 1 ? ` (${ms.length}×)` : ''),
      detail: `${r.detail} Found on line ${lineOf(text, ms[0].index)}.`,
      evidence: clip(text.substr(Math.max(0, ms[0].index - 40), 160).replace(/\s+/g, ' ')), find: ms[0][0], fix: r.fix });
  }

  const msg = /addEventListener\(\s*["']message["']/.exec(text);
  if (msg && !/\.origin\b/.test(text)) addFinding(out, { kind: 'review', sev: 'medium', category: 'XSS / Injection', title: 'postMessage listener without an origin check',
    detail: 'Any website that can frame or open this page can send it messages. A vulnerability if the handler does something sensitive with the data.', evidence: clip(text.substr(msg.index, 140)), find: msg[0],
    fix: 'Validate event.origin against an allow-list before processing message data.' });
}

const LIBS = [
  { name: 'jQuery', banner: /jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/, url: /jquery[.-@/]v?(\d+\.\d+\.\d+)/i,
    vuln: (v) => cmpVer(v, '3.5.0') < 0, why: 'versions < 3.5.0 are affected by XSS in htmlPrefilter (CVE-2020-11022 / CVE-2020-11023)', sev: 'medium' },
  { name: 'Bootstrap', banner: /Bootstrap v(\d+\.\d+\.\d+)/, url: /bootstrap[.-@/]v?(\d+\.\d+\.\d+)/i,
    vuln: (v) => cmpVer(v, '3.4.1') < 0 || (cmpVer(v, '4.0.0') >= 0 && cmpVer(v, '4.3.1') < 0), why: 'has known XSS in tooltip/popover data attributes (CVE-2019-8331)', sev: 'medium' },
  { name: 'AngularJS', banner: /AngularJS v(1\.\d+\.\d+)/, url: /angular(?:\.js)?[.-@/]v?(1\.\d+\.\d+)/i,
    vuln: () => true, why: 'AngularJS 1.x is end-of-life (Jan 2022) and has unpatched sandbox-escape / XSS issues', sev: 'medium' },
  { name: 'Lodash', banner: /lodash(?:\.min)?\.js[^\n]{0,40}?(\d+\.\d+\.\d+)|var VERSION\s*=\s*["'](4\.\d+\.\d+)["'][^]{0,200}lodash/, url: /lodash[.-@/]v?(\d+\.\d+\.\d+)/i,
    vuln: (v) => cmpVer(v, '4.17.21') < 0, why: 'versions < 4.17.21 have prototype pollution / command injection (CVE-2020-8203, CVE-2021-23337)', sev: 'medium' },
  { name: 'Moment.js', banner: /moment\.js[^\n]{0,30}?version\s*:\s*(\d+\.\d+\.\d+)|\/\/! moment\.js\s*\n\/\/! version : (\d+\.\d+\.\d+)/, url: /moment[.-@/]v?(\d+\.\d+\.\d+)/i,
    vuln: (v) => cmpVer(v, '2.29.4') < 0, why: 'versions < 2.29.4 have ReDoS / path traversal (CVE-2022-31129, CVE-2022-24785)', sev: 'low' },
  { name: 'Vue 2', banner: /Vue\.js v(2\.\d+\.\d+)/, url: /vue[.-@/]v?(2\.\d+\.\d+)/i,
    vuln: () => true, why: 'Vue 2 reached end-of-life on 31 Dec 2023 and no longer receives security fixes', sev: 'low' },
];
function cmpVer(a, b) {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  return 0;
}
function scanLibraries(text, scriptUrls, out) {
  for (const lib of LIBS) {
    let v = null, where = '';
    const b = lib.banner.exec(text);
    if (b) { v = b[1] || b[2]; where = 'inline banner'; }
    if (!v) for (const u of scriptUrls) { const m = lib.url.exec(u); if (m) { v = m[1]; where = u; break; } }
    if (v && lib.vuln(v)) addFinding(out, { kind: 'review', sev: lib.sev, category: 'Vulnerable Components', title: `Outdated ${lib.name} ${v} (known CVEs)`,
      detail: `${lib.name} ${v} ${lib.why}. Exploitable only if the site uses the affected feature with user-controlled data — but upgrading is cheap.`, evidence: where, find: v,
      fix: `Upgrade ${lib.name} to the latest supported release.` });
  }
}

function scanHtml(r, out) {
  const doc = new DOMParser().parseFromString(r.body, 'text/html');
  const base = new URL(r.finalUrl);
  const isHttps = base.protocol === 'https:';
  const scripts = [...doc.querySelectorAll('script[src]')].map((s) => { try { return new URL(s.getAttribute('src'), base).href; } catch { return null; } }).filter(Boolean);

  doc.querySelectorAll('form').forEach((f) => {
    const action = f.getAttribute('action') || '';
    const method = (f.getAttribute('method') || 'get').toLowerCase();
    const hasPwd = !!f.querySelector('input[type=password]');
    const snippet = clip(f.outerHTML.split('>')[0] + '>', 140);
    let abs = null; try { abs = new URL(action || r.finalUrl, base); } catch {}
    if (isHttps && abs && abs.protocol === 'http:') addFinding(out, { kind: 'vuln', sev: 'high', category: 'Insecure Transport', title: 'Form submits over plain HTTP',
      detail: 'Data entered into this form is sent unencrypted.', evidence: snippet, find: action, fix: 'Point the form action to an HTTPS URL.' });
    if (hasPwd && method === 'get') addFinding(out, { kind: 'vuln', sev: 'medium', category: 'Sensitive Data Exposure', title: 'Password form uses GET',
      detail: 'Passwords end up in the URL, browser history, proxy and server logs.', evidence: snippet, find: snippet.slice(0, 40), fix: 'Use method="post" for credential forms.' });
    if (method === 'post' && !f.querySelector('input[type=hidden][name*=csrf i], input[type=hidden][name*=token i], input[type=hidden][name*=nonce i], input[type=hidden][name*=authenticity i]'))
      addFinding(out, { kind: 'review', sev: 'low', category: 'Authentication & Authorization', title: 'POST form without a visible CSRF token',
        detail: 'No hidden anti-CSRF field was found. Many sites protect against CSRF with SameSite cookies or headers instead, so this is often fine.', evidence: snippet, find: snippet.slice(0, 40),
        fix: 'Use per-session CSRF tokens and SameSite=Lax/Strict cookies for state-changing requests.' });
  });

  const noSri = [...doc.querySelectorAll('script[src], link[rel~=stylesheet][href]')].filter((el) => {
    const u = el.getAttribute('src') || el.getAttribute('href');
    try { return new URL(u, base).host !== base.host && !el.hasAttribute('integrity'); } catch { return false; }
  }).map((el) => el.getAttribute('src') || el.getAttribute('href'));
  if (noSri.length) addFinding(out, { kind: 'hardening', sev: 'info', category: 'Vulnerable Components', title: `${noSri.length} third-party script/style(s) without Subresource Integrity`,
    detail: 'Only possible for static files; analytics and other scripts that change often cannot use SRI.', evidence: noSri.slice(0, 6).join('\n'), find: noSri[0],
    fix: 'Add integrity="sha384-…" and crossorigin="anonymous" to static third-party resources.' });

  return { scripts, isHttps };
}

function scanHeaders(r, isHtml, out) {
  const h = r.headers;
  const isHttps = r.finalUrl.startsWith('https:');
  const hasHsts = !!h['strict-transport-security'];
  const tip = (title, sev, detail, fix, evidence = '', category = 'Security Misconfiguration') => addFinding(out, { kind: 'hardening', sev, category, title, detail, fix, evidence, header: true });

  if (!isHttps) addFinding(out, { kind: 'vuln', sev: 'high', category: 'Insecure Transport', title: 'Site served over plain HTTP', header: true,
    detail: 'All traffic, cookies and credentials can be read or modified in transit.', fix: 'Serve the site over HTTPS and redirect HTTP to HTTPS.', evidence: r.finalUrl });
  if (isHttps && !hasHsts) tip('Missing Strict-Transport-Security (HSTS)', 'low', 'Without HSTS a user on a hostile network could be downgraded to HTTP on their very first visit.', 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains', '', 'Insecure Transport');
  const csp = h['content-security-policy'];
  if (isHtml && !csp) tip('No Content-Security-Policy', 'low', 'CSP is a second line of defence that limits the damage IF an XSS bug exists. Its absence is not a vulnerability by itself — many large sites have none.', "Define a CSP, e.g. default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; base-uri 'self'");
  if (csp) {
    const weak = [];
    if (/'unsafe-inline'/.test(csp) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(csp)) weak.push("'unsafe-inline'");
    if (/'unsafe-eval'/.test(csp)) weak.push("'unsafe-eval'");
    if (/(?:script-src|default-src)[^;]*\s\*(?:\s|;|$)/.test(csp)) weak.push('wildcard *');
    if (weak.length) tip('Content-Security-Policy could be stricter', 'info', `The CSP allows ${weak.join(', ')}, which weakens its XSS protection.`, 'Remove unsafe-inline/unsafe-eval and wildcards; use nonces or hashes.', clip(csp, 200));
  }
  if (isHtml && !h['x-frame-options'] && !(csp && /frame-ancestors/.test(csp))) tip('No anti-framing header (clickjacking protection)', 'low', 'The page can be shown inside another site\'s iframe. This only matters on pages with sensitive one-click actions for logged-in users (e.g. delete account, change email) — test those pages, not the homepage.', "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.");
  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') tip('No X-Content-Type-Options: nosniff', 'info', 'Mainly relevant for sites that serve user-uploaded files.', 'Add: X-Content-Type-Options: nosniff');
  if (isHtml && !h['referrer-policy']) tip('No Referrer-Policy header', 'info', 'Modern browsers already default to strict-origin-when-cross-origin, so this is effectively covered.', 'Optionally add: Referrer-Policy: strict-origin-when-cross-origin', '', 'Privacy');
  if (isHtml && !h['permissions-policy']) tip('No Permissions-Policy header', 'info', 'Lets you explicitly switch off browser features (camera, geolocation…) you do not use.', 'Add a Permissions-Policy that disables unused features.');

  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-runtime']) {
    if (!h[name]) continue;
    const versioned = /\d/.test(h[name]);
    tip(`Technology shown in ${name} header`, versioned ? 'low' : 'info', versioned ? 'Exact versions make it easier to match known CVEs.' : 'Reveals the technology stack. Harmless on its own.', `Remove or genericise the ${name} header.`, `${name}: ${h[name]}`, 'Information Disclosure');
  }

  const acao = h['access-control-allow-origin'];
  const creds = (h['access-control-allow-credentials'] || '') === 'true';
  if (acao === '*' && creds) addFinding(out, { kind: 'vuln', sev: 'high', category: 'Security Misconfiguration', header: true, title: 'CORS allows any origin with credentials',
    detail: 'Misconfigured CORS lets other websites read authenticated responses.', fix: 'Restrict Access-Control-Allow-Origin to trusted origins.', evidence: `access-control-allow-origin: *\naccess-control-allow-credentials: true` });
  else if (acao === '*') tip('CORS open to all origins', 'info', 'Fine for public content; a problem only if this endpoint returns private data.', 'Restrict Access-Control-Allow-Origin if the response is not public.', 'access-control-allow-origin: *');
  else if (acao && acao !== 'null' && creds) addFinding(out, { kind: 'review', sev: 'low', category: 'Security Misconfiguration', header: true, title: 'Credentialed CORS enabled',
    detail: `Origin ${acao} may read authenticated responses. Check the server does not simply echo back any Origin header.`, fix: 'Use a strict allow-list of origins for credentialed CORS.', evidence: `access-control-allow-origin: ${acao}` });

  for (const c of r.setCookies || []) {
    const name = c.split('=')[0].trim();
    const lc = c.toLowerCase();
    // Only cookies that look like login/session cookies need HttpOnly; analytics/preference cookies don't.
    const session = /sess|auth|token|jwt|^sid$|_sid|login|remember|connect\.sid|csrf/i.test(name);
    const noSecure = isHttps && !/;\s*secure/.test(lc);
    const noHttpOnly = !/;\s*httponly/.test(lc);
    if (session && (noHttpOnly || (noSecure && !hasHsts))) {
      const missing = [noHttpOnly && 'HttpOnly', noSecure && 'Secure'].filter(Boolean).join(', ');
      addFinding(out, { kind: 'review', sev: 'medium', category: 'Security Misconfiguration', header: true, title: `Session-like cookie "${name}" missing ${missing}`,
        detail: 'The name suggests a login/session cookie. Without HttpOnly an XSS bug could steal it; without Secure it can leak over HTTP. Confirm it really is a session cookie.',
        evidence: clip(c, 180), fix: 'Set session cookies with Secure; HttpOnly; SameSite=Lax (or Strict).' });
    } else if (noSecure && !hasHsts) {
      tip(`Cookie "${name}" missing Secure flag`, 'info', 'Not a login cookie, and the leak risk is small, but marking every cookie Secure is good practice.', 'Add the Secure attribute.', clip(c, 180));
    }
  }
}

function runQuickScan(r, lang) {
  const out = [];
  sec.ai = []; sec.aiRaw = ''; sec.aiSummary = ''; sec.aiRating = ''; sec.aiMeta = null; sec.showQuick = false;
  if (sec.controller) sec.controller.abort();
  const isHtml = lang === 'html';
  let scripts = [], isHttps = r.finalUrl.startsWith('https:');
  scanHeaders(r, isHtml, out);
  if (r.isText) {
    if (isHtml) ({ scripts, isHttps } = scanHtml(r, out));
    scanSecrets(r.body, out);
    scanDisclosure(r.body, isHttps, out);
    scanCodePatterns(r.body, out);
    scanLibraries(r.body, scripts, out);
  }
  out.sort((a, b) => SEV.indexOf(a.sev) - SEV.indexOf(b.sev));
  sec.quick = out;
  renderSecurity();
}

/* =====================================================================
   2. AI SETTINGS
   ===================================================================== */

const PROVIDERS = {
  anthropic: { label: 'Anthropic (Claude)', model: 'claude-opus-5-5', models: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-4-5', 'claude-fable-5-1'], key: true, keyHint: 'sk-ant-…', base: false },
  openai: { label: 'OpenAI', model: 'gpt-5', models: ['gpt-5', 'gpt-5-mini', 'gpt-4.1', 'gpt-4o'], key: true, keyHint: 'sk-…', base: 'https://api.openai.com/v1' },
  gemini: { label: 'Google Gemini', model: 'gemini-2.5-pro', models: ['gemini-2.5-pro', 'gemini-2.5-flash'], key: true, keyHint: 'AIza…', base: false },
  openrouter: { label: 'OpenRouter', model: '', models: [], key: true, keyHint: 'sk-or-…', base: 'https://openrouter.ai/api/v1', modelHint: 'provider/model-name' },
  groq: { label: 'Groq', model: 'llama-3.3-70b-versatile', models: ['llama-3.3-70b-versatile'], key: true, keyHint: 'gsk_…', base: 'https://api.groq.com/openai/v1' },
  deepseek: { label: 'DeepSeek', model: 'deepseek-chat', models: ['deepseek-chat', 'deepseek-reasoner'], key: true, keyHint: 'sk-…', base: 'https://api.deepseek.com/v1' },
  xai: { label: 'xAI (Grok)', model: 'grok-4', models: ['grok-4'], key: true, keyHint: 'xai-…', base: 'https://api.x.ai/v1' },
  ollama: { label: 'Ollama (local)', model: 'llama3.1', models: [], key: false, base: 'http://localhost:11434/v1' },
  custom: { label: 'Custom (OpenAI-compatible)', model: '', models: [], key: true, keyHint: 'optional', base: '' , modelHint: 'model-name' },
};

const sessionKeys = {};
function loadAiSettings() {
  let s = {};
  try { s = JSON.parse(localStorage.getItem('curlsec-ai') || localStorage.getItem('momal-ai') || '{}'); } catch {}
  return { provider: 'anthropic', models: {}, bases: {}, keys: {}, maxScripts: 5, budget: 200000, remember: true, ...s };
}
let aiSettings = loadAiSettings();
function saveAiSettings() {
  const copy = { ...aiSettings, keys: aiSettings.remember ? aiSettings.keys : {} };
  try { localStorage.setItem('curlsec-ai', JSON.stringify(copy)); localStorage.removeItem('momal-ai'); } catch {}
}
const currentKey = () => aiSettings.keys[aiSettings.provider] || sessionKeys[aiSettings.provider] || '';
const currentModel = () => aiSettings.models[aiSettings.provider] ?? PROVIDERS[aiSettings.provider].model;
const currentBase = () => aiSettings.bases[aiSettings.provider] ?? PROVIDERS[aiSettings.provider].base;

function openAiSettings() {
  const m = $('#aiModal');
  m.classList.add('show');
  $('#aiProvider').innerHTML = Object.entries(PROVIDERS).map(([k, p]) => `<option value="${k}">${p.label}</option>`).join('');
  $('#aiProvider').value = aiSettings.provider;
  $('#aiMaxScripts').value = aiSettings.maxScripts;
  // The budget may have been auto-tuned to a value that isn't in the list — show it anyway.
  if (![...$('#aiBudget').options].some((o) => +o.value === aiSettings.budget)) {
    $('#aiBudget').add(new Option(`${fmtBytes(aiSettings.budget)} (auto-tuned)`, aiSettings.budget), 0);
  }
  $('#aiBudget').value = aiSettings.budget;
  $('#aiRemember').checked = aiSettings.remember;
  $('#mKey').value = currentKey();
  $('#mStatus').className = 'cc-status' + (isConnected() ? ' ok' : '');
  $('#mStatus').textContent = isConnected() ? `✓ Connected to ${PROVIDERS[aiSettings.provider].label} — using ${currentModel()}` : '';
  fillProviderFields();
  if (!isConnected()) setTimeout(() => $('#mKey').focus(), 100);
}
function fillProviderFields() {
  const k = $('#aiProvider').value, p = PROVIDERS[k];
  $('#aiKeyRow').style.display = p.key ? '' : 'none';
  $('#aiKey').placeholder = p.keyHint || '';
  $('#aiKey').value = aiSettings.keys[k] || sessionKeys[k] || '';
  $('#aiModel').value = aiSettings.models[k] ?? p.model;
  $('#aiModel').placeholder = p.modelHint || p.model;
  $('#aiModelList').innerHTML = ((aiSettings.modelLists || {})[k] || p.models).map((x) => `<option value="${x}">`).join('');
  $('#aiBaseRow').style.display = p.base === false ? 'none' : '';
  $('#aiBase').value = aiSettings.bases[k] ?? p.base ?? '';
}
function saveAiModal() {
  const k = $('#aiProvider').value;
  aiSettings.provider = k;
  aiSettings.models[k] = $('#aiModel').value.trim();
  if (PROVIDERS[k].base !== false) aiSettings.bases[k] = $('#aiBase').value.trim();
  aiSettings.maxScripts = +$('#aiMaxScripts').value;
  aiSettings.budget = +$('#aiBudget').value;
  aiSettings.remember = $('#aiRemember').checked;
  const key = $('#aiKey').value.trim();
  sessionKeys[k] = key;
  if (aiSettings.remember) aiSettings.keys[k] = key; else aiSettings.keys = {};
  saveAiSettings();
  $('#aiModal').classList.remove('show');
  updateAiBadge();
  toast('🤖 AI settings saved');
}
/* ---------- One-step connect: paste a key, everything else is automatic ---------- */
function detectProvider(k) {
  k = k.trim();
  if (/^sk-ant-/.test(k)) return 'anthropic';
  if (/^gsk_/.test(k)) return 'groq';
  if (/^AIza/.test(k)) return 'gemini';
  if (/^sk-or-/.test(k)) return 'openrouter';
  if (/^xai-/.test(k)) return 'xai';
  if (/^sk-/.test(k)) return 'openai';
  return null;
}
const isConnected = () => !!currentModel() && (!PROVIDERS[aiSettings.provider].key || !!currentKey() || aiSettings.provider === 'custom');

function showDetected(input, status) {
  const p = detectProvider(input.value);
  status.className = 'cc-status';
  status.textContent = input.value.trim() ? (p ? `Looks like a ${PROVIDERS[p].label} key — press Connect` : 'Press Connect and we will figure out the provider') : '';
}

async function connectKey(input, status, btn) {
  const key = input.value.trim();
  if (!key) { input.focus(); status.className = 'cc-status err'; status.textContent = 'Paste your API key first.'; return; }
  const guess = detectProvider(key);
  status.className = 'cc-status busy';
  status.textContent = `Checking your ${guess ? PROVIDERS[guess].label + ' ' : ''}key…`;
  if (btn) btn.disabled = true;
  try {
    const r = await fetch('/api/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ apiKey: key }) }).then((x) => x.json());
    if (!r.ok) throw new Error(r.error);
    aiSettings.provider = r.provider;
    aiSettings.models[r.provider] = r.model;
    aiSettings.modelLists = { ...(aiSettings.modelLists || {}), [r.provider]: r.models };
    aiSettings.keys[r.provider] = key;
    sessionKeys[r.provider] = key;
    aiSettings.remember = true;
    // Groq's free tier allows only a few thousand tokens per minute — start small (it auto-adjusts later).
    aiSettings.budget = r.provider === 'groq' ? 14000 : 200000;
    aiSettings.maxScripts = r.provider === 'groq' ? 1 : 5;
    saveAiSettings();
    status.className = 'cc-status ok';
    status.textContent = `✓ Connected to ${PROVIDERS[r.provider].label} — using ${r.model}`;
    toast(`✓ AI connected: ${PROVIDERS[r.provider].label}`);
    setTimeout(() => {
      $('#aiModal').classList.remove('show');
      if (last) renderSecurity();
      updateAiBadge();
    }, 900);
  } catch (e) {
    status.className = 'cc-status err';
    status.textContent = '✗ ' + e.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function forgetKey() {
  aiSettings.keys = {};
  for (const k in sessionKeys) delete sessionKeys[k];
  saveAiSettings();
  toast('Key removed from this browser');
  $('#aiModal').classList.remove('show');
  if (last) renderSecurity();
  updateAiBadge();
}

function updateAiBadge() {
  const el = $('#aiModelBadge');
  if (el) el.textContent = isConnected() ? `${PROVIDERS[aiSettings.provider].label.split(' ')[0]} · ${currentModel()}` : 'AI not connected';
  const hb = $('#aiHeaderBtn');
  if (hb) hb.innerHTML = isConnected() ? `<span class="status-dot on"></span><span class="lbl">AI · ${esc(PROVIDERS[aiSettings.provider].label.split(' ')[0])}</span>` : '<span class="status-dot"></span><span class="lbl">Connect AI</span>';
}

/* =====================================================================
   3. AI ANALYSIS
   ===================================================================== */

const SYSTEM_PROMPT = `You are a senior application security engineer performing a passive, read-only security review of a web page's client-side code and HTTP response, on behalf of the site owner or an authorized tester.

Look for real, evidence-backed issues, especially:
- Business-logic flaws visible in client code: authorization or role checks done only in the browser, prices/discounts/quantities trusted from the client, hidden admin features or routes, predictable IDs suggesting IDOR, workflow steps that can be skipped, feature flags that unlock paid/privileged features.
- Sensitive information exposure: API keys, tokens, credentials, secrets, internal hostnames/IPs, staging URLs, emails, personal data, debug output, source maps, revealing comments.
- Injection: DOM-based XSS (trace sources like location/postMessage/storage into sinks like innerHTML/eval), reflected content, template injection, open redirects.
- Authentication & session weaknesses: tokens in localStorage, missing CSRF protection, insecure cookie flags, JWT handling in the client.
- Security misconfiguration: missing/weak security headers, CORS, CSP, clickjacking, mixed content.
- Vulnerable or outdated third-party components with known CVEs.
- Exposed API endpoints worth server-side review.

Rules:
- Only report issues grounded in the provided content. Quote the exact evidence (a short snippet copied verbatim from the code or headers). Never invent code that is not there.
- Verify the automated pre-scan hints: keep the true ones (with better context), silently drop false positives.
- Be precise about severity: critical, high, medium, low, info. Prefer fewer, high-quality findings over noise.
- Classify every finding with "kind":
  * "vulnerability" — a concrete, evidence-backed problem an attacker could actually exploit (e.g. a live secret in the code, a DOM XSS path from URL to sink, a form posting passwords over HTTP).
  * "needs_review" — plausible but cannot be confirmed from this content alone (e.g. client-side role checks that may or may not be enforced server-side).
  * "hardening" — a missing best-practice protection that is NOT exploitable on its own (missing security headers such as CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, nosniff; missing SRI; version banners; non-session cookies without flags).
  Missing security headers are ALWAYS "hardening" unless you can show a concrete exploit path in this content. Cookies that are not login/session cookies (analytics, tracking, preference or anonymous-ID cookies) missing Secure/HttpOnly/SameSite are ALWAYS "hardening". Hardening items are at most severity "low". Framework internals (e.g. Next.js using dangerouslySetInnerHTML for its own JSON) are not findings.
- Be honest: if there are no real vulnerabilities, say so in the summary and use risk_rating "minimal" or "low".
- For each issue explain the impact and give a concrete remediation. Describe how it could be abused at a high level; do not write weaponized exploit payloads.
- Mask secrets in your evidence (keep the first 6 and last 4 characters).

Output ONLY a single JSON object (no markdown fences, no prose before or after) with this exact shape:
{"summary": "2-4 sentence overall assessment", "risk_rating": "critical|high|medium|low|minimal", "findings": [{"title": "...", "kind": "vulnerability|needs_review|hardening", "severity": "critical|high|medium|low|info", "category": "Business Logic|Sensitive Data Exposure|XSS / Injection|Authentication & Authorization|Security Misconfiguration|Vulnerable Components|Insecure Transport|Information Disclosure|Privacy|Attack Surface|Other", "location": "file name / line / element", "evidence": "verbatim snippet", "description": "what is wrong", "impact": "what an attacker could achieve", "recommendation": "how to fix", "cwe": "CWE-79 or empty"}]}`;

const SKIP_SCRIPT_HOSTS = /googletagmanager|google-analytics|googlesyndication|doubleclick|facebook\.net|connect\.facebook|hotjar|clarity\.ms|segment\.(com|io)|cdn\.cookielaw|onetrust|intercom|crisp\.chat|tawk\.to|recaptcha|gstatic\.com\/recaptcha|cloudflareinsights|newrelic|nr-data|sentry-cdn|youtube\.com|ytimg/i;

function aiTerm(line, cls = '') {
  const d = document.createElement('div');
  d.className = 'ai-line ' + cls;
  d.textContent = line;
  $('#aiLog').appendChild(d);
  $('#aiLog').scrollTop = 1e9;
}

async function runAiAnalysis() {
  if (!last) return toast('Curl a URL first');
  if (sec.controller) { sec.controller.abort(); return; }
  if (!isConnected()) {
    const k = $('#ccKey');
    if (k) { const card = k.closest('.connect-card'); card.classList.remove('nudge'); void card.offsetWidth; card.classList.add('nudge'); k.focus(); } else openAiSettings();
    return toast('🔌 Paste your API key first');
  }

  const ctrl = new AbortController();
  sec.controller = ctrl;
  sec.ai = []; sec.aiRaw = ''; sec.aiSummary = ''; sec.aiRating = '';
  renderSecurity();
  $('#aiBox').classList.add('show', 'running');
  $('#aiLog').innerHTML = ''; $('#aiStream').textContent = '';
  setAiButton(true);

  const notes = [];
  try {
    // 1. Gather the main document (what the user sees in the editor) + linked first-party scripts
    const lang = $('#lang').textContent;
    const main = last.isText ? editor.getValue() : '[binary content omitted]';
    const scriptUrls = lang === 'html'
      ? [...$$('.asset')].filter((a) => a.querySelector('.t.js')).map((a) => a.dataset.u)
      : [];
    const host = new URL(last.finalUrl).host;
    const picked = scriptUrls.filter((u) => !SKIP_SCRIPT_HOSTS.test(u))
      .sort((a, b) => (new URL(b).host === host) - (new URL(a).host === host))
      .slice(0, aiSettings.maxScripts);

    aiTerm(`$ curlsec analyze ${last.finalUrl}`, 'cmd');
    const files = [];
    for (const u of picked) {
      if (ctrl.signal.aborted) throw new DOMException('Aborted', 'AbortError');
      aiTerm(`→ fetching ${u}`);
      try {
        const r = await fetch('/api/curl', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: u }), signal: ctrl.signal }).then((x) => x.json());
        if (r.ok && r.isText) { files.push({ url: u, body: r.body }); aiTerm(`  ✓ ${fmtBytes(r.size)}`, 'ok'); }
        else aiTerm(`  ✗ skipped (${r.error || r.contentType})`, 'warn');
      } catch (e) { if (e.name === 'AbortError') throw e; aiTerm('  ✗ ' + e.message, 'warn'); }
    }
    if (scriptUrls.length > picked.length) notes.push(`${scriptUrls.length - picked.length} script(s) not included (analytics/ads or over the ${aiSettings.maxScripts}-file limit).`);

    // 2. Build the prompt for a given code budget (re-built with less code if the model says it's too big)
    const baseNotes = [...notes];
    const buildPrompt = (budget) => {
      const n = [...baseNotes];
      let mainCode = main;
      const mainBudget = files.length ? Math.floor(budget * 0.55) : budget;
      if (mainCode.length > mainBudget) { n.push(`Main document truncated: sent ${fmtBytes(mainBudget)} of ${fmtBytes(mainCode.length)}.`); mainCode = mainCode.slice(0, mainBudget); }
      let remaining = budget - mainCode.length;
      const fileBlocks = files.map((f, i) => {
        const share = Math.max(0, Math.floor(remaining / (files.length - i)));
        let body = f.body;
        if (body.length > share) { n.push(`${f.url.split('/').pop().split('?')[0]} truncated: sent ${fmtBytes(share)} of ${fmtBytes(body.length)}.`); body = body.slice(0, share); }
        remaining -= body.length;
        return body ? `\n## Linked script: ${f.url}\n\`\`\`javascript\n${body}\n\`\`\`\n` : '';
      });
      const hints = sec.quick.filter((f) => f.sev !== 'info').map((f) => `- [${f.sev}] ${f.title}${f.evidence ? ' — ' + clip(f.evidence.replace(/\n/g, ' | '), 140) : ''}`).join('\n') || '- none';
      const prompt = `Perform a passive security review of this web resource.

TARGET URL: ${last.url}
FINAL URL: ${last.finalUrl}
HTTP STATUS: ${last.status} ${last.statusText}
CONTENT-TYPE: ${last.contentType}
${last.redirects.length ? 'REDIRECTS: ' + last.redirects.map((x) => `${x.status} ${x.from} -> ${x.to}`).join(' ; ') + '\n' : ''}
## Response headers
${Object.entries(last.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
${(last.setCookies || []).length ? '\n## Set-Cookie\n' + last.setCookies.join('\n') + '\n' : ''}
## Automated pre-scan hints (verify these)
${hints}
${n.length ? '\n## Notes\n' + n.map((x) => '- ' + x).join('\n') + '\n' : ''}
## Main document (${lang})
\`\`\`${lang}
${mainCode}
\`\`\`
${fileBlocks.join('')}`;
      return { prompt, notes: n };
    };

    // 3. Stream the answer; on "too large" / rate-limit errors shrink or wait and retry automatically
    const TOO_LARGE = /too large|reduce the length|context length|maximum context|context window|tokens per minute|\bTPM\b|^413/i;
    let budget = aiSettings.budget;
    for (let attempt = 0; ; attempt++) {
      const built = buildPrompt(budget);
      const prompt = built.prompt;
      notes.length = 0; notes.push(...built.notes);
      if (attempt === 0) notes.forEach((x) => aiTerm('⚠ ' + x, 'warn'));
      sec.aiMeta = { model: currentModel(), provider: PROVIDERS[aiSettings.provider].label, sent: prompt.length, files: files.length, notes };
      aiTerm(`→ sending ${fmtBytes(prompt.length)} (${files.length + 1} file(s)) to ${currentModel()}`);
      aiTerm('⏳ waiting for the model…', 'dim');
      sec.aiRaw = '';
      try {
        await streamAnalysis(prompt, ctrl, notes);
        if (budget !== aiSettings.budget) { aiSettings.budget = budget; saveAiSettings(); }
        break;
      } catch (e) {
        if (e.name === 'AbortError' || attempt >= 4) throw e;
        const wait = /try again in ([\d.]+)s/i.exec(e.message);
        if (TOO_LARGE.test(e.message)) {
          const lim = /Limit (\d+), Requested (\d+)/i.exec(e.message);
          // Cut the code by the excess tokens (~3.5 chars each) plus a safety margin.
          budget = lim ? Math.floor(budget - (+lim[2] - +lim[1] + 600) * 3.5) : Math.floor(budget / 2.5);
          if (budget < 1500) throw new Error('This model\'s limit is too small for this page. Try another model (AI Settings → Advanced) or a provider with a bigger limit.');
          aiTerm(`↻ Too much code for this model's limit — retrying with ${fmtBytes(budget)} of code`, 'warn');
        } else if (wait && +wait[1] <= 60) {
          aiTerm(`↻ Rate limited — waiting ${Math.ceil(+wait[1])}s and retrying`, 'warn');
          await new Promise((r) => setTimeout(r, (+wait[1] + 1) * 1000));
        } else throw e;
      }
    }

    // 4. Parse
    const parsed = parseAiJson(sec.aiRaw);
    if (!parsed) throw new Error('The model did not return valid JSON. Raw output is shown below.');
    sec.aiSummary = parsed.summary || '';
    sec.aiRating = String(parsed.risk_rating || '').toLowerCase();
    const KIND_MAP = { vulnerability: 'vuln', vuln: 'vuln', needs_review: 'review', review: 'review', hardening: 'hardening' };
    sec.ai = (parsed.findings || []).map((f) => ({
      source: 'ai', kind: KIND_MAP[String(f.kind).toLowerCase()] || 'review',
      sev: SEV.includes(String(f.severity).toLowerCase()) ? String(f.severity).toLowerCase() : 'info',
      title: f.title || 'Untitled finding', category: f.category || 'Other', location: f.location || '', evidence: f.evidence || '',
      detail: f.description || '', impact: f.impact || '', fix: f.recommendation || '', cwe: f.cwe || '', find: f.evidence || '',
    })).map(enforceHardening)
      .map((f) => (f.kind === 'hardening' && SEV.indexOf(f.sev) < SEV.indexOf('low') ? { ...f, sev: 'low' } : f))
      .sort((a, b) => SEV.indexOf(a.sev) - SEV.indexOf(b.sev));
    const nV = sec.ai.filter((f) => f.kind === 'vuln').length;
    aiTerm(`✓ done — ${nV} vulnerabilit${nV === 1 ? 'y' : 'ies'}, ${sec.ai.length - nV} other finding(s)`, 'ok');
    toast(nV ? `🚨 AI confirmed ${nV} vulnerabilit${nV === 1 ? 'y' : 'ies'}` : '✅ AI found no real vulnerabilities');
  } catch (e) {
    if (e.name === 'AbortError') { aiTerm('■ stopped by user', 'warn'); }
    else { aiTerm('✗ ' + e.message, 'err'); toast('AI analysis failed'); sec.aiError = e.message; }
  } finally {
    sec.controller = null;
    $('#aiBox').classList.remove('running');
    setAiButton(false);
    renderSecurity();
    sec.aiError = null;
  }
}

// Send one prompt to /api/analyze and stream the model's answer into sec.aiRaw.
async function streamAnalysis(prompt, ctrl, notes) {
  const res = await fetch('/api/analyze', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: ctrl.signal,
    body: JSON.stringify({ provider: aiSettings.provider, apiKey: currentKey(), model: currentModel(), baseUrl: currentBase(), system: SYSTEM_PROMPT, prompt }),
  });
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = '', started = false, error = null;
  const t0 = performance.now();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      const ev = JSON.parse(line);
      if (ev.type === 'start') aiTerm('✓ connected — model is analyzing', 'ok');
      if (ev.type === 'text') {
        if (!started) { started = true; aiTerm('✍ receiving findings…', 'ok'); }
        sec.aiRaw += ev.text;
        $('#aiStream').textContent = sec.aiRaw.slice(-1800);
        $('#aiCount').textContent = (sec.aiRaw.match(/"severity"\s*:/g) || []).length;
        $('#aiElapsed').textContent = ((performance.now() - t0) / 1000).toFixed(0) + 's';
      }
      if (ev.type === 'error') error = ev.error;
      if (ev.type === 'done' && ev.stop && /max_tokens|length|MAX_TOKENS/.test(ev.stop)) notes.push('The model hit its output limit — the report may be incomplete.');
    }
  }
  if (error) throw new Error(error);
}

// Safety net: models sometimes over-rate missing headers or non-login cookie flags as "vulnerabilities".
const HEADER_TIP_RE = /content.?security.?policy|\bcsp\b|x-frame-options|clickjacking|frame-ancestors|referrer.?policy|permissions.?policy|nosniff|x-content-type|subresource integrity|\bsri\b|strict.?transport|\bhsts\b|server header|x-powered-by|version disclos/i;
const SESSION_COOKIE_RE = /sess|auth|token|jwt|\bsid\b|login|remember|csrf/i;
function enforceHardening(f) {
  if (f.kind === 'hardening') return f;
  const text = `${f.title} ${f.category}`;
  const cookieFlags = /cookie/i.test(text) && /secure|httponly|samesite|flag/i.test(text) && !SESSION_COOKIE_RE.test(`${f.title} ${f.evidence}`);
  return HEADER_TIP_RE.test(text) || cookieFlags ? { ...f, kind: 'hardening' } : f;
}

function parseAiJson(text) {
  let t = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const a = t.indexOf('{'), b = t.lastIndexOf('}');
  if (a < 0 || b < a) return null;
  try { return JSON.parse(t.slice(a, b + 1)); } catch { return null; }
}

function setAiButton(running) {
  const b = $('#aiRunBtn');
  if (!b) return;
  b.innerHTML = running ? icon('stop') + 'Stop analysis' : sec.ai.length ? icon('refresh') + 'Re-run AI analysis' : icon('cpu') + 'Run AI analysis';
  b.classList.toggle('stop', running);
}

/* =====================================================================
   4. RENDERING
   ===================================================================== */

// The grade only counts real vulnerabilities (full weight) and "needs review" items (partial weight).
// Hardening tips never lower the grade.
function scoreOf(list) {
  const s = list.reduce((acc, f) => acc - (f.kind === 'vuln' ? SEV_WEIGHT[f.sev] : f.kind === 'review' ? SEV_WEIGHT[f.sev] * 0.4 : 0), 100);
  return Math.max(0, Math.round(s));
}
const gradeOf = (s) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F');
const gradeColor = (g) => ({ A: 'var(--ok)', B: '#a3e635', C: 'var(--warn)', D: '#fb923c', F: 'var(--err)' }[g]);
const byKind = (list) => Object.fromEntries(KINDS.map((k) => [k, list.filter((f) => f.kind === k)]));
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function findingCard(f, i) {
  const canGo = f.find && editor && editor.getModel().findMatches(f.find.split('\n')[0].slice(0, 80), false, false, false, null, false, 1).length;
  const pill = f.kind === 'hardening' ? 'tip' : f.sev;
  return `<div class="finding kind-${f.kind} sev-${f.kind === 'hardening' ? 'info' : f.sev}" style="animation-delay:${Math.min(i, 20) * 35}ms">
    <div class="f-head" onclick="this.parentElement.classList.toggle('open')">
      <span class="sev-pill">${pill}</span>
      <span class="f-title">${esc(f.title)}</span>
      <span class="f-cat">${esc(f.category)}${f.cwe ? ' · ' + esc(f.cwe) : ''}</span>
      <span class="chev">${icon('chevron')}</span>
    </div>
    <div class="f-body"><div>
      ${f.location ? `<div class="f-loc">${icon('pin')}${esc(f.location)}</div>` : ''}
      ${f.detail ? `<p>${esc(f.detail)}</p>` : ''}
      ${f.evidence ? `<pre class="f-ev">${esc(f.evidence)}</pre>` : ''}
      ${f.impact ? `<div class="f-row"><b>Impact</b><span>${esc(f.impact)}</span></div>` : ''}
      ${f.fix ? `<div class="f-row fix"><b>Fix</b><span>${esc(f.fix)}</span></div>` : ''}
      ${canGo ? `<button class="tbtn goto" data-find="${esc(f.find.split('\n')[0].slice(0, 80))}">${icon('code')}Show in code</button>` : ''}
    </div></div>
  </div>`;
}

function groupsHtml(list, prefix) {
  const g = byKind(list);
  const section = (k) => {
    if (!g[k].length) return '';
    const m = KIND_META[k];
    const cards = g[k].map(findingCard).join('');
    if (k === 'hardening') {
      return `<details class="group group-hardening" id="${prefix}-${k}">
        <summary><span class="g-title">${icon(m.icon)} ${m.title} <span class="g-count">${g[k].length}</span></span><span class="g-sub">${m.sub}</span></summary>
        <div class="findings">${cards}</div>
      </details>`;
    }
    return `<div class="group group-${k}" id="${prefix}-${k}">
      <div class="g-head"><span class="g-title">${icon(m.icon)} ${m.title} <span class="g-count">${g[k].length}</span></span><span class="g-sub">${m.sub}</span></div>
      <div class="findings">${cards}</div>
    </div>`;
  };
  return KINDS.map(section).join('') || '<div class="empty small">Nothing flagged.</div>';
}

function renderSecurity() {
  const view = $('#securityView');
  if (!view) return;
  const usingAi = sec.ai.length > 0;
  const list = usingAi ? sec.ai : sec.quick;
  const g = byKind(list);
  const nV = g.vuln.length, nR = g.review.length, nH = g.hardening.length;
  const score = scoreOf(list), grade = gradeOf(score), color = gradeColor(grade);
  const C = 2 * Math.PI * 52;

  const badge = $('#sCount');
  badge.textContent = nV || nR || '✓';
  badge.className = 'badge ' + (nV ? 'sev-badge-high' : nR ? 'sev-badge-medium' : 'sev-badge-ok');

  const headline = nV
    ? `<span class="hl hl-bad">${icon('alert')}${plural(nV, 'vulnerability', 'vulnerabilities')} found</span>`
    : `<span class="hl hl-good">${icon('shieldCheck')}No ${nR ? 'confirmed ' : ''}vulnerabilities found</span>`;
  const subline = [nR && `${plural(nR, 'item needs', 'items need')} a manual check`, nH && `${plural(nH, 'hardening tip', 'hardening tips')} (optional)`].filter(Boolean).join(' · ');

  view.innerHTML = `
  <div class="sec">
    <div class="sec-top">
      <div class="ring" title="Grade counts only real vulnerabilities and items needing review — hardening tips don't lower it.">
        <svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" class="ring-bg"/><circle cx="60" cy="60" r="52" class="ring-fg" style="stroke:${color};stroke-dasharray:${C};stroke-dashoffset:${C}" data-off="${C * (1 - score / 100)}"/></svg>
        <div class="ring-txt"><b style="color:${color}">${grade}</b><span>${score}/100</span></div>
      </div>
      <div class="sec-sum">
        <div class="sec-h">${headline} <span class="host">${esc(new URL(last.finalUrl).host)}</span></div>
        ${subline ? `<div class="sec-subline">${subline}</div>` : ''}
        <div class="kind-pills">
          <button class="kind-pill kp-vuln" data-jump="${usingAi ? 'ai' : 'q'}-vuln" ${nV ? '' : 'disabled'}>${icon('alert')}<b>${nV}</b> vulnerabilities</button>
          <button class="kind-pill kp-review" data-jump="${usingAi ? 'ai' : 'q'}-review" ${nR ? '' : 'disabled'}>${icon('search')}<b>${nR}</b> need review</button>
          <button class="kind-pill kp-hardening" data-jump="${usingAi ? 'ai' : 'q'}-hardening" ${nH ? '' : 'disabled'}>${icon('shield')}<b>${nH}</b> hardening tips</button>
        </div>
        ${sec.aiSummary ? `<p class="ai-summary"><b>AI verdict${sec.aiRating ? ` — <span class="rating r-${esc(sec.aiRating)}">${esc(sec.aiRating)} risk</span>` : ''}:</b> ${esc(sec.aiSummary)}</p>`
          : `<p class="muted">These results come from a quick pattern scan. Run the AI analysis to verify them and look for logic flaws.</p>`}
      </div>
      <div class="sec-actions">
        <button class="ai-btn ${sec.controller ? 'stop' : ''}" id="aiRunBtn">${sec.controller ? icon('stop') + 'Stop analysis' : usingAi ? icon('refresh') + 'Re-run AI analysis' : icon('cpu') + 'Run AI analysis'}</button>
        <button class="tbtn" id="aiSetBtn"><span class="status-dot ${isConnected() ? 'on' : ''}"></span><span id="aiModelBadge"></span></button>
        <button class="tbtn" id="secExport">${icon('download')}Export report</button>
      </div>
    </div>

    ${!isConnected() ? connectCardHtml('cc') : ''}

    <div class="ai-box ${sec.controller ? 'show running' : sec.aiRaw || sec.aiError ? 'show' : ''}" id="aiBox">
      <div class="ai-box-head"><span class="scan-dot"></span> AI analysis <span class="muted">· <span id="aiCount">${sec.ai.length || 0}</span> finding(s) · <span id="aiElapsed">0s</span></span></div>
      <div class="ai-cols"><div class="ai-log" id="aiLog">${$('#aiLog') ? $('#aiLog').innerHTML : ''}</div><pre class="ai-stream" id="aiStream">${esc(sec.aiRaw.slice(-1800))}</pre></div>
      <div class="scanline"></div>
    </div>

    ${!usingAi && sec.aiRaw && !sec.controller ? `<div class="sec-title">Raw AI output</div><pre class="f-ev raw">${esc(sec.aiRaw)}</pre>` : ''}
    ${sec.aiMeta?.notes?.length && !sec.controller ? `<div class="sec-note">${icon('info')}<div>${sec.aiMeta.notes.map(esc).join('<br>')}</div></div>` : ''}

    ${usingAi
      ? `<div class="sec-title">${icon('cpu')}Verified by AI <span class="muted">· ${esc(sec.aiMeta?.provider || '')} ${esc(sec.aiMeta?.model || '')}</span></div>
         ${groupsHtml(sec.ai, 'ai')}
         <details class="quick-wrap"><summary>${icon('chevron')}Show the original quick-scan results (${sec.quick.length})</summary>${groupsHtml(sec.quick, 'q')}</details>`
      : `<div class="sec-title">${icon('bolt')}Quick scan <span class="muted">· runs on your computer, nothing is sent anywhere</span></div>
         ${groupsHtml(sec.quick, 'q')}`}
  </div>`;

  updateAiBadge();
  requestAnimationFrame(() => requestAnimationFrame(() => { const fg = view.querySelector('.ring-fg'); if (fg) fg.style.strokeDashoffset = fg.dataset.off; }));
}

function connectCardHtml(id) {
  return `<div class="connect-card">
    <div class="cc-title">${icon('plug')}Connect an AI model in one step</div>
    <div class="cc-sub">Paste an API key from <b>Groq</b> (free), OpenAI, Claude, Gemini, OpenRouter, xAI or DeepSeek. We detect the provider and pick the best model automatically.</div>
    <div class="cc-row">
      <input id="${id}Key" class="cc-input" type="password" placeholder="Paste your API key here…" autocomplete="off" spellcheck="false" />
      <button class="ai-btn cc-btn" id="${id}Connect" type="button">Connect</button>
    </div>
    <div class="cc-status" id="${id}Status"></div>
    <div class="cc-help">No key yet? <a href="https://console.groq.com/keys" target="_blank" rel="noopener">Get a free Groq key</a> · <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener">Free Gemini key</a></div>
  </div>`;
}

function exportReport() {
  if (!last) return;
  const sect = (title, list) => !list.length ? '' : `\n## ${title}\n\n` + list.map((f) =>
    `### [${f.sev.toUpperCase()}] ${f.title}\n- **Category:** ${f.category}${f.cwe ? ` (${f.cwe})` : ''}\n${f.location ? `- **Location:** ${f.location}\n` : ''}${f.detail ? `\n${f.detail}\n` : ''}${f.evidence ? `\n\`\`\`\n${f.evidence}\n\`\`\`\n` : ''}${f.impact ? `\n**Impact:** ${f.impact}\n` : ''}${f.fix ? `\n**Fix:** ${f.fix}\n` : ''}`).join('\n');
  const list = sec.ai.length ? sec.ai : sec.quick;
  const g = byKind(list);
  const md = `# CurlSec findings — ${last.finalUrl}\n\nGenerated by CurlSec on ${new Date().toLocaleString()}\n\n` +
    `- HTTP ${last.status} ${last.statusText} · ${last.contentType}\n- Grade: ${gradeOf(scoreOf(list))} (${scoreOf(list)}/100)\n` +
    `- Source: ${sec.ai.length ? 'AI-verified (' + sec.aiMeta.provider + ' ' + sec.aiMeta.model + ')' : 'quick pattern scan'}\n` +
    `- ${g.vuln.length} vulnerabilities · ${g.review.length} need review · ${g.hardening.length} hardening tips\n` +
    (sec.aiSummary ? `\n> ${sec.aiSummary}\n` : '') +
    KINDS.map((k) => sect(`${KIND_META[k].icon} ${KIND_META[k].title}`, g[k]) + (g[k].length ? `\n_${KIND_META[k].sub}_\n` : '')).join('');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }));
  a.download = 'curlsec-findings_' + new URL(last.finalUrl).hostname.replace(/\W+/g, '_') + '.md';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('⬇ Report exported');
}

/* ---------- Events ---------- */
document.addEventListener('click', (e) => {
  const t = e.target;
  if (t.closest('#aiRunBtn')) return runAiAnalysis();
  if (t.closest('#aiSetBtn') || t.closest('#aiHeaderBtn')) return openAiSettings();
  if (t.closest('#secExport')) return exportReport();
  const jump = t.closest('.kind-pill');
  if (jump) {
    const el = document.getElementById(jump.dataset.jump);
    if (el) { if (el.tagName === 'DETAILS') el.open = true; const q = el.closest('details.quick-wrap'); if (q) q.open = true; el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    return;
  }
  const go = t.closest('.goto');
  if (go) {
    const m = editor.getModel().findMatches(go.dataset.find, false, false, false, null, false, 1)[0];
    if (!m) return toast('Snippet not found in the editor');
    setTab('code');
    setTimeout(() => {
      editor.revealRangeInCenter(m.range, 0);
      editor.setSelection(m.range);
      const deco = editor.createDecorationsCollection([{ range: m.range, options: { isWholeLine: true, className: 'flash-line' } }]);
      setTimeout(() => deco.clear(), 2500);
      editor.focus();
    }, 120);
  }
  if (t.id === 'aiModal' || t.closest('#aiCancel')) $('#aiModal').classList.remove('show');
  if (t.closest('#aiSave')) saveAiModal();
  if (t.closest('#ccConnect')) connectKey($('#ccKey'), $('#ccStatus'), t.closest('#ccConnect'));
  if (t.closest('#mConnect')) connectKey($('#mKey'), $('#mStatus'), t.closest('#mConnect'));
  if (t.closest('#aiForget')) forgetKey();
  if (t.closest('#aiKeyEye')) { const k = $('#aiKey'); k.type = k.type === 'password' ? 'text' : 'password'; }
});
document.addEventListener('change', (e) => { if (e.target.id === 'aiProvider') fillProviderFields(); });
// Paste a key → detect it → connect automatically. Enter also connects.
for (const p of ['cc', 'm']) {
  document.addEventListener('input', (e) => { if (e.target.id === p + 'Key') showDetected(e.target, $('#' + p + 'Status')); });
  document.addEventListener('paste', (e) => {
    if (e.target.id !== p + 'Key') return;
    setTimeout(() => connectKey(e.target, $('#' + p + 'Status'), $('#' + p + 'Connect')), 150);
  });
  document.addEventListener('keydown', (e) => {
    if (e.target.id === p + 'Key' && e.key === 'Enter') { e.preventDefault(); connectKey(e.target, $('#' + p + 'Status'), $('#' + p + 'Connect')); }
  });
}
document.addEventListener('DOMContentLoaded', updateAiBadge);
if (document.readyState !== 'loading') updateAiBadge();
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('#aiModal')?.classList.remove('show'); });
