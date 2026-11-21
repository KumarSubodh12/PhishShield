/*!
 * PhishShield - URL analyzer (heuristic phishing detector)
 *
 * Works in the browser (window.PhishShield.UrlAnalyzer) and in Node (require).
 * It NEVER opens or fetches the URL being analysed - it only inspects the text,
 * so pasting a malicious link here is safe.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishShield = root.PhishShield || {};
    root.PhishShield.UrlAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Reference data
  // ---------------------------------------------------------------------------

  // Brands that phishers love to imitate. `keywords` are the names to look for
  // inside a hostname, `domains` are the genuine registered domains.
  const BRANDS = [
    { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com'] },
    { name: 'Google', keywords: ['google', 'gmail'], domains: ['google.com', 'google.co.in', 'gmail.com'] },
    { name: 'Microsoft', keywords: ['microsoft', 'outlook', 'office365'], domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'] },
    { name: 'Apple', keywords: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', keywords: ['amazon'], domains: ['amazon.com', 'amazon.in', 'amazon.co.uk'] },
    { name: 'Facebook', keywords: ['facebook'], domains: ['facebook.com', 'fb.com', 'messenger.com'] },
    { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com'] },
    { name: 'WhatsApp', keywords: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net'] },
    { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com'] },
    { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com'] },
    { name: 'GitHub', keywords: ['github'], domains: ['github.com', 'githubusercontent.com', 'githubassets.com'] },
    { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'Twitter / X', keywords: ['twitter'], domains: ['twitter.com', 'x.com'] },
    { name: 'Paytm', keywords: ['paytm'], domains: ['paytm.com'] },
    { name: 'PhonePe', keywords: ['phonepe'], domains: ['phonepe.com'] },
    { name: 'Flipkart', keywords: ['flipkart'], domains: ['flipkart.com'] },
    { name: 'State Bank of India', keywords: ['sbi', 'onlinesbi'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbicard.com'] },
    { name: 'HDFC Bank', keywords: ['hdfc', 'hdfcbank'], domains: ['hdfcbank.com', 'hdfc.com'] },
    { name: 'ICICI Bank', keywords: ['icici', 'icicibank'], domains: ['icicibank.com'] },
    { name: 'IRCTC', keywords: ['irctc'], domains: ['irctc.co.in', 'irctc.com'] },
    { name: 'UIDAI (Aadhaar)', keywords: ['uidai', 'aadhaar', 'aadhar'], domains: ['uidai.gov.in'] },
    { name: 'Income Tax India', keywords: ['incometax', 'incometaxindia'], domains: ['incometax.gov.in', 'incometaxindia.gov.in'] }
  ];

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 'lnkd.in'
  ]);

  // TLDs that are cheap/free and heavily abused in phishing campaigns.
  const RISKY_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'zip', 'mov', 'work',
    'support', 'country', 'kim', 'loan', 'men', 'party', 'review', 'science',
    'stream', 'download', 'racing', 'win', 'bid', 'icu', 'cyou', 'buzz', 'rest', 'monster'
  ]);

  // Second-level public suffixes, so "bank.co.in" is treated as one registered domain.
  const MULTI_SUFFIX = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'org.in', 'net.in', 'ac.in',
    'gov.in', 'nic.in', 'edu.in', 'res.in', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'com.br', 'com.cn', 'co.za', 'com.sg', 'com.mx',
    'co.kr', 'com.pk', 'com.bd'
  ]);

  const SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'security', 'account',
    'update', 'confirm', 'banking', 'password', 'wallet', 'billing', 'invoice',
    'suspend', 'suspended', 'unlock', 'recover', 'helpdesk', 'alert',
    'authenticate', 'credential', 'refund', 'prize', 'reward', 'bonus', 'gift',
    'claim', 'otp', 'kyc', 'free', 'support'
  ];

  const REDIRECT_PARAMS = /^(url|redirect|redirect_uri|redirecturl|next|return|returnurl|goto|dest|destination|continue|link)$/i;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /** Classic dynamic-programming edit distance. */
  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    let prev = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = cur;
    }
    return prev[b.length];
  }

  /** Undo common look-alike tricks: paypa1 -> paypal, rnicrosoft -> microsoft. */
  function leetVariants(token) {
    const bases = [token, token.replace(/rn/g, 'm').replace(/vv/g, 'w')];
    const out = new Set();
    for (const base of bases) {
      for (const one of ['l', 'i']) {
        out.add(base.replace(/[013457]/g, (c) => ({ '0': 'o', '1': one, '3': 'e', '4': 'a', '5': 's', '7': 't' }[c] || c)));
      }
    }
    return Array.from(out);
  }

  /** "example.co.in" -> "example.co.in", "a.b.example.com" -> "example.com" */
  function getRegisteredDomain(host) {
    const labels = host.split('.').filter(Boolean);
    if (labels.length <= 2) return labels.join('.');
    const lastTwo = labels.slice(-2).join('.');
    return MULTI_SUFFIX.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
  }

  /** Make a URL safe to copy into reports / chats (hxxp://evil[.]com). */
  function defang(text) {
    return String(text).replace(/^http/i, (m) => (m === m.toUpperCase() ? 'HXXP' : 'hxxp')).replace(/\./g, '[.]');
  }

  /** Accepts messy input: defanged links, missing scheme, wrapped in <>/quotes. */
  function normalizeInput(raw) {
    let text = String(raw).trim().replace(/^[<\["'(]+|[>\]"')]+$/g, '');
    text = text.replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)/g, '.');
    if (/^(javascript|data|vbscript):/i.test(text)) return { text, assumedScheme: false };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return { text: 'http://' + text.replace(/^\/\//, ''), assumedScheme: true };
    return { text, assumedScheme: false };
  }

  function tokenMatches(token, word) {
    return word.length <= 4 ? token === word : token.includes(word);
  }

  function findOfficialBrand(registered) {
    return BRANDS.find((b) => b.domains.includes(registered)) || null;
  }

  /** Does this host imitate `brand` without being its real domain? */
  function matchImpersonation(tokens, brand) {
    for (const keyword of brand.keywords) {
      for (const token of tokens) {
        if (token === keyword) {
          return { brand, kind: 'brand-name', keyword, token };
        }
        if (token !== keyword && leetVariants(token).includes(keyword)) {
          return { brand, kind: 'lookalike', keyword, token };
        }
        if (keyword.length >= 6 && token.length >= 6 && levenshtein(token, keyword) === 1) {
          return { brand, kind: 'typosquat', keyword, token };
        }
        if (keyword.length >= 6 && token.includes(keyword)) {
          return { brand, kind: 'embedded', keyword, token };
        }
      }
    }
    return null;
  }

  const IMPERSONATION_TEXT = {
    'brand-name': (m) => `The name "${m.keyword}" appears in the hostname, but the site is not ${m.brand.name}'s real domain (${m.brand.domains[0]}).`,
    lookalike: (m) => `"${m.token}" looks like "${m.keyword}" with swapped characters (digits or rn/vv tricks) - a classic look-alike domain.`,
    typosquat: (m) => `"${m.token}" is one typo away from "${m.keyword}" - typical typosquatting of ${m.brand.name}.`,
    embedded: (m) => `"${m.token}" hides the name "${m.keyword}" inside a longer word to look like ${m.brand.name}.`
  };

  function levelFor(score) {
    if (score >= 55) return { level: 'high', verdict: 'High risk - likely phishing' };
    if (score >= 30) return { level: 'medium', verdict: 'Suspicious - be careful' };
    return { level: 'low', verdict: 'Low risk - no strong red flags' };
  }

  // ---------------------------------------------------------------------------
  // Main entry point
  // ---------------------------------------------------------------------------

  function analyze(raw) {
    const input = String(raw == null ? '' : raw).trim();
    if (!input) return { ok: false, error: 'Please paste a URL to analyze.' };
    if (input.length > 2048) return { ok: false, error: 'URL is too long (max 2048 characters).' };

    const { text, assumedScheme } = normalizeInput(input);
    const findings = [];
    const add = (id, severity, title, detail, points) => findings.push({ id, severity, title, detail, points: points || 0 });

    // Script / data URLs are executable content, not web pages.
    if (/^(javascript|data|vbscript):/i.test(text)) {
      add('dangerous-scheme', 'high', 'Executable or inline content',
        'This is not a normal web address. javascript:/data: links can run code or show a fake page inside your browser.', 80);
      return { ok: true, input, url: null, host: '', registeredDomain: '', score: 80, ...levelFor(80), findings, defanged: defang(text), officialBrand: null };
    }

    let url;
    try {
      url = new URL(text);
    } catch (e) {
      return { ok: false, error: 'Could not understand this as a URL. Check for typos.' };
    }

    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!host) return { ok: false, error: 'No hostname found in this URL.' };

    const registered = getRegisteredDomain(host);
    const labels = host.split('.');
    const regLabels = registered.split('.');
    const tld = labels[labels.length - 1];
    const officialBrand = findOfficialBrand(registered);
    const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const isIPv6 = host.startsWith('[');
    const pathText = decodeSafe(url.pathname).toLowerCase();
    const queryText = decodeSafe(url.search).toLowerCase();

    // 1. IP address instead of a domain name
    if (isIPv4 || isIPv6) {
      add('ip-host', 'high', 'IP address instead of a domain name',
        'Real companies use domain names. A raw IP address hides who owns the server.', 30);
    }

    // 2. user:pass@host trick
    if (url.username || url.password) {
      add('at-symbol', 'high', 'Hidden "@" in the address',
        `Browsers ignore everything before "@". "${url.username}" is only decoration - you would actually visit ${host}.`, 25);
    }

    // 3. Punycode / homograph attack
    if (labels.some((l) => l.startsWith('xn--'))) {
      add('punycode', 'high', 'Look-alike (homograph) characters',
        'The domain uses international characters that can mimic English letters (e.g. Cyrillic "a" vs Latin "a").', 30);
    }

    // 4. Scheme / HTTPS
    if (url.protocol === 'https:') {
      add('https', 'good', 'Uses HTTPS',
        'Traffic is encrypted. Note: many phishing sites also have HTTPS, so this alone does not prove safety.', 0);
    } else if (url.protocol === 'http:' && !assumedScheme) {
      add('no-https', 'medium', 'Not using HTTPS',
        'The connection is unencrypted - anything you type (passwords, OTPs) can be read on the network.', 10);
    } else if (assumedScheme) {
      add('no-scheme', 'info', 'No http/https given', 'The HTTPS check was skipped because the link had no scheme.', 0);
    } else {
      add('odd-scheme', 'medium', `Unusual scheme "${url.protocol}"`, 'Phishing links are almost always http or https.', 10);
    }

    // 5. Risky TLD
    if (!isIPv4 && !isIPv6 && RISKY_TLDS.has(tld)) {
      add('risky-tld', 'medium', `Risky domain ending ".${tld}"`,
        'This ending is cheap or free and is heavily abused for scam and phishing sites.', 12);
    }

    // 6. URL shortener
    if (SHORTENERS.has(registered)) {
      add('shortener', 'medium', 'URL shortener',
        'The real destination is hidden, so this tool cannot judge it. Use a "link expander" before you open it.', 30);
    }

    // 7. Too many subdomains
    const subdomainCount = isIPv4 || isIPv6 ? 0 : labels.length - regLabels.length;
    if (subdomainCount >= 4) {
      add('subdomains', 'medium', `${subdomainCount} subdomain levels`,
        'Long chains like login.secure.account.example.com push the real domain out of sight.', 12);
    } else if (subdomainCount === 3) {
      add('subdomains', 'low', '3 subdomain levels', 'Deep subdomain nesting is a mild warning sign.', 6);
    }

    // 8. Hyphens in host
    const hyphens = (host.replace(/xn--/g, '').match(/-/g) || []).length;
    if (hyphens >= 3) {
      add('hyphens', 'medium', `${hyphens} hyphens in the domain`, 'Phishers chain words like "secure-login-update-bank".', 8);
    } else if (hyphens === 2) {
      add('hyphens', 'low', '2 hyphens in the domain', 'Hyphen-separated lookalike names are common in phishing.', 4);
    }

    // 9. Very long domain label
    if (Math.max(...labels.map((l) => l.length)) >= 25) {
      add('long-label', 'low', 'Very long domain part', 'Unusually long or random-looking names are typical of throwaway domains.', 6);
    }

    // 10. URL length
    if (input.length >= 100) {
      add('long-url', 'medium', `Very long URL (${input.length} characters)`, 'Long URLs make it easy to bury the real destination.', 8);
    } else if (input.length >= 75) {
      add('long-url', 'low', `Long URL (${input.length} characters)`, 'Slightly long address.', 4);
    }

    // 11. Non-standard port
    if (url.port) {
      add('port', 'medium', `Unusual port :${url.port}`, 'Normal sites use the default web ports (80/443).', 10);
    }

    // 12. Percent-encoding obfuscation
    const encoded = (url.pathname + url.search).match(/%[0-9a-f]{2}/gi) || [];
    if (encoded.length >= 3) {
      add('encoding', 'low', `${encoded.length} percent-encoded characters`, 'Heavy encoding can hide what the link really does.', 6);
    }

    // 13. Redirect-style parameters
    for (const [key, value] of url.searchParams) {
      if (REDIRECT_PARAMS.test(key) && /^(https?:)?\/\//i.test(value.trim())) {
        add('redirect-param', 'medium', 'Redirect to another site inside the link',
          `The "${key}" parameter sends you onward to ${value.slice(0, 60)}. Attackers abuse trusted sites this way.`, 10);
        break;
      }
    }

    // 14. A second URL / trusted domain hidden in the path
    if (/(https?:\/\/|www\.)/i.test(pathText)) {
      add('url-in-path', 'medium', 'Another web address inside the path',
        'A second URL after the domain is a trick to look like a different site.', 10);
    } else {
      const spoofed = BRANDS.find((b) => b !== officialBrand && b.domains.some((d) => pathText.includes(d)));
      if (spoofed) {
        add('brand-in-path', 'medium', `${spoofed.name}'s domain name placed in the path`,
          'e.g. evil.com/paypal.com/login - the part after the first "/" does not change who owns the site.', 30);
      }
    }

    // 15. Brand impersonation (only if not the genuine domain)
    const tokens = host.split(/[.\-_]/).filter(Boolean);
    if (officialBrand) {
      add('official', 'good', `Matches ${officialBrand.name}'s official domain`,
        `${registered} is on the list of genuine ${officialBrand.name} domains. The domain is real, but the page itself could still be user-generated content - check the content too.`, 0);
    }
    if (!isIPv4 && !isIPv6) {
      for (const brand of BRANDS) {
        if (brand === officialBrand) continue;
        const match = matchImpersonation(tokens, brand);
        if (match) {
          const strong = match.kind === 'lookalike' || match.kind === 'typosquat';
          add('impersonation', 'high', `Possible ${brand.name} impersonation`, IMPERSONATION_TEXT[match.kind](match), strong ? 45 : 40);
          break;
        }
      }
    }

    // 16. Scam vocabulary (skipped for genuine brand domains)
    if (!officialBrand) {
      const hostTokens = tokens;
      const pathTokens = (pathText + ' ' + queryText).split(/[^a-z0-9]+/).filter(Boolean);
      const hostHits = new Set();
      const pathHits = new Set();
      for (const word of SUSPICIOUS_WORDS) {
        if (hostTokens.some((t) => tokenMatches(t, word))) hostHits.add(word);
        else if (pathTokens.some((t) => tokenMatches(t, word))) pathHits.add(word);
      }
      const pts = Math.min(hostHits.size * 6, 18) + Math.min(pathHits.size * 3, 9);
      if (pts > 0) {
        const all = [...hostHits, ...pathHits];
        add('keywords', hostHits.size ? 'medium' : 'low', 'Pressure / credential words',
          `Words often used to push you into acting: ${all.join(', ')}.`, pts);
      }
    }

    const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
    const hasRedFlags = findings.some((f) => f.points > 0);
    if (!hasRedFlags) {
      add('clean', 'good', 'No obvious red flags', 'None of the checks fired. Stay careful - heuristics cannot prove a site is safe.', 0);
    }

    // Worst findings first, good news last.
    const order = { high: 0, medium: 1, low: 2, info: 3, good: 4 };
    findings.sort((a, b) => order[a.severity] - order[b.severity] || b.points - a.points);

    return {
      ok: true,
      input,
      url: url.href,
      host,
      registeredDomain: registered,
      score,
      ...levelFor(score),
      findings,
      defanged: defang(url.href),
      officialBrand: officialBrand ? officialBrand.name : null
    };
  }

  function decodeSafe(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  return { analyze, normalizeInput, getRegisteredDomain, levenshtein, leetVariants, defang, BRANDS };
});
