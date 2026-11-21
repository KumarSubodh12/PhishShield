/*!
 * PhishShield - Password auditor
 *
 *  - estimates strength (entropy, patterns, common passwords, crack time)
 *  - checks the Have I Been Pwned breach database using k-anonymity
 *    (only the first 5 characters of the SHA-1 hash ever leave your device)
 *  - generates strong random passwords with crypto.getRandomValues
 *
 * Works in the browser (window.PhishShield.PasswordAuditor) and in Node (require).
 * The password is never stored, logged or sent anywhere in plain text.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishShield = root.PhishShield || {};
    root.PhishShield.PasswordAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Most-used passwords, roughly in order of popularity (rank = index + 1).
  const COMMON = [
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111',
    '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein',
    '696969', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890',
    'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx',
    '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter',
    'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
    'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', '112233',
    'george', 'computer', 'michelle', 'jessica', 'pepper', 'zxcvbn', '555555', '11111111',
    '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger',
    'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole',
    'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin',
    'thunder', 'taylor', 'matrix', 'admin', 'welcome', 'login', 'passw0rd', 'password1',
    'password123', 'admin123', 'qwerty123', 'letmein123', 'whatever', 'monkey123',
    'abcd1234', 'test', 'test123', 'root', 'toor', 'guest', 'changeme', 'default',
    'secret', 'india', 'india123', 'cricket', 'sachin', 'krishna', 'ganesh', 'rahul',
    'mumbai', 'delhi', 'bollywood', 'iloveindia', 'ilovecricket', 'college', 'student'
  ];
  const COMMON_RANK = new Map(COMMON.map((word, i) => [word, i + 1]));

  // Everyday words / names: not "top passwords", but still in every cracking dictionary.
  const DICTIONARY = [
    'rohit', 'amit', 'priya', 'rohan', 'ankit', 'neha', 'pooja', 'virat', 'dhoni', 'arjun',
    'aman', 'ravi', 'sunil', 'vijay', 'sanjay', 'ajay', 'deepak', 'anil', 'suresh', 'ramesh',
    'shiva', 'lakshmi', 'pune', 'bangalore', 'chennai', 'kolkata', 'hyderabad', 'school',
    'hello', 'user', 'family', 'friends', 'friend', 'house', 'happy', 'lucky', 'angel',
    'flower', 'purple', 'orange', 'yellow', 'tiger', 'lion', 'cool', 'king', 'queen',
    'music', 'cricket', 'hacker', 'cyber', 'security', 'internet', 'google', 'facebook'
  ];
  DICTIONARY.forEach((w) => { if (!COMMON_RANK.has(w)) COMMON_RANK.set(w, 1500); });

  const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];

  const ATTACKS = [
    { id: 'online', label: 'Online login, rate-limited', rate: 100 },
    { id: 'slow', label: 'Stolen database, bcrypt hash', rate: 1e4 },
    { id: 'fast', label: 'Stolen database, fast hash (GPU)', rate: 1e10 }
  ];

  const LEVELS = [
    { score: 0, label: 'Very weak' },
    { score: 1, label: 'Weak' },
    { score: 2, label: 'Fair' },
    { score: 3, label: 'Strong' },
    { score: 4, label: 'Very strong' }
  ];

  // ---------------------------------------------------------------------------
  // Strength analysis
  // ---------------------------------------------------------------------------

  function poolSize(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    return pool;
  }

  /** p@ssw0rd -> password (digit 1 is left alone so "password1" still matches). */
  function deLeet(text) {
    return text.replace(/[@04357$!]/g, (c) => ({ '@': 'a', '0': 'o', '4': 'a', '3': 'e', '5': 's', '7': 't', '$': 's', '!': 'i' }[c]));
  }

  /**
   * Looks the password up in the common-password / dictionary list, also trying
   * the "leet" version and ignoring a short number/symbol tail (rahul@2004).
   * Returns { rank, bits, word } or null.
   */
  function dictionaryHit(pw) {
    const lower = pw.toLowerCase();
    const variants = [lower, deLeet(lower)];
    let best = null;
    for (const v of variants) {
      if (COMMON_RANK.has(v)) {
        const rank = COMMON_RANK.get(v);
        const bits = Math.log2(rank + 1) + (v === lower ? 0 : 2);
        if (!best || bits < best.bits) best = { rank, bits, word: v, exact: true };
      }
      const m = v.match(/^(.*?[a-z])([^a-z]{1,6})$/);
      if (m && COMMON_RANK.has(m[1])) {
        const rank = COMMON_RANK.get(m[1]);
        const bits = Math.log2(rank + 1) + 2 + m[2].length * 3.3;
        if (!best || bits < best.bits) best = { rank, bits, word: m[1], exact: false };
      }
    }
    return best;
  }

  /** Marks runs like "abcd", "4321", "aaaa" and keyboard walks like "qwerty". */
  function findPatterns(pw, costs) {
    const lower = pw.toLowerCase();
    const found = [];

    // Sequential / repeated runs (step +1, -1 or 0)
    let i = 0;
    while (i < lower.length - 2) {
      const step = lower.charCodeAt(i + 1) - lower.charCodeAt(i);
      if (Math.abs(step) <= 1) {
        let j = i + 1;
        while (j + 1 < lower.length && lower.charCodeAt(j + 1) - lower.charCodeAt(j) === step) j++;
        const len = j - i + 1;
        if (len >= 3) {
          for (let k = i + 1; k <= j; k++) costs[k] = Math.min(costs[k], 1);
          found.push({ type: step === 0 ? 'repeat' : 'sequence', text: pw.slice(i, j + 1) });
          i = j + 1;
          continue;
        }
      }
      i++;
    }

    // Keyboard walks (forward or backward along a row)
    for (const row of KEYBOARD_ROWS) {
      for (const r of [row, row.split('').reverse().join('')]) {
        for (let s = 0; s <= lower.length - 3; s++) {
          let e = s + 3;
          if (!r.includes(lower.slice(s, e))) continue;
          while (e < lower.length && r.includes(lower.slice(s, e + 1))) e++;
          for (let k = s + 1; k < e; k++) costs[k] = Math.min(costs[k], 1.5);
          found.push({ type: 'keyboard', text: pw.slice(s, e) });
          s = e - 1;
        }
      }
    }

    // Years 1900-2099
    const yearRe = /(19|20)\d{2}/g;
    let m;
    while ((m = yearRe.exec(pw))) {
      for (let k = m.index; k < m.index + 4; k++) costs[k] = Math.min(costs[k], 1.7);
      found.push({ type: 'year', text: m[0] });
    }
    return found;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds) || seconds > 1e300) return 'longer than the age of the universe';
    if (seconds < 1) return 'instantly';
    const units = [
      ['second', 60], ['minute', 60], ['hour', 24], ['day', 30.44], ['month', 12], ['year', 1]
    ];
    let value = seconds;
    for (let u = 0; u < units.length; u++) {
      const [name, next] = units[u];
      if (value < next || name === 'year') {
        if (name === 'year') break;
        const n = Math.floor(value);
        return `${n} ${name}${n === 1 ? '' : 's'}`;
      }
      value /= next;
    }
    const years = value;
    if (years >= 1.4e10) return 'longer than the age of the universe';
    if (years >= 1e12) return 'trillions of years';
    if (years >= 1e9) return 'billions of years';
    if (years >= 1e6) return 'millions of years';
    if (years >= 1e3) return 'thousands of years';
    const n = Math.floor(years);
    return `${n} year${n === 1 ? '' : 's'}`;
  }

  function analyze(password) {
    const pw = String(password == null ? '' : password);
    if (!pw) return { ok: false, error: 'empty' };

    const pool = poolSize(pw);
    const perChar = Math.log2(pool);
    const costs = new Array(pw.length).fill(perChar);
    const patterns = findPatterns(pw, costs);
    let entropy = costs.reduce((a, b) => a + b, 0);

    const hit = dictionaryHit(pw);
    if (hit && hit.bits < entropy) entropy = hit.bits;
    entropy = Math.max(0, entropy);

    // ---- Score (0-4) ----
    let score = entropy < 28 ? 0 : entropy < 36 ? 1 : entropy < 60 ? 2 : entropy < 80 ? 3 : 4;
    if (pw.length < 8) score = Math.min(score, 1);
    else if (pw.length < 10) score = Math.min(score, 2);
    if (hit && hit.exact) score = 0;

    // ---- Crack-time estimates (average = half the search space) ----
    const guesses = Math.pow(2, entropy) / 2;
    const crackTimes = ATTACKS.map((a) => ({ id: a.id, label: a.label, display: formatDuration(guesses / a.rate) }));

    // ---- Explanations ----
    const weaknesses = [];
    const tips = [];
    const weak = (severity, title, detail) => weaknesses.push({ severity, title, detail });

    if (hit) {
      weak('high', hit.exact ? 'Common or guessable password' : 'Built on a common word',
        hit.exact
          ? `"${hit.word}" is in the lists attackers try first. It would fall in seconds, whatever its length.`
          : `It starts from the common word "${hit.word}" plus a short tail. Attackers try this combination automatically.`);
    }
    if (pw.length < 8) weak('high', `Too short (${pw.length} characters)`, 'Every extra character multiplies the work for an attacker. Aim for 12 or more.');
    else if (pw.length < 12) weak('medium', `Fairly short (${pw.length} characters)`, 'Length is the single biggest factor. 12+ characters is a good minimum.');

    const seen = new Set();
    for (const p of patterns) {
      const key = p.type + p.text.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const msg = {
        repeat: ['Repeated characters', `"${p.text}" repeats the same character - it adds almost no strength.`],
        sequence: ['Predictable sequence', `"${p.text}" is a simple run (like abc or 123) that crackers try early.`],
        keyboard: ['Keyboard pattern', `"${p.text}" follows keys that sit next to each other on the keyboard.`],
        year: ['Contains a year', `"${p.text}" is easy to guess - birth years and graduation years are checked first.`]
      }[p.type];
      weak('medium', msg[0], msg[1]);
    }

    const uniqueRatio = new Set(pw).size / pw.length;
    if (pw.length >= 8 && uniqueRatio < 0.5) weak('low', 'Few different characters', 'Reusing the same few characters makes the password easier to guess.');

    if (!/[a-z]/.test(pw) && !/[A-Z]/.test(pw)) weak('low', 'No letters', 'A mix of letters and other characters widens the search space.');
    else if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) tips.push('Mix upper and lower case letters.');
    if (!/[0-9]/.test(pw)) tips.push('Add a few digits in the middle, not only at the end.');
    if (!/[^a-zA-Z0-9]/.test(pw)) tips.push('Add a symbol such as ! # % or a space.');

    if (pw.length < 14) tips.unshift('Use 14+ characters, or a passphrase of 4-5 random words (e.g. "lamp-orbit-tulip-seven").');
    tips.push('Use a different password for every site and store them in a password manager.');
    tips.push('Turn on two-factor authentication (2FA) wherever possible.');

    return {
      ok: true,
      length: pw.length,
      poolSize: pool,
      entropyBits: Math.round(entropy * 10) / 10,
      score,
      label: LEVELS[score].label,
      crackTimes,
      weaknesses,
      tips,
      checks: {
        lower: /[a-z]/.test(pw),
        upper: /[A-Z]/.test(pw),
        digits: /[0-9]/.test(pw),
        symbols: /[^a-zA-Z0-9]/.test(pw),
        longEnough: pw.length >= 12
      }
    };
  }

  // ---------------------------------------------------------------------------
  // Breach check (Have I Been Pwned, k-anonymity)
  // ---------------------------------------------------------------------------

  async function sha1Hex(text) {
    const data = new TextEncoder().encode(text);
    const digest = await globalThis.crypto.subtle.digest('SHA-1', data);
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  /** The API returns lines like "0018A45C4D1DEF81644B54AB7F969B88D65:10". */
  function parseRangeResponse(body, suffix) {
    for (const line of String(body).split(/\r?\n/)) {
      const [s, count] = line.trim().split(':');
      if (s && s.toUpperCase() === suffix.toUpperCase()) return parseInt(count, 10) || 0;
    }
    return 0;
  }

  async function checkBreach(password, fetchImpl) {
    const doFetch = fetchImpl || (typeof fetch === 'function' ? fetch : null);
    if (!doFetch) throw new Error('fetch is not available in this environment');
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await doFetch('https://api.pwnedpasswords.com/range/' + prefix);
    if (!res.ok) throw new Error('Breach service returned HTTP ' + res.status);
    const body = await res.text();
    return { count: parseRangeResponse(body, suffix), prefix };
  }

  // ---------------------------------------------------------------------------
  // Generator
  // ---------------------------------------------------------------------------

  const SETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.?'
  };

  /** Uniform random integer in [0, max) without modulo bias. */
  function randomInt(max) {
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / max) * max;
    do { globalThis.crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function generatePassword(options) {
    const o = Object.assign({ length: 16, lower: true, upper: true, digits: true, symbols: true }, options);
    const active = ['lower', 'upper', 'digits', 'symbols'].filter((k) => o[k]);
    if (!active.length) throw new Error('Select at least one character type');
    const length = Math.max(active.length, Math.min(128, Math.floor(o.length)));
    const all = active.map((k) => SETS[k]).join('');

    // One guaranteed character from each chosen set, the rest from the full pool.
    const chars = active.map((k) => SETS[k][randomInt(SETS[k].length)]);
    while (chars.length < length) chars.push(all[randomInt(all.length)]);

    // Fisher-Yates shuffle so the guaranteed characters are not always first.
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
  }

  return { analyze, formatDuration, sha1Hex, parseRangeResponse, checkBreach, generatePassword, COMMON_COUNT: COMMON.length };
});
