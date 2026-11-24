/* PhishShield - UI wiring.
 * Security note: user input (URLs, passwords) is only ever written to the page
 * with textContent, never innerHTML, so a malicious link cannot inject markup (XSS). */
(function () {
  'use strict';

  const { UrlAnalyzer, UrlMl, UrlModel, PasswordAuditor } = window.PhishShield;
  const $ = (id) => document.getElementById(id);

  // ---------- small helpers ----------
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  const storage = {
    get(key, fallback) {
      try {
        const raw = window.localStorage.getItem(key);
        return raw ? JSON.parse(raw) : fallback;
      } catch (e) { return fallback; }
    },
    set(key, value) {
      try { window.localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* private mode: ignore */ }
    }
  };

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      try {
        const ta = el('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
      } catch (e2) { return false; }
    }
  }

  const SEVERITY_LABEL = { high: 'High', medium: 'Medium', low: 'Low', good: 'Good', info: 'Info' };

  function renderFindings(list, findings, showPoints) {
    clear(list);
    for (const f of findings) {
      const li = el('li', 'finding sev-' + f.severity);
      li.appendChild(el('span', 'badge', SEVERITY_LABEL[f.severity] || f.severity));
      const body = el('div');
      body.appendChild(el('strong', null, f.title));
      body.appendChild(el('p', null, f.detail));
      li.appendChild(body);
      li.appendChild(el('span', 'pts', showPoints && f.points > 0 ? '+' + f.points : ''));
      list.appendChild(li);
    }
  }

  // ---------- tabs ----------
  const tabs = Array.from(document.querySelectorAll('.tab'));
  function selectTab(tab, focus) {
    for (const t of tabs) {
      const active = t === tab;
      t.setAttribute('aria-selected', String(active));
      t.tabIndex = active ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !active;
    }
    if (focus) tab.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (e) => {
      let next = null;
      if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
      else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === 'Home') next = tabs[0];
      else if (e.key === 'End') next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); selectTab(next, true); }
    });
  });

  // =====================================================================
  // URL analyzer
  // =====================================================================
  const HISTORY_KEY = 'phishshield.history.v1';
  const HISTORY_MAX = 8;
  const ADVICE = {
    high: 'Do not open this link or enter any details. If it came in a message, report it as phishing and delete it.',
    medium: 'Treat with caution. Do not log in through this link - open the official site by typing its address yourself.',
    low: 'No strong warning signs, but this is only a heuristic check. Stay alert before entering passwords or OTPs.'
  };

  let lastResult = null;

  function renderUrlResult(r) {
    lastResult = r;
    const card = $('url-result');
    card.hidden = false;
    card.classList.remove('lvl-low', 'lvl-medium', 'lvl-high');
    card.classList.add('lvl-' + r.level);

    $('url-score').textContent = String(r.score);
    $('url-verdict-title').textContent = r.verdict;
    $('url-advice').textContent = ADVICE[r.level];
    $('meta-host').textContent = r.host || '(none)';
    $('meta-domain').textContent = r.registeredDomain || '(none)';
    $('meta-rule-score').textContent = r.ruleScore + '/100';
    $('meta-defanged').textContent = r.defanged;
    const mlSummary = $('url-ml-summary');
    mlSummary.hidden = !r.ml;
    if (r.ml) {
      $('url-ml-score').textContent = r.ml.percent + '%';
      $('url-ml-note').textContent = 'Prior-adjusted estimate from a research dataset. URL text and structure only; treat as a signal, not proof.';
    }
    renderFindings($('url-findings'), r.findings, true);
    $('copy-status').textContent = '';

    // animate the gauge from empty to the score
    const fill = $('gauge-fill');
    fill.style.strokeDasharray = '0 100';
    requestAnimationFrame(() => requestAnimationFrame(() => {
      fill.style.strokeDasharray = r.score + ' 100';
    }));
  }

  function runAnalysis(value, remember) {
    const errorBox = $('url-error');
    const r = UrlAnalyzer.analyze(value);
    if (!r.ok) {
      errorBox.textContent = r.error;
      errorBox.hidden = false;
      $('url-result').hidden = true;
      return;
    }
    r.ruleScore = r.score;
    r.ml = UrlMl && UrlMl.score && UrlModel ? UrlMl.score(value, UrlModel) : null;
    if (r.ml) {
      // Rule checks never lower risk; the learned model contributes up to 35%.
      r.score = UrlMl.combineRiskScores(r.ruleScore, r.ml.percent);
      if (r.score >= 55) { r.level = 'high'; r.verdict = 'High risk - likely phishing'; }
      else if (r.score >= 30) { r.level = 'medium'; r.verdict = 'Suspicious - be careful'; }
      else { r.level = 'low'; r.verdict = 'Low risk - no strong red flags'; }
    }
    errorBox.hidden = true;
    renderUrlResult(r);
    if (remember) addHistory(r);
  }

  function addHistory(r) {
    const list = storage.get(HISTORY_KEY, []).filter((h) => h.input !== r.input);
    list.unshift({ input: r.input, score: r.score, level: r.level });
    storage.set(HISTORY_KEY, list.slice(0, HISTORY_MAX));
    renderHistory();
  }

  function renderHistory() {
    const list = storage.get(HISTORY_KEY, []);
    const ul = $('history');
    clear(ul);
    $('history-card').hidden = list.length === 0;
    for (const h of list) {
      const li = el('li');
      li.appendChild(el('span', 'tag ' + h.level, h.score + ' ' + h.level));
      const btn = el('button', null, h.input);
      btn.type = 'button';
      btn.title = 'Analyze again';
      btn.addEventListener('click', () => {
        $('url-input').value = h.input;
        runAnalysis(h.input, false);
      });
      li.appendChild(btn);
      ul.appendChild(li);
    }
  }

  $('url-form').addEventListener('submit', (e) => {
    e.preventDefault();
    runAnalysis($('url-input').value, true);
  });

  document.querySelectorAll('[data-sample]').forEach((chip) => {
    chip.addEventListener('click', () => {
      $('url-input').value = chip.dataset.sample;
      runAnalysis(chip.dataset.sample, true);
    });
  });

  $('clear-history').addEventListener('click', () => {
    storage.set(HISTORY_KEY, []);
    renderHistory();
  });

  $('copy-report').addEventListener('click', async () => {
    if (!lastResult) return;
    const r = lastResult;
    const lines = [
      'PhishShield report - ' + new Date().toLocaleString(),
      'URL (defanged): ' + r.defanged,
      'Risk: ' + r.score + '/100 - ' + r.verdict,
      'Rule score: ' + r.ruleScore + '/100',
      r.ml ? 'ML phishing likelihood: ' + r.ml.percent + '%' : 'ML model: unavailable',
      'Findings:'
    ].concat(r.findings.map((f) => '- [' + (SEVERITY_LABEL[f.severity] || f.severity).toUpperCase() + '] ' + f.title + ': ' + f.detail));
    const ok = await copyText(lines.join('\n'));
    $('copy-status').textContent = ok ? 'Copied!' : 'Could not copy - select the text manually.';
  });

  // =====================================================================
  // Password lab
  // =====================================================================
  const PW_SUMMARY = [
    'Cracked almost instantly. Do not use.',
    'Easy to crack. Make it longer and less predictable.',
    'Fine for low-value accounts, not for email or banking.',
    'Good. A little longer would be even better.',
    'Excellent. Keep it in a password manager.'
  ];
  const pwInput = $('pw-input');
  let breachToken = 0;

  function renderPassword() {
    breachToken++; // invalidate any in-flight breach lookup
    const breachBox = $('pw-breach-result');
    breachBox.textContent = '';
    breachBox.className = 'breach-result';
    $('pw-breach').disabled = false;

    const r = PasswordAuditor.analyze(pwInput.value);
    $('pw-result').hidden = !r.ok;
    if (!r.ok) return;

    $('pw-meter').dataset.score = String(r.score);
    $('pw-label').textContent = r.label;
    $('pw-summary').textContent = '- ' + PW_SUMMARY[r.score];
    $('pw-length').textContent = String(r.length);
    $('pw-entropy').textContent = String(r.entropyBits);
    $('pw-pool').textContent = String(r.poolSize);

    const checks = $('pw-checks');
    clear(checks);
    [['a-z', r.checks.lower], ['A-Z', r.checks.upper], ['0-9', r.checks.digits], ['symbols', r.checks.symbols], ['12+ chars', r.checks.longEnough]]
      .forEach(([name, ok]) => checks.appendChild(el('li', ok ? 'ok' : '', (ok ? '✓ ' : '✗ ') + name)));

    const crack = $('pw-crack');
    clear(crack);
    for (const c of r.crackTimes) {
      const tr = el('tr');
      tr.appendChild(el('td', null, c.label));
      tr.appendChild(el('td', null, c.display));
      crack.appendChild(tr);
    }

    if (r.weaknesses.length) {
      renderFindings($('pw-weak'), r.weaknesses, false);
    } else {
      renderFindings($('pw-weak'), [{ severity: 'good', title: 'No obvious weak spots', detail: 'No common word, sequence or pattern was detected.', points: 0 }], false);
    }

    const tips = $('pw-tips');
    clear(tips);
    r.tips.forEach((t) => tips.appendChild(el('li', null, t)));
  }

  pwInput.addEventListener('input', renderPassword);

  $('pw-toggle').addEventListener('click', (e) => {
    const show = pwInput.type === 'password';
    pwInput.type = show ? 'text' : 'password';
    e.currentTarget.textContent = show ? 'Hide' : 'Show';
    e.currentTarget.setAttribute('aria-pressed', String(show));
  });

  $('pw-breach').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const box = $('pw-breach-result');
    const pw = pwInput.value;
    if (!pw) return;
    const token = ++breachToken;
    btn.disabled = true;
    box.className = 'breach-result';
    box.textContent = 'Checking...';
    try {
      const { count } = await PasswordAuditor.checkBreach(pw);
      if (token !== breachToken) return; // password changed meanwhile
      if (count > 0) {
        box.className = 'breach-result bad';
        box.textContent = 'Found in ' + count.toLocaleString() + ' known data breaches. Never use this password.';
      } else {
        box.className = 'breach-result good';
        box.textContent = 'Not found in known breaches. (That does not guarantee it is strong.)';
      }
    } catch (err) {
      if (token !== breachToken) return;
      box.className = 'breach-result warn';
      box.textContent = 'Could not reach the breach service. Check your internet connection and try again.';
    } finally {
      if (token === breachToken) btn.disabled = false;
    }
  });

  // ---------- generator ----------
  const genOut = $('gen-out');
  const genLength = $('gen-length');
  let genValid = false;

  function generate() {
    $('gen-length-val').textContent = genLength.value;
    try {
      genOut.textContent = PasswordAuditor.generatePassword({
        length: Number(genLength.value),
        lower: $('gen-lower').checked,
        upper: $('gen-upper').checked,
        digits: $('gen-digits').checked,
        symbols: $('gen-symbols').checked
      });
      genValid = true;
    } catch (err) {
      genOut.textContent = 'Select at least one character type';
      genValid = false;
    }
  }

  $('gen-new').addEventListener('click', generate);
  genLength.addEventListener('input', generate);
  ['gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols'].forEach((id) => $(id).addEventListener('change', generate));
  $('gen-copy').addEventListener('click', async (e) => {
    if (!genValid) return;
    const btn = e.currentTarget;
    const ok = await copyText(genOut.textContent);
    btn.textContent = ok ? 'Copied!' : 'Copy failed';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });

  // ---------- init ----------
  renderHistory();
  generate();
})();
