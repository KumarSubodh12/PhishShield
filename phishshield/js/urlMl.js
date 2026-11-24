/* URL-only machine-learning inference for PhishShield.
 * Mirrors scripts/train_url_model.py. It never requests the URL under analysis. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else { root.PhishShield = root.PhishShield || {}; root.PhishShield.UrlMl = factory(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const FEATURES = [
    'urlLength', 'hostLength', 'dotCount', 'subdomainCount', 'pathLength',
    'queryLength', 'digitRatio', 'letterRatio', 'hyphenCount', 'atCount',
    'percentCount', 'equalsCount', 'questionCount', 'https', 'ipHost',
    'punycode', 'suspiciousWords', 'shortener', 'hostDigitRatio',
    'hostHyphenCount', 'encodedChars', 'hostnameIsUrlLike'
  ];
  const SUSPICIOUS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'bank',
    'password', 'wallet', 'billing', 'invoice', 'suspend', 'unlock', 'recover', 'alert',
    'authenticate', 'credential', 'refund', 'prize', 'reward', 'claim', 'otp', 'kyc', 'free', 'support'];
  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 'lnkd.in']);

  function extractFeatures(raw) {
    const s = String(raw).trim().replace(/^hxxps?/i, (m) => m.toLowerCase() === 'hxxps' ? 'https' : 'http')
      .replace(/\[\.\]|\(\.\)/g, '.');
    const candidate = s.includes('://') ? s : 'http://' + s;
    let url;
    try { url = new URL(candidate); } catch (_) { return null; }
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    const path = url.pathname || '';
    const query = url.search ? url.search.slice(1) : '';
    const low = s.toLowerCase();
    const total = Math.max(1, s.length);
    const letters = (s.match(/\p{L}/gu) || []).length;
    const digits = (s.match(/[0-9]/g) || []).length;
    const hostDigits = (host.match(/[0-9]/g) || []).length;
    const labels = host ? host.split('.') : [];
    const octets = host.split('.');
    const ip = (octets.length === 4 && octets.every((x) => /^\d+$/.test(x) && Number(x) <= 255)) ||
      (host.startsWith('[') && host.endsWith(']'));
    const suspicious = Math.min(1, SUSPICIOUS.reduce((n, w) => n + low.split(w).length - 1, 0) / 4);
    const count = (re) => (s.match(re) || []).length;
    return [
      Math.min(s.length, 2048) / 2048, Math.min(host.length, 253) / 253,
      Math.min(count(/\./g), 20) / 20, Math.min(Math.max(0, labels.length - 2), 10) / 10,
      Math.min(path.length, 1024) / 1024, Math.min(query.length, 1024) / 1024,
      digits / total, letters / total, Math.min(count(/-/g), 20) / 20,
      Math.min(count(/@/g), 3) / 3, Math.min(count(/%/g), 20) / 20,
      Math.min(count(/=/g), 20) / 20, Math.min(count(/\?/g), 3) / 3,
      Number(url.protocol === 'https:'), Number(ip), Number(labels.some((x) => x.startsWith('xn--'))),
      suspicious, Number(SHORTENERS.has(host)), hostDigits / Math.max(1, host.length),
      Math.min((host.match(/-/g) || []).length, 12) / 12,
      Math.min((low.match(/%2f|%3a|%40|%2e/g) || []).length, 10) / 10,
      Number(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/i.test(candidate))
    ];
  }

  function score(raw, model) {
    if (!model || model.algorithm !== 'logistic-regression' || model.featureVersion !== 1 ||
        !Array.isArray(model.weights) || model.weights.length !== FEATURES.length) return null;
    const values = extractFeatures(raw);
    if (!values) return null;
    let z = model.bias + (model.priorCorrection || 0);
    for (let i = 0; i < values.length; i++) z += values[i] * model.weights[i];
    const probability = z > 35 ? 1 : z < -35 ? 0 : 1 / (1 + Math.exp(-z));
    return { probability, percent: Math.round(probability * 100), features: values };
  }

  function combineRiskScores(ruleScore, mlPercent) {
    const rules = Math.max(0, Math.min(100, Number(ruleScore) || 0));
    const ml = Math.max(0, Math.min(100, Number(mlPercent) || 0));
    return Math.max(rules, Math.round(rules * 0.65 + ml * 0.35));
  }

  return { FEATURES, extractFeatures, score, combineRiskScores };
});
