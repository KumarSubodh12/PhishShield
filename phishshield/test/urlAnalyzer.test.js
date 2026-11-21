const test = require('node:test');
const assert = require('node:assert/strict');
const U = require('../js/urlAnalyzer.js');

const ids = (r) => r.findings.filter((f) => f.points > 0).map((f) => f.id);

test('genuine brand domains score low', () => {
  for (const url of ['https://www.google.com/search?q=cats', 'https://accounts.google.com/signin', 'https://github.com/anthropics', 'https://www.wikipedia.org/wiki/Phishing']) {
    const r = U.analyze(url);
    assert.equal(r.ok, true);
    assert.equal(r.level, 'low', url);
    assert.equal(r.score, 0, url);
  }
});

test('official domain is recognised as such', () => {
  const r = U.analyze('https://accounts.google.com/signin');
  assert.equal(r.officialBrand, 'Google');
  assert.equal(r.registeredDomain, 'google.com');
});

test('look-alike domain (paypa1) is high risk', () => {
  const r = U.analyze('http://paypa1.com/login');
  assert.ok(ids(r).includes('impersonation'));
  assert.equal(r.level, 'high');
});

test('rn -> m look-alike is detected', () => {
  assert.ok(ids(U.analyze('https://rnicrosoft.com')).includes('impersonation'));
});

test('typosquat (one letter off) is detected', () => {
  assert.ok(ids(U.analyze('https://gooogle.com')).includes('impersonation'));
});

test('brand name in subdomain of a foreign domain is impersonation', () => {
  const r = U.analyze('https://paypal.com.account-update.tk/login');
  assert.ok(ids(r).includes('impersonation'));
  assert.ok(ids(r).includes('risky-tld'));
  assert.equal(r.level, 'high');
});

test('unrelated words that merely contain a short brand name are not flagged', () => {
  assert.equal(U.analyze('https://applebees.com').score, 0);
});

test('IP address host is flagged', () => {
  const r = U.analyze('http://192.168.45.7:8080/bank/login');
  assert.ok(ids(r).includes('ip-host'));
  assert.ok(ids(r).includes('port'));
});

test('"@" trick is flagged', () => {
  const r = U.analyze('http://secure-bank.com@evil-host.top/');
  assert.ok(ids(r).includes('at-symbol'));
  assert.equal(r.host, 'evil-host.top');
});

test('punycode homograph domain is flagged', () => {
  const r = U.analyze('https://аpple.com/'); // Cyrillic "a"
  assert.ok(ids(r).includes('punycode'));
});

test('URL shorteners are flagged', () => {
  assert.ok(ids(U.analyze('https://bit.ly/3abcXYZ')).includes('shortener'));
});

test('brand domain hidden in the path is flagged', () => {
  assert.ok(ids(U.analyze('https://evil.com/paypal.com/login')).includes('brand-in-path'));
});

test('redirect parameter is flagged', () => {
  assert.ok(ids(U.analyze('https://example.com/go?url=https://evil.com')).includes('redirect-param'));
});

test('defanged input is understood', () => {
  const r = U.analyze('hxxps://sbi-kyc-update[.]in/otp');
  assert.equal(r.ok, true);
  assert.equal(r.host, 'sbi-kyc-update.in');
  assert.ok(ids(r).includes('impersonation'));
});

test('input without a scheme skips the HTTPS penalty', () => {
  const r = U.analyze('example.com');
  assert.equal(r.ok, true);
  assert.ok(!ids(r).includes('no-https'));
});

test('plain http is penalised', () => {
  assert.ok(ids(U.analyze('http://example.com/')).includes('no-https'));
});

test('javascript: URLs are high risk', () => {
  const r = U.analyze('javascript:alert(1)');
  assert.equal(r.level, 'high');
  assert.equal(r.url, null);
});

test('empty and invalid input return an error, not a crash', () => {
  assert.equal(U.analyze('').ok, false);
  assert.equal(U.analyze('   ').ok, false);
  assert.equal(U.analyze('http://').ok, false);
  assert.equal(U.analyze('x'.repeat(3000)).ok, false);
  assert.equal(U.analyze(null).ok, false);
});

test('score is always between 0 and 100', () => {
  const r = U.analyze('http://192.168.1.1:81/https://paypal.com.secure-login-verify-account-update.tk/login?url=http://x.y&a=%41%42%43%44');
  assert.ok(r.score >= 0 && r.score <= 100);
});

test('getRegisteredDomain handles multi-part suffixes', () => {
  assert.equal(U.getRegisteredDomain('a.b.example.com'), 'example.com');
  assert.equal(U.getRegisteredDomain('a.b.example.co.in'), 'example.co.in');
  assert.equal(U.getRegisteredDomain('example.com'), 'example.com');
});

test('levenshtein distance', () => {
  assert.equal(U.levenshtein('kitten', 'sitting'), 3);
  assert.equal(U.levenshtein('paypal', 'paypal'), 0);
  assert.equal(U.levenshtein('', 'abc'), 3);
});

test('defang makes links non-clickable', () => {
  assert.equal(U.defang('http://evil.com/a'), 'hxxp://evil[.]com/a');
});
