const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../js/passwordAuditor.js');

test('very common passwords are very weak', () => {
  for (const pw of ['123456', 'password', 'qwerty', 'iloveyou', 'P@ssw0rd']) {
    const r = P.analyze(pw);
    assert.equal(r.score, 0, pw);
    assert.ok(r.weaknesses.some((w) => w.severity === 'high'), pw);
  }
});

test('common word plus short tail is detected', () => {
  const r = P.analyze('rahul@2004');
  assert.ok(r.score <= 1);
  assert.ok(r.weaknesses.length >= 1);
});

test('short passwords can never score above "weak"', () => {
  assert.ok(P.analyze('Xk9#mQ2!').score <= 2);
  assert.ok(P.analyze('Xk9#m').score <= 1);
});

test('long random password is very strong', () => {
  const r = P.analyze('k9#Vm2$xQp7!Lw4z');
  assert.equal(r.score, 4);
  assert.equal(r.weaknesses.length, 0);
});

test('sequences, repeats, keyboard walks and years are reported', () => {
  const titles = (pw) => P.analyze(pw).weaknesses.map((w) => w.title);
  assert.ok(titles('abcdefgh').includes('Predictable sequence'));
  assert.ok(titles('aaaaaaaaaaaa').includes('Repeated characters'));
  assert.ok(titles('zxcvbnmasdf').includes('Keyboard pattern'));
  assert.ok(titles('Summer@2004x').includes('Contains a year'));
});

test('entropy grows with length', () => {
  assert.ok(P.analyze('Gq7!vLm2').entropyBits < P.analyze('Gq7!vLm2Zr5#kTe9').entropyBits);
});

test('empty password returns ok:false', () => {
  assert.equal(P.analyze('').ok, false);
});

test('crack times are returned for three attack models', () => {
  const r = P.analyze('hello1');
  assert.equal(r.crackTimes.length, 3);
  assert.ok(r.crackTimes.every((c) => typeof c.display === 'string' && c.display.length > 0));
});

test('formatDuration', () => {
  assert.equal(P.formatDuration(0.2), 'instantly');
  assert.equal(P.formatDuration(45), '45 seconds');
  assert.equal(P.formatDuration(1), '1 second');
  assert.equal(P.formatDuration(5000), '1 hour');
  assert.equal(P.formatDuration(1e30), 'longer than the age of the universe');
});

test('sha1Hex matches the known value for "password"', async () => {
  assert.equal(await P.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('parseRangeResponse finds the matching suffix', () => {
  const body = '0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\r\nFFFF:1';
  assert.equal(P.parseRangeResponse(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 3730471);
  assert.equal(P.parseRangeResponse(body, 'ABCDEF'), 0);
});

test('checkBreach sends only the 5-character hash prefix (k-anonymity)', async () => {
  let requested;
  const fakeFetch = async (url) => {
    requested = url;
    return { ok: true, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\n0000000000000000000000000000000000A:2' };
  };
  const result = await P.checkBreach('password', fakeFetch);
  assert.equal(requested, 'https://api.pwnedpasswords.com/range/5BAA6');
  // only the 5-char prefix is in the URL: never the plain password or the full SHA-1
  assert.equal(requested.split('/range/')[1].length, 5);
  assert.ok(!requested.includes('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'));
  assert.equal(result.count, 3730471);
  assert.equal(result.prefix, '5BAA6');
});

test('checkBreach reports 0 when the hash is not listed', async () => {
  const fakeFetch = async () => ({ ok: true, text: async () => 'AAAAA:1' });
  assert.equal((await P.checkBreach('some-unique-pass-9137', fakeFetch)).count, 0);
});

test('checkBreach throws on service errors', async () => {
  await assert.rejects(P.checkBreach('x', async () => ({ ok: false, status: 503, text: async () => '' })), /503/);
});

test('generatePassword respects length and character sets', () => {
  const pw = P.generatePassword({ length: 24 });
  assert.equal(pw.length, 24);
  assert.match(pw, /[a-z]/);
  assert.match(pw, /[A-Z]/);
  assert.match(pw, /[0-9]/);
  assert.match(pw, /[^a-zA-Z0-9]/);

  const digitsOnly = P.generatePassword({ length: 10, lower: false, upper: false, symbols: false });
  assert.match(digitsOnly, /^[0-9]{10}$/);
});

test('generatePassword needs at least one character type', () => {
  assert.throws(() => P.generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
});

test('generated passwords are different every time and score strong', () => {
  const seen = new Set();
  for (let i = 0; i < 50; i++) {
    const pw = P.generatePassword({ length: 16 });
    seen.add(pw);
    assert.ok(P.analyze(pw).score >= 3, pw);
  }
  assert.equal(seen.size, 50);
});
