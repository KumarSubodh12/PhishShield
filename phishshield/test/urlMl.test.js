const test = require('node:test');
const assert = require('node:assert/strict');
const Ml = require('../js/urlMl.js');
const Model = require('../js/urlModel.generated.js');

test('generated model metadata matches the inference feature schema', () => {
  assert.equal(Model.algorithm, 'logistic-regression');
  assert.equal(Model.features.length, Ml.FEATURES.length);
  assert.deepEqual(Model.features, Ml.FEATURES);
  assert.equal(Model.weights.length, Ml.FEATURES.length);
  assert.equal(Model.training.holdout.samples, 17871);
});

test('feature extraction handles normal and defanged URLs consistently', () => {
  const normal = Ml.extractFeatures('https://sbi-kyc-update.in/otp');
  const defanged = Ml.extractFeatures('hxxps://sbi-kyc-update[.]in/otp');
  assert.equal(normal.length, Ml.FEATURES.length);
  assert.deepEqual(defanged, normal);
});

test('features identify transport, address, punycode, and credential signals', () => {
  const https = Ml.extractFeatures('https://example.com/path');
  const ip = Ml.extractFeatures('http://192.168.1.1/login');
  const punycode = Ml.extractFeatures('https://xn--pple-43d.com/login');
  const userinfo = Ml.extractFeatures('http://user:pass@example.com/login');
  assert.equal(https[Ml.FEATURES.indexOf('https')], 1);
  assert.equal(ip[Ml.FEATURES.indexOf('ipHost')], 1);
  assert.equal(punycode[Ml.FEATURES.indexOf('punycode')], 1);
  assert.equal(userinfo[Ml.FEATURES.indexOf('hostnameIsUrlLike')], 1);
});

test('inference returns a finite phishing estimate within 0-100', () => {
  const result = Ml.score('https://accounts.google.com/signin', Model);
  assert.ok(result);
  assert.ok(Number.isFinite(result.probability));
  assert.ok(result.percent >= 0 && result.percent <= 100);
  assert.equal(result.features.length, Ml.FEATURES.length);
});

test('inference declines invalid URLs and incompatible model versions', () => {
  assert.equal(Ml.score('http://[invalid', Model), null);
  assert.equal(Ml.score('https://example.com', { ...Model, featureVersion: 2 }), null);
  assert.equal(Ml.score('https://example.com', { ...Model, weights: [1] }), null);
});

test('combined risk incorporates ML without reducing the rule score', () => {
  assert.equal(Ml.combineRiskScores(60, 0), 60);
  assert.equal(Ml.combineRiskScores(20, 100), 48);
  assert.equal(Ml.combineRiskScores(100, 100), 100);
  assert.equal(Ml.combineRiskScores(-5, 50), 18);
  assert.equal(Ml.combineRiskScores(150, 50), 100);
});
