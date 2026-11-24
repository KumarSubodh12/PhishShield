#!/usr/bin/env python3
"""Train PhishShield's browser logistic-regression model from UCI PhiUSIIL.

Downloads the CC BY 4.0 source data on demand; raw URL data is never committed.
The features here intentionally mirror js/urlMl.js and use URL text only.
"""
import csv
import hashlib
import io
import ipaddress
import json
import math
import random
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "js" / "urlModel.generated.js"
DATA_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
FEATURES = [
    "urlLength", "hostLength", "dotCount", "subdomainCount", "pathLength",
    "queryLength", "digitRatio", "letterRatio", "hyphenCount", "atCount",
    "percentCount", "equalsCount", "questionCount", "https", "ipHost",
    "punycode", "suspiciousWords", "shortener", "hostDigitRatio",
    "hostHyphenCount", "encodedChars", "hostnameIsUrlLike",
]
SUSPICIOUS = ("login", "signin", "verify", "secure", "account", "update", "bank",
              "password", "wallet", "billing", "invoice", "suspend", "unlock",
              "recover", "alert", "authenticate", "credential", "refund", "prize",
              "reward", "claim", "otp", "kyc", "free", "support")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "lnkd.in"}


def features(raw):
    s = str(raw).strip()
    candidate = s if "://" in s else "http://" + s
    # Keep parsing consistent with the browser's WHATWG URL implementation for normal URLs.
    from urllib.parse import urlsplit
    p = urlsplit(candidate)
    host = (p.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    path = p.path or ("/" if host else "")
    query = p.query or ""
    low = s.lower()
    total = max(1, len(s))
    letters = sum(c.isalpha() for c in s)
    digits = sum("0" <= c <= "9" for c in s)
    hostdigits = sum("0" <= c <= "9" for c in host)
    try:
        ipaddress.ip_address(host.strip("[]"))
        ip = 1
    except ValueError:
        ip = 0
    suspicious = min(1.0, sum(low.count(w) for w in SUSPICIOUS) / 4)
    labels = host.split(".") if host else []
    nums = [
        min(len(s), 2048) / 2048, min(len(host), 253) / 253,
        min(s.count("."), 20) / 20, min(max(0, len(labels) - 2), 10) / 10,
        min(len(path), 1024) / 1024, min(len(query), 1024) / 1024,
        digits / total, letters / total, min(s.count("-"), 20) / 20,
        min(s.count("@"), 3) / 3, min(s.count("%"), 20) / 20,
        min(s.count("="), 20) / 20, min(s.count("?"), 3) / 3,
        float(p.scheme.lower() == "https"), float(ip),
        float(any(x.startswith("xn--") for x in labels)), suspicious,
        float(host in SHORTENERS), hostdigits / max(1, len(host)),
        min(host.count("-"), 12) / 12, min(sum(s.count(x) for x in ("%2f", "%3a", "%40", "%2e")), 10) / 10,
        float("//" in p.netloc or "@" in p.netloc),
    ]
    return nums


def sigmoid(x):
    if x < -35: return 0.0
    if x > 35: return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def main():
    print("Downloading UCI PhiUSIIL dataset (15 MB)...", flush=True)
    req = urllib.request.Request(DATA_URL, headers={"User-Agent": "PhishShield-ML-training/1.0"})
    with urllib.request.urlopen(req, timeout=90) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    member = next(n for n in archive.namelist() if n.lower().endswith(".csv"))
    with archive.open(member) as f:
        rows = csv.DictReader(io.TextIOWrapper(f, encoding="utf-8-sig", newline=""))
        records = []
        for row in rows:
            url = row.get("URL", "")
            label = row.get("label", "")
            if url and label in ("0", "1"):
                # UCI: 0 phishing, 1 legitimate.
                from urllib.parse import urlsplit
                host = ((urlsplit(url if "://" in url else "http://" + url).hostname or "")
                        .encode("idna").decode("ascii").lower())
                # Keep every URL from one host in the same partition to reduce
                # memorization leakage from multiple paths on the same site.
                bucket = hashlib.sha256(host.encode("utf-8")).digest()[0] % 100
                records.append((features(url), 1 if label == "0" else 0, bucket))
    train = [(x, y) for x, y, h in records if h < 80]
    valid = [(x, y) for x, y, h in records if 80 <= h < 90]
    test = [(x, y) for x, y, h in records if h >= 90]
    print(f"Rows: {len(records):,}; train {len(train):,}, validation {len(valid):,}, holdout {len(test):,}", flush=True)

    # Balance phishing and legitimate examples so the majority class cannot
    # suppress recall in the browser-facing decision threshold.
    phishing_count = sum(y for _, y in train)
    phishing_weight = len(train) / (2 * phishing_count)
    legitimate_weight = len(train) / (2 * (len(train) - phishing_count))
    phishing_prior = phishing_count / len(train)
    prior_correction = math.log(phishing_prior / (1 - phishing_prior))
    threshold = 0.45

    # Deterministic full-batch logistic regression with L2 regularization.
    weights = [0.0] * len(FEATURES)
    bias = 0.0
    rng = random.Random(20261124)
    lr = 0.08
    epochs = 38
    for epoch in range(epochs):
        rng.shuffle(train)
        gw = [0.0] * len(FEATURES)
        gb = 0.0
        for x, y in train:
            sample_weight = phishing_weight if y else legitimate_weight
            err = (sigmoid(sum(a * b for a, b in zip(weights, x)) + bias) - y) * sample_weight
            gb += err
            for j, value in enumerate(x): gw[j] += err * value
        scale = lr / len(train)
        for j in range(len(weights)):
            weights[j] -= scale * (gw[j] + 0.001 * weights[j])
        bias -= scale * gb
        if epoch in (9, 19, 29, 37):
            lr *= 0.92
            print(f"Epoch {epoch + 1}/{epochs} complete", flush=True)

    def metrics(data):
        tp = fp = tn = fn = 0
        for x, y in data:
            pred = sigmoid(sum(a * b for a, b in zip(weights, x)) + bias) >= threshold
            if pred and y: tp += 1
            elif pred: fp += 1
            elif y: fn += 1
            else: tn += 1
        return {"accuracy": round((tp + tn) / len(data), 4),
                "precision": round(tp / max(1, tp + fp), 4),
                "recall": round(tp / max(1, tp + fn), 4),
                "f1": round(2 * tp / max(1, 2 * tp + fp + fn), 4),
                "samples": len(data)}

    model = {"algorithm": "logistic-regression", "featureVersion": 1, "features": FEATURES,
             "weights": [round(x, 8) for x in weights], "bias": round(bias, 8),
             "priorCorrection": round(prior_correction, 8), "threshold": threshold,
             "training": {"dataset": "UCI PhiUSIIL Phishing URL (Website)",
             "uciId": 967, "license": "CC BY 4.0", "rows": len(records),
             "positiveClass": "phishing", "split": "SHA-256 hostname hash: 80/10/10",
             "evaluationThreshold": threshold, "probabilityPriorAdjusted": True,
             "validation": metrics(valid), "holdout": metrics(test)}}
    OUT.write_text("/* Generated by scripts/train_url_model.py; do not edit by hand. */\n" +
                   "(function(root){var model=" + json.dumps(model, separators=(",", ":")) +
                   ";if(typeof module==='object'&&module.exports)module.exports=model;else{root.PhishShield=root.PhishShield||{};root.PhishShield.UrlModel=model;}})(typeof self!=='undefined'?self:this);\n", encoding="utf-8")
    print(json.dumps(model["training"], indent=2))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
