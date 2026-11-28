/* mandate-verify.js — verify a mandate bundle in the browser, with no network calls.
 *
 * Input:  {receipt: {body, hash}, intent: {...}, grant: {grant: {...}, sig: "base64"},
 *          public_key: "ssh-ed25519 AAAA…" | "<64 hex>"}
 * Output: {ok: bool, checks: [{name, ok, detail}]}
 *
 * It recomputes everything: SHA-256 over RFC 8785 canonical JSON, the commitment (v1 and the
 * salted v2, honouring commitment_alg from the *signed* grant), the render hash, and the Ed25519
 * signature of the grant core. No fetch() appears in this file on purpose: a verifier that phones
 * home is not a verifier.
 */
(function (root) {
  "use strict";

  // ---------- bytes ----------
  function utf8(s) { return new TextEncoder().encode(s); }
  function hex(buf) {
    return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }
  function b64ToBytes(b64) {
    var s = atob(b64.replace(/\s+/g, ""));
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function concat() {
    var parts = Array.prototype.slice.call(arguments).map(function (a) {
      return a instanceof Uint8Array ? a : utf8(String(a));
    });
    var len = parts.reduce(function (n, p) { return n + p.length; }, 0);
    var out = new Uint8Array(len), at = 0;
    parts.forEach(function (p) { out.set(p, at); at += p.length; });
    return out;
  }
  async function sha256hex(bytes) {
    return hex(await crypto.subtle.digest("SHA-256", bytes));
  }
  async function sha512bytes(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-512", bytes));
  }

  // ---------- RFC 8785 (JCS) ----------
  // Numbers use ECMAScript Number::toString, which is what RFC 8785 prescribes; strings escape
  // only what the spec requires. Key order is by UTF-16 code units, as the spec says.
  function jcs(value) {
    if (value === null) return "null";
    var t = typeof value;
    if (t === "boolean") return value ? "true" : "false";
    if (t === "number") {
      if (!isFinite(value)) throw new Error("non-finite number");
      return JSON.stringify(value);          // matches Number::toString for JSON-representable values
    }
    if (t === "string") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
    if (t === "object") {
      var keys = Object.keys(value).sort(function (a, b) {
        return a < b ? -1 : a > b ? 1 : 0;
      });
      return "{" + keys.map(function (k) { return JSON.stringify(k) + ":" + jcs(value[k]); }).join(",") + "}";
    }
    throw new Error("cannot canonicalise " + t);
  }

  // ---------- Ed25519 verify (RFC 8032), BigInt ----------
  var P = 2n ** 255n - 19n;
  var L = 2n ** 252n + 27742317777372353535851937790883648493n;
  var D = mod(-121665n * inv(121666n));
  var D2 = mod(2n * D);
  var I = pow(2n, (P - 1n) / 4n);
  var BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
  var BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

  function mod(a, m) { var r = a % (m || P); return r >= 0n ? r : r + (m || P); }
  function pow(b, e, m) {
    b = mod(b, m); var r = 1n, mm = m || P;
    while (e > 0n) { if (e & 1n) r = mod(r * b, mm); b = mod(b * b, mm); e >>= 1n; }
    return r;
  }
  function inv(a) { return pow(a, P - 2n); }
  function sqrt(a) {
    var r = pow(a, (P + 3n) / 8n);
    if (mod(r * r - a) !== 0n) r = mod(r * I);
    return mod(r * r - a) === 0n ? r : null;
  }
  function pointAdd(p, q) {
    var a = mod((p[1] - p[0]) * (q[1] - q[0]));
    var b = mod((p[1] + p[0]) * (q[1] + q[0]));
    var c = mod(2n * D * p[3] * q[3]);
    var d = mod(2n * p[2] * q[2]);
    var e = mod(b - a), f = mod(d - c), g = mod(d + c), h = mod(b + a);
    return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
  }
  function pointDouble(p) { return pointAdd(p, p); }
  function scalarmult(p, e) {
    var q = [0n, 1n, 1n, 0n];
    while (e > 0n) {
      if (e & 1n) q = pointAdd(q, p);
      p = pointDouble(p); e >>= 1n;
    }
    return q;
  }
  function pointCompress(p) {
    var zInv = inv(p[2]);
    var x = mod(p[0] * zInv), y = mod(p[1] * zInv);
    var out = new Uint8Array(32);
    var yBytes = le(y);
    out.set(yBytes);
    if (x & 1n) out[31] |= 0x80;
    return out;
  }
  function le(n) {
    var out = new Uint8Array(32);
    for (var i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
    return out;
  }
  function fromLe(bytes) {
    var n = 0n;
    for (var i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  }
  function pointDecompress(bytes) {
    var y = fromLe(bytes);
    var sign = (bytes[31] & 0x80) !== 0;
    y = mod(y & ((1n << 255n) - 1n));
    var x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
    var x = sqrt(x2);
    if (x === null) throw new Error("point not on curve");
    if (Number(x & 1n) !== (sign ? 1 : 0)) x = mod(-x);
    return [x, y, 1n, mod(x * y)];
  }
  function ed25519Verify(sigBytes, msg, pkBytes) {
    if (sigBytes.length !== 64 || pkBytes.length !== 32) return false;
    var R = sigBytes.slice(0, 32), S = fromLe(sigBytes.slice(32));
    if (S >= L) return false;
    var A;
    try { A = pointDecompress(pkBytes); } catch (e) { return false; }
    return sha512bytes(concat(R, pkBytes, msg)).then(function (h) {
      var k = mod(fromLe(h), L);
      var left = scalarmult(pointDecompress(encodeBase()), S);
      var right = pointAdd(pointDecompress(R), scalarmult(A, k));
      return hex(pointCompress(left)) === hex(pointCompress(right));
    });
  }
  function encodeBase() {
    var out = new Uint8Array(32);
    out.set(le(BY));
    if (BX & 1n) out[31] |= 0x80;
    return out;
  }

  // ---------- SSH signature (what `mandate` emits) ----------
  function readString(buf, at) {
    var len = new DataView(buf.buffer, buf.byteOffset + at, 4).getUint32(0);
    return { bytes: buf.slice(at + 4, at + 4 + len), next: at + 4 + len };
  }
  function bytesString(bytes) {
    var b = bytes instanceof Uint8Array ? bytes : utf8(String(bytes));
    var len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, b.length);
    return concat(len, b);
  }
  function utf8String(text) { return bytesString(utf8(text)); }
  async function sshSigVerify(armor, msg, pkBytes, wantNamespace) {
    var body = String(armor || "");
    if (body.indexOf("-----BEGIN SSH SIGNATURE-----") >= 0) {
      body = body.split("-----BEGIN SSH SIGNATURE-----")[1].split("-----END SSH SIGNATURE-----")[0];
    }
    var raw;
    try { raw = b64ToBytes(body); } catch (e) {
      if (/^[A-Za-z0-9+/=]+$/.test(body.trim())) throw new Error("signature is not base64");
      throw new Error("signature is not an SSH signature nor base64");
    }
    if (raw.length === 64) {                      // raw Ed25519 signature
      return { ok: await ed25519Verify(raw, msg, pkBytes), namespace: "" };
    }
    var magic = String.fromCharCode.apply(null, raw.slice(0, 6));
    if (magic !== "SSHSIG") throw new Error("not an SSHSIG blob");
    var at = 10;                                   // "SSHSIG" + uint32 version
    var pub = readString(raw, at); at = pub.next;
    var ns = readString(raw, at); at = ns.next;
    var reserved = readString(raw, at); at = reserved.next;
    var hashAlg = readString(raw, at); at = hashAlg.next;
    var sigField = readString(raw, at);
    var namespace = new TextDecoder().decode(ns.bytes);
    if (wantNamespace && namespace !== wantNamespace) {
      throw new Error("signature namespace is " + namespace + ", expected " + wantNamespace);
    }
    var algField = readString(sigField.bytes, 0);       // "ssh-ed25519"
    var sigField2 = readString(sigField.bytes, algField.next);   // string(64)
    var sig = sigField2.bytes.length === 64
      ? sigField2.bytes : sigField2.bytes.slice(sigField2.bytes.length - 64);
    // Records signed before 1.0.10 include a trailing newline in the signed bytes; 1.0.10+
    // signs the canonical bytes exactly. Try both, newest convention first.
    var variants = [msg, concat(msg, "\n")];
    for (var i = 0; i < variants.length; i++) {
      var digest = await crypto.subtle.digest("SHA-512", variants[i]);
      var signed = concat(
        utf8("SSHSIG"),
        utf8String(namespace),
        utf8String(new TextDecoder().decode(reserved.bytes)),
        utf8String(new TextDecoder().decode(hashAlg.bytes)),
        bytesString(new Uint8Array(digest))
      );
      if (await ed25519Verify(sig, signed, pkBytes)) {
        return { ok: true, namespace: namespace, legacy_newline: i === 1 };
      }
    }
    return { ok: false, namespace: namespace };
  }

  // ---------- keys ----------
  function parsePublicKey(text) {
    text = String(text || "").trim();
    if (/^[0-9a-fA-F]{64}$/.test(text)) return fromHex(text);
    var m = text.match(/ssh-ed25519\s+([A-Za-z0-9+/=]+)/);
    if (!m) return null;
    var blob = b64ToBytes(m[1]);
    if (blob.length < 32) return null;
    return blob.slice(blob.length - 32);      // 4+11 "ssh-ed25519" + 4 + 32 key bytes
  }
  function fromHex(s) {
    var out = new Uint8Array(32);
    for (var i = 0; i < 32; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  // ---------- render / core (mirror of mandate.core) ----------
  function amountOf(intent) {
    var a = (intent.effect || {}).amount;
    if (!a || typeof a !== "object") return [null, null];
    var v = Number(a.value);
    if (!isFinite(v)) return [null, null];
    return [v, String(a.currency || "BAM")];
  }
  function renderOf(intent) {
    var effect = intent.effect || {};
    var parts = [String(effect.kind || "?")];
    if (effect.target !== undefined && effect.target !== null) {
      parts.push("target=" + JSON.stringify(effect.target));
    }
    var pair = amountOf(intent);
    if (pair[0] !== null) parts.push("amount=" + pair[0].toFixed(2) + " " + pair[1]);
    var params = effect.params || {};
    Object.keys(params).sort().forEach(function (k) {
      parts.push(k + "=" + JSON.stringify(params[k]));
    });
    var evidence = Array.from(new Set((intent.provenance || []).filter(function (p) {
      return p && p.type === "data_ref" && p.source;
    }).map(function (p) { return String(p.source); }))).sort();
    if (evidence.length) parts.push("evidence=" + evidence.join(","));
    return {
      summary: parts.join(" | "),
      fields: {
        kind: effect.kind === undefined ? null : effect.kind,
        target: effect.target === undefined ? null : effect.target,
        amount: pair[0] === null ? null : { value: pair[0], currency: pair[1] },
        params: params,
        evidence: evidence
      }
    };
  }

  function intentCore(intent) {
    var effect = JSON.parse(JSON.stringify(intent.effect || {}));
    if (!effect.revert) effect.revert = "irreversible";
    return {
      v: 1,
      actor: { agent: (intent.actor || {}).agent, session: (intent.actor || {}).session },
      nonce: intent.nonce,
      effect: effect,
      requested_by: intent.requested_by,
      render_hash: null,
      provenance_hash: null
    };
  }

  async function commitmentOf(intent, alg, saltHex) {
    var core = intentCore(intent);
    core.render_hash = await sha256hex(utf8(jcs(renderOf(intent))));
    core.provenance_hash = await sha256hex(utf8(jcs(intent.provenance || [])));
    var payload = jcs(core);
    if (alg === "sha256-jcs-salt-v1") {
      if (!saltHex || !/^[0-9a-fA-F]{32,}$/.test(saltHex)) throw new Error("salted grant without a salt");
      var salt = new Uint8Array(saltHex.match(/../g).map(function (h) { return parseInt(h, 16); }));
      var prefix = concat("mandate/commitment/v2\u0000", salt);
      return "sha256:" + await sha256hex(concat(prefix, payload));
    }
    return "sha256:" + await sha256hex(utf8(payload));
  }

  async function verifyBundle(bundle) {
    var checks = [];
    function push(name, ok, detail) { checks.push({ name: name, ok: !!ok, detail: detail || "" }); }
    try {
      var receipt = bundle.receipt || {};
      var body = receipt.body || {};
      var grantObj = bundle.grant || {};
      var grant = grantObj.grant || {};
      var intent = bundle.intent || {};

      // 1. receipt integrity
      var bodyHash = await sha256hex(utf8(jcs(body)));
      push("receipt sha256(jcs(body))", bodyHash === String(receipt.hash || "").toLowerCase(),
           "izračunato " + bodyHash.slice(0, 16) + "…");

      // 2. grant signature over the canonical grant core
      var pk = parsePublicKey(bundle.public_key);
      push("javni ključ", !!pk, pk ? "32 bajta" : "nije ssh-ed25519 ni 64 hex");
      if (pk) {
        var res = await sshSigVerify(String(grantObj.sig || ""), utf8(jcs(grant)), pk, "mandate");
        push("Ed25519 potpis granta", res.ok,
             "potpisnik " + String(grant.approver || "?") + " · namespace " + (res.namespace || "raw"));
      }

      // 3. commitment recomputed from the intent, with the algorithm the *grant* declares
      var commitment = await commitmentOf(intent, String(grant.commitment_alg || ""),
                                          String(grant.commitment_salt || ""));
      push("commitment (intent → grant)", commitment === String(grant.commitment || ""),
           commitment.slice(0, 24) + "…");

      // 4. render hash agreement (grant, receipt)
      push("render hash (grant = receipt)",
           String(grant.render_hash || "") === String(body.render_hash || ""),
           String(grant.render_hash || "").slice(0, 16) + "…");

      // 5. attribution and nonce
      push("approver (grant = receipt)",
           String(grant.approver || "") === String(body.approver || ""),
           String(body.approver || "?"));
      if (body.grant_nonce) {
        push("nonce (grant = receipt)", String(grant.nonce || "") === String(body.grant_nonce),
             String(grant.nonce || "?"));
      }

      // 6. one-shot: the receipt must not claim to be a second use
      push("max_uses = 1", Number((grant.scope || {}).max_uses || 0) === 1,
           "scope.max_uses=" + String((grant.scope || {}).max_uses));

      var okAll = checks.every(function (c) { return c.ok; });
      return { ok: okAll, checks: checks };
    } catch (err) {
      push("verifier", false, String(err && err.message ? err.message : err));
      return { ok: false, checks: checks, error: String(err && err.message ? err.message : err) };
    }
  }

  // ---------- RFC 6962 inclusion proof ----------
  function hexBytes(hexText) {
    var clean = String(hexText || "").replace(/[^0-9a-fA-F]/g, "");
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }
  async function leafHash(entryText) {
    return sha256hex(concat(new Uint8Array([0]), utf8(entryText)));
  }
  async function nodeHash(left, right) {
    return sha256hex(concat(new Uint8Array([1]), left, right));
  }
  async function verifyInclusion(entryText, index, size, proof, rootHex) {
    if (!(index >= 0) || index >= size || size <= 0) return false;
    var node = hexBytes(await leafHash(entryText));
    for (var i = 0; i < proof.length; i++) {
      var sibling = hexBytes(proof[i].hash);
      if (sibling.length !== 32) return false;
      if (proof[i].side === "left") node = hexBytes(await nodeHash(sibling, node));
      else if (proof[i].side === "right") node = hexBytes(await nodeHash(node, sibling));
      else return false;
    }
    return hex(node) === String(rootHex || "").toLowerCase();
  }

  root.MandateVerify = {
    verifyBundle: verifyBundle,
    jcs: jcs,
    ed25519Verify: ed25519Verify,
    sshSigVerify: sshSigVerify,
    parsePublicKey: parsePublicKey,
    commitmentOf: commitmentOf,
    verifyInclusion: verifyInclusion,
    leafHash: leafHash,
    sha256hex: sha256hex
  };
})(typeof window !== "undefined" ? window : globalThis);
