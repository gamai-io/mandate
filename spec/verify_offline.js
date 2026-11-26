#!/usr/bin/env node
// Verify a Mandate grant and receipt with Node's standard library only.
//
// A second implementation, in another language and on another crypto library
// (OpenSSL through Node, not our Python), so "who verifies your verifier" has a
// concrete answer that does not depend on the vendor's package.
//
//   node spec/verify_offline.js --grant spec/vectors/grant.json \
//        --intent spec/vectors/intent.json --signers spec/vectors/allowed_signers \
//        --receipt spec/vectors/receipt.json
//
// Exit 0 = every check passed, 1 = at least one failed, 2 = usage.
"use strict";
const crypto = require("crypto");
const fs = require("fs");


// ------------------------------------------------------- strict JSON
// A verifier that reads {"a":1,"a":2} as {"a":2} can disagree with the signer about
// what was signed. Refuse duplicates, integers a double cannot hold, and lone
// surrogates before any hash is computed (same rules as the Python verifier).
function strictParse(text) {
  const stack = [];            // [{keys:Set|null, expectKey:bool}]
  let i = 0;
  const n = text.length;
  let pending = "";
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1, out = "";
      while (j < n) {
        if (text[j] === "\\") { out += text[j] + text[j + 1]; j += 2; continue; }
        if (text[j] === '"') break;
        out += text[j]; j += 1;
      }
      if (j >= n) throw new Error("syntax: unterminated string");
      const raw = text.slice(i, j + 1);
      const top = stack[stack.length - 1];
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(raw);
        if (top.keys.has(key)) throw new Error("duplicate_key: " + key);
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (c === "{") { stack.push({ keys: new Set(), expectKey: true }); i += 1; continue; }
    if (c === "[") { stack.push({ keys: null, expectKey: false }); i += 1; continue; }
    if (c === "}" || c === "]") { stack.pop(); i += 1; continue; }
    if (c === ",") {
      const top = stack[stack.length - 1];
      if (top && top.keys) top.expectKey = true;
      i += 1; continue;
    }
    if (c === ":") { i += 1; continue; }
    if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < n && /[-+0-9.eE]/.test(text[j])) j += 1;
      const token = text.slice(i, j);
      if (/^-?\d+$/.test(token)) {
        const digits = token.replace("-", "");
        if (digits.length > 16 || Math.abs(Number(token)) > Number.MAX_SAFE_INTEGER) {
          throw new Error("int_range: " + token);
        }
      }
      i = j; continue;
    }
    i += 1;
  }
  const value = JSON.parse(text);            // rejects NaN/Infinity and bad syntax
  const bad = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
  const walk = (v) => {
    if (typeof v === "string") { if (bad.test(v)) throw new Error("lone_surrogate"); return; }
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(value);
  return value;
}

function readJson(path) {
  return strictParse(fs.readFileSync(path, "utf8"));
}

// ------------------------------------------------------------------ JCS
function jcs(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Object.is(value, -0)) return "0";
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new Error("unsupported type " + typeof value);
}

const sha256hex = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

// -------------------------------------------------------------- SSHSIG
function readString(blob, offset) {
  const length = blob.readUInt32BE(offset);
  const start = offset + 4;
  if (start + length > blob.length) throw new Error("truncated");
  return [blob.subarray(start, start + length), start + length];
}

function sshString(data) {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(data.length, 0);
  return Buffer.concat([header, data]);
}

function parseSshsig(armored) {
  const body = armored.split("\n").filter((l) => l && !l.startsWith("-----")).join("");
  const blob = Buffer.from(body, "base64");
  if (blob.subarray(0, 6).toString() !== "SSHSIG") throw new Error("bad magic");
  const version = blob.readUInt32BE(6);
  if (version !== 1) throw new Error("unsupported SSHSIG version");
  let offset = 10;
  let publicKey, namespace, reserved, hashAlg, signature;
  [publicKey, offset] = readString(blob, offset);
  [namespace, offset] = readString(blob, offset);
  [reserved, offset] = readString(blob, offset);
  [hashAlg, offset] = readString(blob, offset);
  [signature, offset] = readString(blob, offset);
  const [keyType] = readString(publicKey, 0);
  const [keyBytes] = readString(publicKey, 4 + keyType.length);
  const [sigType] = readString(signature, 0);
  const [sigBytes] = readString(signature, 4 + sigType.length);
  if (keyType.toString() !== "ssh-ed25519" || sigType.toString() !== "ssh-ed25519") {
    throw new Error("only ssh-ed25519 is checked by this script");
  }
  return { publicKey: keyBytes, namespace: namespace.toString(),
           reserved, hash: hashAlg.toString(), signature: sigBytes };
}

function ed25519Verify(rawKey, signature, message) {
  // SPKI DER prefix for Ed25519, then the 32 raw bytes.
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = crypto.createPublicKey({ key: Buffer.concat([prefix, rawKey]),
                                       format: "der", type: "spki" });
  return crypto.verify(null, message, key, signature);
}

function verifySig(armored, payload, namespace) {
  const parsed = parseSshsig(armored);
  if (parsed.namespace !== namespace) {
    return [false, `namespace is ${parsed.namespace}, expected ${namespace}`];
  }
  const digest = crypto.createHash(parsed.hash).update(payload, "utf8").digest();
  const toSign = Buffer.concat([Buffer.from("SSHSIG"), sshString(Buffer.from(parsed.namespace)),
                                sshString(parsed.reserved), sshString(Buffer.from(parsed.hash)),
                                sshString(digest)]);
  return ed25519Verify(parsed.publicKey, parsed.signature, toSign)
    ? [true, "signature verifies"] : [false, "signature does not verify"];
}

// --------------------------------------------------------------- Mandate-1
function render(intent) {
  const effect = intent.effect || {};
  const parts = [String(effect.kind || "?")];
  if (effect.target !== undefined && effect.target !== null) {
    parts.push("target=" + JSON.stringify(effect.target));
  }
  const amount = effect.amount || {};
  if (amount.value !== undefined && amount.value !== null) {
    parts.push("amount=" + Number(amount.value).toFixed(2) + " " + amount.currency);
  }
  for (const key of Object.keys(effect.params || {}).sort()) {
    parts.push(key + "=" + JSON.stringify(effect.params[key]));
  }
  const evidence = Array.from(new Set((intent.provenance || [])
    .filter((p) => p && p.type === "data_ref" && p.source)
    .map((p) => String(p.source)))).sort();
  if (evidence.length) parts.push("evidence=" + evidence.join(","));
  const value = amount.value === undefined || amount.value === null ? null : Number(amount.value);
  return { summary: parts.join(" | "),
           fields: { kind: effect.kind === undefined ? null : effect.kind,
                     target: effect.target === undefined ? null : effect.target,
                     amount: value === null ? null
                       : { value, currency: amount.currency === undefined ? null : amount.currency },
                     params: effect.params || {},
                     evidence } };
}

const renderHash = (intent) => sha256hex(jcs(render(intent)));
const provenanceHash = (intent) => sha256hex(jcs(intent.provenance || []));

function intentCore(intent) {
  const effect = Object.assign({}, intent.effect);
  effect.revert = effect.revert || "irreversible";
  const actor = intent.actor || {};
  return { v: intent.v === undefined ? 1 : intent.v,
           actor: { agent: actor.agent || null, session: actor.session || null },
           nonce: intent.nonce === undefined ? null : intent.nonce,
           effect, requested_by: intent.requested_by === undefined ? null : intent.requested_by,
           render_hash: renderHash(intent),
           provenance_hash: provenanceHash(intent) };
}

const commitmentOf = (intent) => "sha256:" + sha256hex(jcs(intentCore(intent)));

function allowedEntries(path) {
  const entries = [];
  for (const line of fs.readFileSync(path, "utf8").split("\n")) {
    const raw = line.trim();
    if (raw.length < 3 || raw.startsWith("#")) continue;
    const tokens = raw.split(/\s+/);
    const index = tokens.findIndex((t) => t.startsWith("ssh-") || t.startsWith("sk-"));
    if (index < 0 || index + 1 >= tokens.length) continue;
    const options = raw.slice(0, raw.indexOf(tokens[index])).split("#")[0];
    const ns = /namespaces\s*=\s*"([^"]*)"/.exec(options);
    const va = /valid-after\s*=\s*"([^"]*)"/.exec(options);
    const vb = /valid-before\s*=\s*"([^"]*)"/.exec(options);
    const blob = Buffer.from(tokens[index + 1], "base64");
    const [type] = readString(blob, 0);
    const [key] = readString(blob, 4 + type.length);
    entries.push({
      principal: tokens[0],
      key,
      fingerprint: "SHA256:" + crypto.createHash("sha256").update(blob).digest("base64").replace(/=+$/, ""),
      namespaces: ns ? ns[1].split(",").map((x) => x.trim()).filter(Boolean) : [],
      after: va ? va[1] : null,
      before: vb ? vb[1] : null,
    });
  }
  return entries;
}

function normFingerprint(value) {
  return String(value || "").trim().toLowerCase().replace(/^sha256:/, "");
}

function loadRevoked(path) {
  const out = new Set();
  if (!path || !fs.existsSync(path)) return out;
  for (const line of fs.readFileSync(path, "utf8").split("\n")) {
    if (line.trim() && !line.trim().startsWith("#")) {
      out.add(normFingerprint(line.trim().split(/\s+/)[0]));
    }
  }
  return out;
}

function principalMatches(field, name) {
  return String(field).split(",").some((pattern) => {
    const escaped = pattern.trim().replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*");
    return escaped && new RegExp("^" + escaped + "$").test(name);
  });
}

function stamp(value) {
  let text = String(value || "").trim();
  if (!text) return null;
  if (text.length === 8) text += "000000";
  else if (text.length === 12) text += "00";
  return /^\d{14}$/.test(text) ? text : "invalid";
}

function validNow(entry, now) {
  const moment = new Date(now * 1000).toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const after = stamp(entry.after);
  const before = stamp(entry.before);
  if (after === "invalid" || before === "invalid") return false;
  if (after && moment < after) return false;
  if (before && moment >= before) return false;
  return true;
}

function authorized(entries, approver, embedded, namespace, revoked) {
  const now = Date.now() / 1000;
  const fp = normFingerprint("SHA256:" + crypto.createHash("sha256")
    .update(embedded).digest("base64").replace(/=+$/, ""));
  if (revoked.has(fp)) return [false, "the signature key is revoked"];
  for (const entry of entries) {
    if (!principalMatches(entry.principal, approver)) continue;
    if (!entry.key.equals(embedded)) continue;
    if (!entry.namespaces.includes(namespace)) continue;
    if (!validNow(entry, now)) continue;
    return [true, "signature key is authorised"];
  }
  return [false, "signature key is not authorised (namespace/validity/revocation)"];
}

// --------------------------------------------------------------------- CLI
function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

function main() {
  const grantPath = arg("--grant");
  const signersPath = arg("--signers");
  if (!grantPath || !signersPath) {
    console.error("usage: verify_offline.js --grant G --signers S [--intent I] [--receipt R]");
    return 2;
  }
  const checks = [];
  const errors = [];
  const check = (name, ok, detail) => {
    checks.push({ check: name, ok, detail });
    if (!ok) errors.push(detail);
  };
  const grantObj = readJson(grantPath);
  const core = grantObj.grant || {};

  const [sigOk, sigWhy] = verifySig(grantObj.sig || "", jcs(core) + "\n", "mandate");
  check("grant_signature", sigOk, sigWhy);

  const entries = allowedEntries(signersPath);
  const approver = core.approver || "";
  let embedded;
  try {
    embedded = parseSshsig(grantObj.sig || "").publicKey;
  } catch (exc) {
    embedded = null;
  }
  const [authorised, why] = embedded
    ? authorized(entries, approver, embedded, "mandate", loadRevoked(arg("--revoked")))
    : [false, "grant signature is missing or unreadable"];
  check("signer_authorised", authorised, why);

  if (process.env.MANDATE_DEBUG) {
    const i = readJson(arg("--intent"));
    console.error("CORE=" + jcs(intentCore(i)));
  }
  const intentPath = arg("--intent");
  if (intentPath) {
    const intent = readJson(intentPath);
    const computed = commitmentOf(intent);
    check("commitment_matches_intent", computed === core.commitment,
          `computed ${computed}, grant says ${core.commitment}`);
    if (core.render_hash) {
      check("render_hash_matches_intent", core.render_hash === renderHash(intent),
            `approver saw ${render(intent).summary}`);
    }
  }

  const receiptPath = arg("--receipt");
  if (receiptPath) {
    const receipt = readJson(receiptPath);
    const body = receipt.body || {};
    check("receipt_hash", sha256hex(jcs(body)) === receipt.hash,
          `receipt hash ${sha256hex(jcs(body))} vs body`);
    check("receipt_bound_to_grant", body.commitment === core.commitment,
          `commitment ${body.commitment}`);
  }

  console.log(JSON.stringify({ ok: errors.length === 0, checks, errors }, null, 1));
  return errors.length === 0 ? 0 : 1;
}

try {
  process.exitCode = main();
} catch (exc) {
  // A document that cannot be parsed strictly is a refusal, not a crash: say which rule.
  const code = String(exc && exc.message || exc).split(":")[0];
  console.error(JSON.stringify({ ok: false, error: code, detail: String(exc && exc.message || exc) }));
  process.exitCode = 1;
}
