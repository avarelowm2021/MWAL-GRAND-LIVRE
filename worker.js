/**
 * MWAL Grand Ledger API — Cloudflare Worker (Free)
 * Endpoints:
 *   GET  /stats    -> returns public stats.json
 *   POST /submit   -> accepts { type: "mint"|"validated", payload: <proof|package|observerExport>, source?: {...} }
 *
 * Storage:
 *  - GitHub repo (public) for immutable ledger files
 *  - Cloudflare KV for:
 *      - txId uniqueness (anti double submit)
 *      - cached stats (fast /stats)
 *
 * REQUIRED ENV (Worker Settings):
 *  - GITHUB_OWNER        (e.g. "YourUser")
 *  - GITHUB_REPO         (e.g. "MWAL-GRAND-LIVRE")
 *  - GITHUB_BRANCH       (e.g. "main")
 *  - GITHUB_TOKEN        (secret) fine-grained token with "Contents: Read/Write" on that repo
 *  - LEDGER_KV           (KV namespace binding)
 */

const PROOF_PROTOCOL = "MWAL_MINING_V2";
const PACKAGE_PROTOCOL = "MWAL_PACKAGE_V1";
const OBS_PROTOCOL = "MWAL_OBSERVER_PACKAGE_V1";
const UNIT_MWAL_STR = "0.00000694444444444444";
const UNIT_MWAL = 0.00000694444444444444;
const INTERVAL_MS = 4000;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response("", { status: 204, headers: CORS_HEADERS });
    }

    if (url.pathname === "/stats" && req.method === "GET") {
      return await handleStats(req, env);
    }

    if (url.pathname === "/submit" && req.method === "POST") {
      return await handleSubmit(req, env);
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  }
};

// ------------------------- Helpers -------------------------

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
      ...extraHeaders,
    },
  });
}

function nowISO() {
  return new Date().toISOString();
}

function round8(n) {
  return Math.round((Number(n) + Number.EPSILON) * 1e8) / 1e8;
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function isObject(x) {
  return x && typeof x === "object" && !Array.isArray(x);
}

// Unwrap payload types: proof, package, observer export
function unwrapAny(raw) {
  if (!raw) throw new Error("EMPTY_PAYLOAD");

  // observer wrapper
  if (raw.protocol === OBS_PROTOCOL && raw.package) raw = raw.package;

  // package
  if (raw.protocol === PACKAGE_PROTOCOL && raw.proof) {
    return { kind: "package", proof: raw.proof, raw };
  }

  // raw proof
  if (raw.protocol === PROOF_PROTOCOL && Array.isArray(raw.blocks)) {
    return { kind: "proof", proof: raw, raw };
  }

  // sometimes {proof:{...}}
  if (raw.proof && raw.proof.protocol === PROOF_PROTOCOL) {
    return { kind: "proofWrap", proof: raw.proof, raw };
  }

  throw new Error("UNKNOWN_FORMAT");
}

function validateLogsV8(proof) {
  const logs = Array.isArray(proof.logs) ? proof.logs : [];
  if (logs.length < 2) return { ok: false, err: "LOGS_REQUIRED" };

  const hasStart = logs.some(x => x && x.type === "START");
  const hasDone = logs.some(x => x && x.type === "DONE");
  if (!hasStart || !hasDone) return { ok: false, err: "LOGS_INCOMPLETE_START_DONE" };

  const blocks = Array.isArray(proof.blocks) ? proof.blocks.length : 0;
  const blockLogs = logs.filter(x => x && x.type === "BLOCK").length;
  if (blockLogs !== blocks) return { ok: false, err: "LOGS_BLOCK_COUNT_MISMATCH" };

  // txId coherence (if logs include txId)
  if (proof.txId) {
    const mismatch = logs.some(x => x && x.txId && x.txId !== proof.txId);
    if (mismatch) return { ok: false, err: "LOGS_TXID_MISMATCH" };
  }

  // monotone ts
  let last = -Infinity;
  for (const l of logs) {
    const t = Date.parse(l.ts || "");
    if (!Number.isFinite(t)) return { ok: false, err: "LOGS_BAD_TS" };
    if (t < last) return { ok: false, err: "LOGS_NOT_MONOTONE" };
    last = t;
  }

  return { ok: true, logs };
}

async function validateProofStrict(proof) {
  if (!isObject(proof)) throw new Error("PROOF_NOT_OBJECT");
  if (proof.protocol !== PROOF_PROTOCOL) throw new Error("BAD_PROTOCOL");
  if (!proof.rules || proof.rules.unitMWAL !== UNIT_MWAL_STR || proof.rules.intervalMs !== INTERVAL_MS) {
    throw new Error("BAD_RULES");
  }
  if (!Array.isArray(proof.blocks) || proof.blocks.length < 1) throw new Error("EMPTY_BLOCKS");

  const vLogs = validateLogsV8(proof);
  if (!vLogs.ok) throw new Error(vLogs.err);

  let prev = "GENESIS";
  const blocks = proof.blocks;

  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i];

    if (String(b.amountMWAL) !== UNIT_MWAL_STR) throw new Error("BAD_UNIT_BLOCK");
    if (b.prevHash !== prev) throw new Error("BROKEN_CHAIN");

    if (i > 0) {
      const t0 = Date.parse(blocks[i - 1].timestamp);
      const t1 = Date.parse(b.timestamp);
      if (!Number.isFinite(t0) || !Number.isFinite(t1)) throw new Error("BAD_TIMESTAMP");
      if ((t1 - t0) !== INTERVAL_MS) throw new Error("BAD_INTERVAL");
    }

    // recompute hash (same principle as your system: hash over JSON without "hash")
    const copy = { ...b };
    delete copy.hash;
    const h = await sha256Hex(JSON.stringify(copy));
    if (h !== b.hash) throw new Error("BAD_HASH");
    prev = b.hash;
  }

  if (proof.finalHash && proof.finalHash !== prev) throw new Error("FINAL_HASH_MISMATCH");

  const proved = round8(blocks.length * UNIT_MWAL);

  return {
    txId: proof.txId || "",
    to: proof.to || "",
    walletId: proof.walletId || "",
    blocks: blocks.length,
    provedMWAL: proved,
    proofHash: await sha256Hex(JSON.stringify(proof)),
  };
}

// ------------------------- GitHub API -------------------------

async function ghRequest(env, method, path, body = null) {
  const url = `https://api.github.com${path}`;
  const headers = {
    "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
    "User-Agent": "MWAL-Ledger-Worker",
    "Accept": "application/vnd.github+json",
  };
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }

  if (!res.ok) {
    throw new Error(`GITHUB_${res.status}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
  }
  return data;
}

async function ghGetFile(env, path) {
  const owner = env.GITHUB_OWNER;
  const repo = env.GITHUB_REPO;
  const branch = env.GITHUB_BRANCH || "main";

  const data = await ghRequest(env, "GET", `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`);
  // content is base64
  const content = atob(data.content.replace(/\n/g, ""));
  return { sha: data.sha, content };
}

async function ghPutFile(env, path, contentText, message) {
  const owner = env.GITHUB_OWNER;
  const repo = env.GITHUB_REPO;
  const branch = env.GITHUB_BRANCH || "main";

  // Check if exists to include sha
  let sha = null;
  try {
    const existing = await ghRequest(env, "GET", `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`);
    sha = existing.sha;
  } catch (_) {
    sha = null; // new file
  }

  const body = {
    message,
    branch,
    content: btoa(unescape(encodeURIComponent(contentText))), // UTF-8 safe base64
    ...(sha ? { sha } : {}),
  };

  return await ghRequest(env, "PUT", `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, body);
}

// ------------------------- Handlers -------------------------

async function handleStats(_req, env) {
  // Serve from KV (fast). If missing, try GitHub stats.json, then cache.
  const cached = await env.LEDGER_KV.get("stats.json");
  if (cached) {
    return new Response(cached, { status: 200, headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
  }

  try {
    const { content } = await ghGetFile(env, "stats.json");
    await env.LEDGER_KV.put("stats.json", content, { expirationTtl: 60 }); // cache 60s
    return new Response(content, { status: 200, headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
  } catch {
    // default stats
    const initial = {
      updatedAt: nowISO(),
      minted: { proofs: 0, blocks: 0, mwal: "0.00000000" },
      validated: { proofs: 0, blocks: 0, mwal: "0.00000000" },
      ledgerHash: "",
    };
    return json(initial, 200);
  }
}

async function handleSubmit(req, env) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400);
  }

  const type = body?.type;
  const payload = body?.payload;
  const source = body?.source || {};

  if (type !== "mint" && type !== "validated") {
    return json({ ok: false, error: "BAD_TYPE", hint: "type must be mint|validated" }, 400);
  }
  if (!payload) {
    return json({ ok: false, error: "MISSING_PAYLOAD" }, 400);
  }

  // unwrap and validate
  let unwrapped;
  try {
    unwrapped = unwrapAny(payload);
  } catch (e) {
    return json({ ok: false, error: "UNWRAP_FAIL", detail: e.message }, 400);
  }

  const proof = unwrapped.proof;

  let proofMeta;
  try {
    proofMeta = await validateProofStrict(proof);
  } catch (e) {
    // optionally store rejected in GitHub too
    return json({ ok: false, error: "INVALID_PROOF", detail: e.message }, 400);
  }

  const txId = proofMeta.txId;
  if (!txId) return json({ ok: false, error: "MISSING_TXID" }, 400);

  // anti duplicate txId global (KV)
  const seenKey = `tx:${txId}`;
  const already = await env.LEDGER_KV.get(seenKey);
  if (already) {
    return json({ ok: false, error: "DUPLICATE_TXID", txId }, 409);
  }

  // Prepare ledger record (immutable)
  const receivedAt = nowISO();
  const record = {
    protocol: "MWAL_LEDGER_RECORD_V1",
    type,
    receivedAt,
    source,
    proofMeta,
    payloadKind: unwrapped.kind,
    // Store original payload too for full auditability
    payload: payload,
  };

  // path in repo (ledger/mint or ledger/validated)
  const safeTx = txId.replace(/[^A-Z0-9\-_]/gi, "_");
  const path = `ledger/${type}/${receivedAt.slice(0,10)}/${safeTx}.json`;
  const message = `MWAL ledger: ${type} ${txId}`;

  // update stats (read KV cache or GitHub, then increment)
  const currentStatsText = (await env.LEDGER_KV.get("stats.json")) || null;

  let stats;
  if (currentStatsText) {
    stats = JSON.parse(currentStatsText);
  } else {
    // fallback GitHub
    try {
      const gh = await ghGetFile(env, "stats.json");
      stats = JSON.parse(gh.content);
    } catch {
      stats = {
        updatedAt: nowISO(),
        minted: { proofs: 0, blocks: 0, mwal: "0.00000000" },
        validated: { proofs: 0, blocks: 0, mwal: "0.00000000" },
        ledgerHash: "",
      };
    }
  }

  // Increment
  const bucket = (type === "mint") ? stats.minted : stats.validated;
  bucket.proofs = (bucket.proofs || 0) + 1;
  bucket.blocks = (bucket.blocks || 0) + proofMeta.blocks;
  bucket.mwal = (round8(Number(bucket.mwal || 0) + proofMeta.provedMWAL)).toFixed(8);

  stats.updatedAt = nowISO();
  // ledger hash can be a simple rolling hash: hash(prevLedgerHash + proofHash)
  const prevLedgerHash = stats.ledgerHash || "";
  stats.ledgerHash = await sha256Hex(prevLedgerHash + proofMeta.proofHash);

  // Write to GitHub: record + updated stats.json
  try {
    await ghPutFile(env, path, JSON.stringify(record, null, 2), message);
    await ghPutFile(env, "stats.json", JSON.stringify(stats, null, 2), "MWAL stats update");
  } catch (e) {
    return json({ ok: false, error: "GITHUB_WRITE_FAIL", detail: e.message }, 500);
  }

  // mark txId as seen (KV)
  await env.LEDGER_KV.put(seenKey, "1", { expirationTtl: 60 * 60 * 24 * 365 * 5 }); // 5 years
  // cache stats
  await env.LEDGER_KV.put("stats.json", JSON.stringify(stats, null, 2), { expirationTtl: 60 });

  return json({
    ok: true,
    accepted: { type, txId, path, provedMWAL: proofMeta.provedMWAL, blocks: proofMeta.blocks },
    stats,
  }, 200);
}
