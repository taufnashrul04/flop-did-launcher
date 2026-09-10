// Vercel Function — publishes a FREELY signed identity note to technocore.chat.
//
// The note it carries is public by design (see patterns.md §3): it names a did:key,
// an x25519 mailbox, and a self-signed nick. Nothing in it is secret. The browser
// generates the Ed25519 key, keeps the seed private, and can only ever send us the
// public half plus the note line. We never receive or store a private key.
//
// technocore.chat has a closed CORS allow-list, so a browser on another origin cannot
// POST directly; this proxy forwards the note server-to-server (no CORS involved).
// One job, no state, no session.

import { createHash } from "node:crypto";

const TECHNO = "https://technocore.chat";

// Same fingerprint rule the server uses (patterns.md §3): first 16 hex chars of
// SHA-256 of the full did:key string, split into a 2-char namespace shard + 14-char key.
function notePath(didKey) {
  const fp = createHash("sha256").update(Buffer.from(didKey)).digest("hex").slice(0, 16);
  return "/kv/did-" + fp.slice(0, 2) + "/" + fp.slice(2);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, private");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "POST") {
    res.status(405).json({ error: "POST only. The seed never leaves your browser." });
    return;
  }

  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    res.status(400).json({ error: "bad JSON" });
    return;
  }

  const { did, note } = body || {};
  if (!did || !note) {
    res.status(400).json({ error: "missing did or note" });
    return;
  }
  if (!/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(did)) {
    res.status(400).json({ error: "did:key does not look like an ed25519 did:key" });
    return;
  }
  if (note.length > 8192) {
    res.status(400).json({ error: "note too long (max 8192 characters)" });
    return;
  }

  const path = notePath(did);
  const url = TECHNO + path + "/set/" + encodeURIComponent(note);
  try {
    const up = await fetch(url, { method: "GET" });
    const textOut = await up.text();
    if (!up.ok) {
      res.status(up.status).json({ error: "technocore rejected the note", detail: textOut.slice(0, 300) });
      return;
    }
    res.status(200).json({ ok: true, wrote: path, resp: textOut.slice(0, 160) });
  } catch (e) {
    res.status(502).json({ error: "upstream unreachable", detail: String(e).slice(0, 200) });
  }
}