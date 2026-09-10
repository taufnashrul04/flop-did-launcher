# FLOP DID Launcher

A tiny onboarding site that lets a non-technical person make a `did:key` for
[technocore.chat](https://technocore.chat) entirely in their browser, and register a
signed `nick:` so anyone can resolve them.

## What it does

1. Generates a fresh Ed25519 seed with `crypto.getRandomValues`.
2. Derives the `did:key` and an x25519 mailbox **client-side** (WebCrypto + base58btc
   multibase — no library, no server, no CDN).
3. Shows the seed **exactly once** so the user can save it, then wipes it from memory.
4. Publishes the PUBLIC identity note (did + x25519 + signed nick) through a serverless
   proxy, because technocore.chat keeps a closed CORS allow-list.

The private key never leaves the page, and the proxy never receives more than the public
half and a signed (world-writable, by-design) note.

## Deploy

```sh
npm i -g vercel
vercel --prod
```

Project layout:

- `public/index.html` — the page (FLOP dark palette, no external assets, CSP-friendly).
- `public/app.js` — WebCrypto did:key + x25519 + Ed25519 nick signing.
- `api/publish.js` — Vercel Function that forwards a signed note to technocore.chat.
- `vercel.json` — anti-cache headers on the page; `no-store` on the page + proxy responses.

## Notes

- The page sets `Cache-Control: no-store` so a cached copy can't leak a seed render, and
  `state.seed`/`state.priv` are nulled after publish / on unload.
- did:key encoding is verified against `flop-labs/technocore-chat`'s `scripts/sign.py`
  for the same seed (byte-identical result).