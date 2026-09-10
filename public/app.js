// FLOP DID Launcher — client-side identity generation.
//
// The seed is created here, used to derive the Ed25519 keypair, shown exactly once, and
// then wiped. Only the PUBLIC half (did + x25519 mailbox pub + signed note) is ever sent
// to the proxy.
//
//   - Ed25519 did:key   (multibase base58btc 'z' + multicodec 0xed 0x01 + 32-byte pub)
//   - x25519 mailbox    (browser-native X25519 keypair — the inbox for end-to-end mail)
//   - signed `nick:`    (Ed25519 over `<full did:key>|<name>` — patterns.md §3 / #355)

const B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(raw) {
  let n = BigInt("0x" + Array.from(raw).map(b => b.toString(16).padStart(2, "0")).join(""));
  let out = "";
  while (n > 0n) { out = B58_ALPHA[n % 58n] + out; n /= 58n; }
  return "z" + out; // multibase 'z' = base58btc
}
function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlFromJwkX(x) {
  // JWK 'x' is already unpadded base64url.
  return x;
}
function hex2bytes(hex) { return new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16))); }

// RFC 8410 DER-wrapped Ed25519 seed so crypto.subtle can import it.
function seedToPkcs8(seed) {
  return new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, ...seed,
  ]);
}

// ---- Ed25519 keypair + did:key -----------------------------------------------------
async function generateKeypair() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const priv = await crypto.subtle.importKey(
    "pkcs8", seedToPkcs8(seed),
    { name: "Ed25519" }, true, ["sign"]
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", priv);
  const pub = hex2bytes(pubJwk.x); // raw 32-byte ed25519 public key
  const did = "did:key:" + b58encode(new Uint8Array([0xed, 0x01, ...pub]));
  return { seed, priv, did };
}

// ---- x25519 mailbox (browser-native, independent of the ed25519 seed) --------------
async function generateMailbox() {
  // `deriveBits` is a real, non-empty usage so WebCrypto will create the key; we only
  // export the public half for the mailbox field.
  const kp = await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"]
  );
  const jwkX = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return b64urlFromJwkX(jwkX.x);
}

// ---- sign nick ----------------------------------------------------------------------
async function signNick(priv, did, nick) {
  const msg = new TextEncoder().encode(did + "|" + nick);
  const sig = await crypto.subtle.sign("Ed25519", priv, msg);
  return b64url(new Uint8Array(sig));
}

window.FLOP = { generateKeypair, generateMailbox, signNick, b64url, b58encode, b64urlFromJwkX, hex2bytes };