// modern_crypto.js — the "good" classical baseline the deprecated code
// should migrate to. Expected CBOM: AES-256-GCM, SHA-256/512, scrypt,
// Ed25519 (signing), X25519 (ECDH). These are conformant-today but still
// classically-quantum-vulnerable where asymmetric (harvest-now-decrypt-later).
const crypto = require("node:crypto");

// AES-256-GCM — authenticated encryption, the target for symmetric.
function encrypt(plaintext, key32) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext: ct, tag: cipher.getAuthTag() };
}

// SHA-256 / SHA-512 — modern digests.
const sha256 = (d) => crypto.createHash("sha256").update(d).digest("hex");
const sha512 = (d) => crypto.createHash("sha512").update(d).digest("hex");

// scrypt — memory-hard password KDF.
function derivePasswordKey(password, salt) {
  return crypto.scryptSync(password, salt, 32);
}

// Ed25519 — modern signature scheme.
function ed25519Sign(message, privateKey) {
  return crypto.sign(null, Buffer.from(message), privateKey);
}

// X25519 — modern ECDH key agreement (still Shor-breakable → PQC needed).
function x25519Shared() {
  const alice = crypto.generateKeyPairSync("x25519");
  const bob = crypto.generateKeyPairSync("x25519");
  return crypto.diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });
}

module.exports = { encrypt, sha256, sha512, derivePasswordKey, ed25519Sign, x25519Shared };
