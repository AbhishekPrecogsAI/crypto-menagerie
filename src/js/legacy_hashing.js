// legacy_hashing.js — deliberately weak/deprecated primitives.
// Expected CBOM findings: MD5 (CRITICAL), SHA-1 (HIGH), RIPEMD-160,
// HMAC-SHA1, DES-CBC. These are the "must be removed" rows for CA-004.
const crypto = require("node:crypto");

// MD5 — broken collision resistance. Do not use.
function fileChecksum(buf) {
  return crypto.createHash("md5").update(buf).digest("hex");
}

// SHA-1 — deprecated for signatures and integrity.
function legacyDigest(data) {
  return crypto.createHash("sha1").update(data).digest("hex");
}

// RIPEMD-160 — legacy, still seen in some wallet/address code.
function ripemd(data) {
  return crypto.createHash("ripemd160").update(data).digest("hex");
}

// HMAC-SHA1 — weak MAC, still used by old webhook signers.
function signWebhook(payload, secret) {
  return crypto.createHmac("sha1", secret).update(payload).digest("hex");
}

// DES-CBC — 56-bit key, trivially brute-forced.
function desEncrypt(plaintext, key8, iv8) {
  const cipher = crypto.createCipheriv("des-cbc", key8, iv8);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

module.exports = { fileChecksum, legacyDigest, ripemd, signWebhook, desEncrypt };
