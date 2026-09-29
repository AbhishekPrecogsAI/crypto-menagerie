// demo/pki-server.js — a tiny "internal PKI" for the Precogs "Fetch from URL"
// demo. Serves ../certs as a directory listing, but only to a caller that sends
// the right credentials, so the Bearer token and Basic auth modes can be shown.
//
//   node demo/pki-server.js
//   → http://localhost:8088/certs/        (directory listing)
//   → http://localhost:8088/certs/index.txt
//
// Bearer token : demo-token-123        (override with PKI_TOKEN)
// Basic auth   : pki / pki-demo-pass   (override with PKI_USER / PKI_PASS)
// Port         : 8088                  (override with PORT)
//
// It listens on localhost, so the Precogs backend must be allowed to fetch
// internal addresses: CERT_FETCH_ALLOW_PRIVATE=true in its .env.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const PORT = Number(process.env.PORT || 8088);
const TOKEN = process.env.PKI_TOKEN || "demo-token-123";
const USER = process.env.PKI_USER || "pki";
const PASS = process.env.PKI_PASS || "pki-demo-pass";
const CERTS = path.join(__dirname, "..", "certs");
const CERT_RE = /\.(pem|crt|cer|der|p7b|p12|pfx|jks)$/i;

function authorized(header = "") {
  if (header === `Bearer ${TOKEN}`) return "bearer";
  if (header === `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`) return "basic";
  return null;
}

http.createServer((req, res) => {
  const how = authorized(req.headers.authorization);
  const url = decodeURIComponent(req.url.split("?")[0]);
  console.log(`${new Date().toISOString()} ${req.method} ${url} → ${how || "401"}`);
  if (!how) {
    res.writeHead(401, { "WWW-Authenticate": 'Bearer realm="demo-pki"' });
    return res.end("Unauthorized\n");
  }

  if (url === "/certs/" || url === "/certs") {
    const files = fs.readdirSync(CERTS).filter((f) => CERT_RE.test(f));
    res.writeHead(200, { "content-type": "text/html" });
    return res.end(`<html><body><h1>Index of /certs/</h1>${files.map((f) => `<a href="${f}">${f}</a><br>`).join("")}</body></html>`);
  }

  const name = path.basename(url);
  const file = path.join(CERTS, name);
  if (url.startsWith("/certs/") && (CERT_RE.test(name) || name === "index.txt") && fs.existsSync(file)) {
    res.writeHead(200, { "content-type": name.endsWith(".txt") ? "text/plain" : "application/x-pem-file" });
    return res.end(fs.readFileSync(file));
  }
  res.writeHead(404);
  res.end("Not found\n");
}).listen(PORT, () => {
  console.log(`Demo PKI on http://localhost:${PORT}/certs/  (Bearer ${TOKEN} | Basic ${USER}/${PASS})`);
});
