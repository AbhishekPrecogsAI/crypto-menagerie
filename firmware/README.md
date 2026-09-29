# firmware/ — code-signing & firmware artefacts (CS-SVC)

This folder stands in for a signed firmware image and its signing metadata,
so the demo also exercises the **code-signing** side of the inventory
(CS-001…CS-003), not just source-level crypto.

In a real build you would drop here:

- `image.bin` — the firmware binary.
- `image.bin.sig` — its detached signature.
- `manifest.json` — signer identity, hash algorithm, and key reference.

Demo signing metadata (what a scanner would read from the manifest):

```json
{
  "artifact": "image.bin",
  "hashAlgorithm": "SHA-256",
  "signatureAlgorithm": "ML-DSA-65",
  "signerKeyId": "pqc-signing-01",
  "legacyFallback": "SHA1withRSA",
  "storedIn": "hsm-prod-01"
}
```

The `legacyFallback` (SHA1withRSA) is intentional — it should surface as a
deprecated signing path that needs removing, while the primary signature is
already post-quantum (ML-DSA-65).
