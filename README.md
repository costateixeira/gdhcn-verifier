# QR → COSE Verifier (GDHCN / WHO SMART Trust)

Decode a QR image (EU DCC-style: `HC1:` → Base45 → zlib → COSE_Sign1) and verify its ES256 signature using the **GDHCN** (WHO SMART Trust) public trustlist — or a local certificate/key.

---

## What this tool does — functional flow (end-to-end)

1. **Read the QR image**
   - Uses OpenCV to detect and decode the QR from `--img <file>`.
   - If multiple QR codes are present, it picks the first with `HC1:`; otherwise the first non-empty payload.

2. **Extract `HC1:` content**
   - If the QR content starts with the literal prefix `HC1:`, the script **uses only the part *after* `HC1:`**.
   - If there is no `HC1:` prefix, the script treats the entire string as Base45.

3. **Base45 decode (DCC standard)**
   - The script **preserves spaces** (space is a valid Base45 character).
   - Only characters from the Base45 alphabet (`0-9 A-Z space $%*+-./:`) are consumed.
   - Decoding produces a zlib-compressed blob.

4. **Decompress (zlib / deflate)**
   - First tries standard zlib decompression.
   - If that fails, retries raw DEFLATE (`wbits = -15`).
   - The result is the **raw COSE_Sign1** CBOR bytes, which are saved as `cose.cbor`.

5. **Parse COSE_Sign1**
   - Expects a COSE_Sign1 structure (CBOR tag 18) of the form:
     ```
     [ protected_bstr, unprotected_map, payload_bstr_or_nil, signature_bstr ]
     ```
   - Extracts:
     - `protected_bstr` (CBOR-encoded protected headers)
     - `payload_bstr`  (CBOR-encoded payload, or empty bstr if `nil`)
     - `signature_bstr` (ECDSA raw signature = `r || s`)
   - Decodes the protected headers to confirm:
     - `alg` (label `1`) is **`-7`** (ES256)
     - optional `kid` (label `4`) as a **byte string**; the script logs `kid` in Base64 for convenience.

6. **Build bytes to be signed**
   - COSE signing input is the CBOR-encoded **Sig_structure**:
     ```
     Sig_structure = [
       "Signature1",
       protected_bstr,   // exact bytes from the COSE object
       h'',              // empty bstr as external_aad
       payload_bstr      // exact bytes from the COSE object
     ]
     ```
   - This preserves the original byte strings exactly (no JSON re-encoding).

7. **Verify ECDSA (ES256)**
   - Converts the COSE raw `r || s` signature to DER form for the crypto library.
   - Computes and verifies ECDSA P-256 with SHA-256 over the Sig_structure.
   - Public key source:
     - **GDHCN trustlist** (recommended):
       - You can choose environment: `prod`, `uat`, or `dev`.
       - The script fetches `v2/trustlist/<domain>/<participant>/<usage>/did.json` (defaults: `domain=DCC`, `participant=-` for “all”, `usage=DSC`).
       - Extracts EC P-256 keys from `verificationMethod[].publicKeyJwk`, preferring `x5c` (certificate chain) if present.
       - If a `kid` is present in the COSE protected headers, it tries matching keys first; otherwise it tries all.
     - **Local certificate/public key** (fallback):
       - Provide `--cert cert.pem` (PEM), `--cert cert.der` (DER), or a Base64-DER text file; auto-detected and parsed.

8. **Artifacts written**
   - `cose.cbor` — the exact raw COSE_Sign1 bytes extracted from the QR.
   - `payload.cbor` — raw payload bytes (as present in COSE).
   - `payload.json` — human-readable JSON if `payload_bstr` decodes as CBOR → JSON.

---

## Why “decode after `HC1:`” matters

- The `HC1:` prefix is **not** data; it indicates an EU DCC payload.
- The **Base45 decoding must run on the substring after `HC1:`** to obtain valid zlib/COSE bytes.
- If there is **no** `HC1:` prefix, the script treats the entire string as Base45 (useful for raw Base45 inputs).

---

## Requirements

- Python 3.9+
- Install dependencies:
  ```bash
  pip install opencv-python cryptography cbor2 requests
  ```

---

## Usage

### Verify with GDHCN trustlist (recommended)

```bash
# PROD trustlist
python verify_cose_from_qr_gdhcn.py --img qr.jpg --gdhcn

# DEV trustlist (common for test/preview QRs, e.g., issuing country XM)
python verify_cose_from_qr_gdhcn.py --img qr.jpg --gdhcn --gdhcn-env dev

# Narrow to a participant (faster lookups), e.g. XXA in DEV
python verify_cose_from_qr_gdhcn.py --img qr.jpg --gdhcn --gdhcn-env dev --participant XXA
```

### Verify with a local cert/key (fallback)

```bash
# PEM or DER certificate (or SubjectPublicKeyInfo); also accepts Base64-DER text
python verify_cose_from_qr_gdhcn.py --img qr.jpg --cert cert.pem
```

### CLI options

```
--img            Path to QR image (jpg/png/webp). Required.
--gdhcn          Fetch keys from GDHCN trustlist (WHO SMART Trust CDN).
--gdhcn-env      prod | uat | dev   (default: prod)
--participant    Optional participant code (e.g., BEL, FRA, WHO, XXA). Default: all ("-")
--domain         Trust domain, default: DCC
--usage          Key usage, default: DSC (Document Signing Cert)
--cert           Optional local certificate/public key (PEM/DER/Base64-DER)
```

---

## Typical output

```
📷 QR content: HC1:6BFOXNMG2N9H56L$MP 7PXH...
🔧 Base45 decoded length: 394
🔧 Decompressed length: 390  Head: d2 84 51 a2 ...
🧭 Protected headers: alg=-7  kid_b64=qb4L0atiX/4=
📝 Wrote payload.cbor and payload.json
🌐 Fetched 123 keys from GDHCN trustlist:
   https://tng-cdn.who.int/v2/trustlist/DCC/-/DSC/did.json
✅ Signature VALID with key kid=qb4L0atiX/4=
```

---

## Troubleshooting & edge cases

- **No QR found / can’t decode**  
  Ensure the image is clear, not too small/blurred; crop to the QR if needed.

- **Base45 errors**  
  Content may not be EU DCC-style; confirm the QR data or ensure the `HC1:` prefix is present. The decoder preserves spaces by design.

- **Decompression fails**  
  The script tries both zlib and raw deflate. If both fail, the payload likely isn’t DCC.

- **Unsupported algorithm**  
  The script expects ES256 (`alg = -7`). Extend verification if your use case needs other COSE algorithms.

- **Verification failed**  
  - Wrong GDHCN environment (try `--gdhcn-env dev` for test QRs).
  - Issuer not present in the chosen trustlist or participant filter too narrow.
  - The QR isn’t DCC/COSE_Sign1 with P-256 ES256.

- **Missing `kid`**  
  Some issuers omit `kid`; the script will try all keys from the trustlist (slower). Use `--participant` to speed it up.

---

## Files in this repo

- `verify_cose_from_qr_gdhcn.py` — the verifier script.
- (generated) `cose.cbor`, `payload.cbor`, `payload.json` — artifacts for audit/debug.

---

## Implementation details (for integrators)

- **Base45**: Implements strict Base45 over the official alphabet and **keeps spaces** (they are valid characters).
- **COSE parsing**: Uses `cbor2`. The script refuses to reconstruct protected/payload from JSON; it uses the **exact byte strings** from the QR.
- **Sig_structure**: Built per COSE spec with `external_aad = b""`.
- **ECDSA**: Converts raw COSE `r || s` into DER for use with `cryptography`’s ECDSA verifier on P-256, SHA-256.
- **GDHCN trustlist**: Fetches DID v2 trustlists from the WHO CDN. Prefers JWKs with `x5c` to ensure correct leaf selection; falls back to `x`/`y`.

---

## Disclaimer

- This tool verifies **cryptographic signatures** only. It does not validate payload semantics, certificate revocation, policy compliance, or freshness. Always apply additional business rules as required by your domain.
