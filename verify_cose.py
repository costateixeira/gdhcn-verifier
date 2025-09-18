# verify_cose_from_qr_gdhcn.py
# Decodes a QR image (JPEG/PNG), extracts COSE (EU-DCC style), and verifies
# signature using WHO GDHCN trustlist (DID v2 embedded) OR a local certificate.
#
# WHO trustlist docs & endpoints:
# - DID Trustlist v2 with embedded keys and hierarchical filters:
#   https://tng-cdn.who.int/v2/trustlist/did.json
#   https://tng-cdn.who.int/v2/trustlist/<domain>/<participant>/<usage>/did.json
#   (see WHO SMART Trust spec)  <-- cited above
#
# Requires: pip install opencv-python cryptography cbor2 requests

import argparse
import base64
import binascii
import json
import sys
import zlib
from pathlib import Path

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# ---------- QR decode (OpenCV) ----------
def decode_qr_image(image_path: str) -> str:
    import cv2
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Could not read image: {image_path}")
    det = cv2.QRCodeDetector()
    try:
        retval, decoded_info, points, _ = det.detectAndDecodeMulti(img)
        if retval and decoded_info:
            decoded_info = [s for s in decoded_info if s]
            for s in decoded_info:
                if s.upper().startswith("HC1:"):
                    return s
            if decoded_info:
                return decoded_info[0]
    except Exception:
        pass
    data, points, _ = det.detectAndDecode(img)
    if not data:
        raise ValueError("No QR code detected or decoding failed.")
    return data

# ---------- Base45 ----------
_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_IDX = {c: i for i, c in enumerate(_B45)}
def base45_decode(s: str) -> bytes:
    s = "".join(ch for ch in s if ch in _B45_IDX)  # KEEP spaces
    out = bytearray()
    i = 0
    L = len(s)
    while i < L:
        if i + 2 < L:
            x = (_B45_IDX[s[i]]
                 + 45 * _B45_IDX[s[i+1]]
                 + 45 * 45 * _B45_IDX[s[i+2]])
            if x > 65535:
                raise ValueError("Invalid Base45 triple")
            out.append(x // 256)
            out.append(x % 256)
            i += 3
        else:
            if i + 1 >= L:
                raise ValueError("Invalid Base45 length")
            x = _B45_IDX[s[i]] + 45 * _B45_IDX[s[i+1]]
            if x > 255:
                raise ValueError("Invalid Base45 pair")
            out.append(x)
            i += 2
    return bytes(out)

# ---------- COSE parse/verify ----------
def load_cose_from_bytes(cose_bytes: bytes):
    obj = cbor2.loads(cose_bytes)
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != 18:  # COSE_Sign1
            raise ValueError(f"Unexpected CBOR tag {obj.tag}, expected 18")
        obj = obj.value
    if not (isinstance(obj, list) and len(obj) == 4):
        raise ValueError("Not a COSE_Sign1 array")
    protected_bstr, unprotected_map, payload_bstr, signature_bstr = obj
    if payload_bstr is None:
        payload_bstr = b""
    for name, val in [("protected", protected_bstr), ("payload", payload_bstr), ("signature", signature_bstr)]:
        if not isinstance(val, (bytes, bytearray)):
            raise ValueError(f"{name} must be a CBOR bstr")
    return bytes(protected_bstr), bytes(payload_bstr), bytes(signature_bstr)

def verify_es256(public_key, protected_bstr: bytes, payload_bstr: bytes, signature: bytes):
    sig_structure = ["Signature1", protected_bstr, b"", payload_bstr]
    to_be_signed = cbor2.dumps(sig_structure, canonical=True)
    if len(signature) % 2 != 0:
        raise ValueError(f"Unexpected ECDSA signature length: {len(signature)}")
    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    der_sig = encode_dss_signature(r, s)
    public_key.verify(der_sig, to_be_signed, ec.ECDSA(hashes.SHA256()))

# ---------- Helpers ----------
def b64u_to_bytes(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def cert_der_from_x5c_first(jwk: dict) -> bytes | None:
    x5c = jwk.get("x5c")
    if not x5c:
        return None
    try:
        return base64.b64decode(x5c[0])
    except Exception:
        return None

def pubkey_from_jwk_ec_p256(jwk: dict):
    # Prefer x5c if present (ensures we use the exact leaf cert)
    der = cert_der_from_x5c_first(jwk)
    if der:
        cert = x509.load_der_x509_certificate(der)
        return cert.public_key()

    # Fall back to x/y coordinates (JWK EC P-256)
    if jwk.get("kty") != "EC" or jwk.get("crv") not in ("P-256", "secp256r1"):
        return None
    x = int.from_bytes(b64u_to_bytes(jwk["x"]), "big")
    y = int.from_bytes(b64u_to_bytes(jwk["y"]), "big")
    curve = ec.SECP256R1()
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
    return pub_numbers.public_key()

def hexdump(b: bytes, n=16) -> str:
    return " ".join(f"{x:02x}" for x in b[:n])

# ---------- GDHCN trustlist fetch ----------
ENV_BASE = {
    "prod": "https://tng-cdn.who.int",
    "uat":  "https://tng-cdn-uat.who.int",
    "dev":  "https://tng-cdn-dev.who.int",
}

def fetch_gdhcn_pubkeys(env="prod", domain="DCC", usage="DSC", participant: str | None = None):
    """
    Returns a list of (kid, cryptography_public_key) from the embedded DID trustlist.
    If participant is None, fetches all participants for the given domain/usage.
    """
    base = ENV_BASE[env]
    if participant:
        url = f"{base}/v2/trustlist/{domain}/{participant}/{usage}/did.json"
    else:
        # all participants for DCC usage DSC
        url = f"{base}/v2/trustlist/{domain}/-/{usage}/did.json"
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    did = r.json()

    methods = did.get("verificationMethod", [])
    keys = []
    for vm in methods:
        jwk = vm.get("publicKeyJwk")
        if not jwk:
            continue
        kid = jwk.get("kid")
        try:
            pk = pubkey_from_jwk_ec_p256(jwk)
        except Exception:
            pk = None
        if pk is not None:
            keys.append((kid, pk))
    return keys, url

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Verify COSE/ES256 from QR image using GDHCN trustlist.")
    ap.add_argument("--img", required=True, help="Path to QR image (jpg/png/webp).")
    ap.add_argument("--cert", default=None, help="Fallback: path to PEM/DER/Base64-DER certificate/public key.")
    ap.add_argument("--gdhcn", action="store_true", help="Fetch keys from GDHCN trustlist.")
    ap.add_argument("--gdhcn-env", choices=["prod", "uat", "dev"], default="prod", help="GDHCN environment (default: prod).")
    ap.add_argument("--participant", default=None, help="Optional participant code (e.g., BEL, FRA, WHO, XXA).")
    ap.add_argument("--domain", default="DCC", help="Trust domain filter (default: DCC).")
    ap.add_argument("--usage", default="DSC", help="Key usage filter (default: DSC = Document Signing Cert).")
    args = ap.parse_args()

    # Read QR
    qr_text = decode_qr_image(args.img).strip()
    print(f"📷 QR content: {qr_text[:60]}{'...' if len(qr_text) > 60 else ''}")

    # HC1: Base45 → zlib → COSE bytes
    body = qr_text[4:] if qr_text.upper().startswith("HC1:") else qr_text
    b45 = base45_decode(body)
    print(f"🔧 Base45 decoded length: {len(b45)}")
    try:
        cose_bytes = zlib.decompress(b45)
    except zlib.error:
        cose_bytes = zlib.decompress(b45, wbits=-15)
    print(f"🔧 Decompressed length: {len(cose_bytes)}  Head: {hexdump(cose_bytes)}")

    # Parse COSE
    protected_bstr, payload_bstr, signature = load_cose_from_bytes(cose_bytes)
    prot = cbor2.loads(protected_bstr)
    alg = prot.get(1)
    kid_hdr = prot.get(4)
    kid_hdr_b64 = base64.b64encode(kid_hdr).decode() if isinstance(kid_hdr, (bytes, bytearray)) else None
    print(f"🧭 Protected headers: alg={alg}  kid_b64={kid_hdr_b64}")

    # Save payload for inspection
    Path("cose.cbor").write_bytes(cose_bytes)
    Path("payload.cbor").write_bytes(payload_bstr)
    try:
        payload_obj = cbor2.loads(payload_bstr)
        Path("payload.json").write_text(json.dumps(payload_obj, indent=2, ensure_ascii=False), encoding="utf-8")
        print("📝 Wrote payload.cbor and payload.json")
    except Exception:
        print("ℹ️ Payload not JSON-decodable (raw CBOR saved).")

    if alg != -7:
        print("❌ Unsupported alg (expected ES256 / -7).")
        sys.exit(2)

    # Build candidate public keys
    candidates = []

    if args.gdhcn:
        try:
            gkeys, used_url = fetch_gdhcn_pubkeys(
                env=args.gdhcn_env,
                domain=args.domain,
                usage=args.usage,
                participant=args.participant
            )
            print(f"🌐 Fetched {len(gkeys)} keys from GDHCN trustlist:\n   {used_url}")
            # If COSE kid present, try to match first
            if kid_hdr_b64:
                prioritized = [(k, pk) for (k, pk) in gkeys if k == kid_hdr_b64] + [(k, pk) for (k, pk) in gkeys if k != kid_hdr_b64]
                candidates.extend(prioritized)
            else:
                candidates.extend(gkeys)
        except Exception as e:
            print("⚠️  GDHCN fetch failed:", repr(e))

    # Fallback: local cert
    if args.cert and Path(args.cert).exists():
        data = Path(args.cert).read_bytes()
        pk = None
        if b"-----BEGIN " in data:
            try:
                cert = x509.load_pem_x509_certificate(data)
                pk = cert.public_key()
                print("🔑 Loaded PEM certificate.")
            except Exception:
                try:
                    pk = serialization.load_pem_public_key(data)
                    print("🔑 Loaded PEM public key.")
                except Exception:
                    pass
        if pk is None:
            # try DER cert or DER key
            try:
                cert = x509.load_der_x509_certificate(data)
                pk = cert.public_key()
                print("🔑 Loaded DER certificate.")
            except Exception:
                try:
                    pk = serialization.load_der_public_key(data)
                    print("🔑 Loaded DER public key.")
                except Exception:
                    pass
        if pk is None:
            print("⚠️  Could not load local certificate/public key:", args.cert)
        else:
            candidates.append(("local", pk))

    if not candidates:
        print("❌ No public keys available (GDHCN fetch failed and no usable --cert).")
        sys.exit(3)

    # Try verification against candidates
    last_err = None
    tried = 0
    for kid, pk in candidates:
        tried += 1
        try:
            verify_es256(pk, protected_bstr, payload_bstr, signature)
            print(f"✅ Signature VALID with key kid={kid}")
            return
        except Exception as e:
            last_err = e

    print("❌ Signature verification FAILED against all candidates.")
    if last_err:
        print("   Last error:", repr(last_err))
    print(f"   Tried {tried} keys (env={args.gdhcn_env}, domain={args.domain}, usage={args.usage}, participant={args.participant or 'ALL'})")

if __name__ == "__main__":
    main()
