# verify_cose_from_qr_gdhcn.py
#
# What it does:
#   - Decodes a QR image (HC1: Base45 → zlib → COSE_Sign1)
#   - Extracts protected/payload/signature (exact CBOR bytes)
#   - (Optionally) fetches the WHO GDHCN DID trustlist and
#       *verifies the trustlist's JsonWebSignature2020 proof*
#     using detached JWS (b64:false) over URDNA2015-canonicalized JSON-LD
#   - Uses verified DSC public keys from that trustlist to verify the COSE signature (ES256)
#   - Falls back to a local certificate/public key if provided
#
# Install deps (Python 3.9+):
#   pip install opencv-python cryptography cbor2 requests jwcrypto pyld
#
# Usage examples:
#   python verify_cose_from_qr_gdhcn.py --img qr.jpg --gdhcn
#   python verify_cose_from_qr_gdhcn.py --img qr.png --gdhcn --gdhcn-env dev --participant XM
#   python verify_cose_from_qr_gdhcn.py --img qr.jpg --gdhcn --no-verify-did-proof
#   python verify_cose_from_qr_gdhcn.py --img qr.jpg --cert cert.pem

import argparse
import base64
import json
import sys
import zlib
import os
from pathlib import Path
from typing import Dict, Optional, Tuple, List

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from jwcrypto import jwk, jws
from pyld import jsonld

# -------- JSON-LD context loader (local-first, safe) --------

def _flatten_context_urls(ctx) -> List[str]:
    urls: List[str] = []
    if isinstance(ctx, str):
        urls.append(ctx)
    elif isinstance(ctx, list):
        for item in ctx:
            if isinstance(item, str):
                urls.append(item)
            elif isinstance(item, dict):
                pass  # inline object context
    elif isinstance(ctx, dict):
        pass
    return urls

def preflight_contexts(doc: dict, loader_func) -> None:
    urls = _flatten_context_urls(doc.get("@context"))
    missing = []
    for u in urls:
        try:
            loader_func(u)
            print(f"   ✅ context OK: {u}")
        except Exception as e:
            missing.append((u, str(e)))
            print(f"   ❌ context MISSING: {u}  -> {e}")
    if missing:
        print("\n📌 To fix missing contexts:")
        print("   - Save the files below into --context-dir with the listed filenames:")
        for u, _ in missing:
            fname = REQUIRED_CONTEXT_URLS.get(u, "<choose-a-name>.jsonld")
            print(f"     {u}  ->  {fname}")
        print("   - Or re-run with --allow-remote-contexts to fetch them automatically.\n")

# URLs you’ll encounter in DID trustlists
REQUIRED_CONTEXT_URLS = {
    "https://www.w3.org/ns/did/v1":                  "did-v1.jsonld",
    "https://w3id.org/security/suites/jws-2020/v1":  "jws-2020-v1.jsonld",
    "https://w3id.org/security/v2":                  "security-v2.jsonld",
    # WHO additional context used in GDHCN trustlists (not always merged at main)
    "https://worldhealthorganization.github.io/smart-trust/tng-additional-context/v1": "tng-additional-context-v1.jsonld",
}

# Remote overrides (used only if --allow-remote-contexts)
# NOTE: JWS 2020 file name is *lds-jws2020-v1.json* (not v1.jsonld).
REMOTE_CONTEXT_OVERRIDES: Dict[str, List[str]] = {
    "https://w3id.org/security/suites/jws-2020/v1": [
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
    ],
    # WHO extra context: try the branch file (no extension), then the eventual main/raw, then GH Pages.
    "https://worldhealthorganization.github.io/smart-trust/tng-additional-context/v1": [
        "https://raw.githubusercontent.com/WorldHealthOrganization/smart-trust/tng-additional-context-jsonld/input/images/tng-additional-context/v1",
        "https://raw.githubusercontent.com/WorldHealthOrganization/smart-trust/main/tng-additional-context/v1.jsonld",
        "https://worldhealthorganization.github.io/smart-trust/tng-additional-context/v1",
    ],
    # If you want to pin security-v2 as well, you can add a candidate here.
}

def fetch_remote_json(url: str) -> dict:
    """
    Fetch a JSON/JSON-LD document with friendly fallbacks:
    - Accept JSON-LD to coax servers into returning JSON (not HTML).
    - Try multiple candidate URLs if configured.
    - If WHO tng-additional-context still won’t return JSON, use a safe no-op context.
    """
    headers = {"Accept": "application/ld+json, application/json;q=0.9, */*;q=0.1"}
    candidates = REMOTE_CONTEXT_OVERRIDES.get(url, [url])
    last_err = None
    for eff_url in candidates:
        try:
            resp = requests.get(eff_url, timeout=25, headers=headers, allow_redirects=True)
            resp.raise_for_status()
            # Some endpoints send text/plain; try to parse anyway
            try:
                return resp.json()
            except Exception:
                return json.loads(resp.text)
        except Exception as e:
            last_err = e
            continue

    if "tng-additional-context" in url:
        print("   ⚠️  WHO extra context not reachable as JSON; using a no-op context.")
        return {"@context": {}}

    raise ValueError(f"Remote context fetch failed for {url}: {last_err}")

def make_local_context_loader(context_dir: str, allow_remote: bool = False):
    """
    Returns a function compatible with pyld.jsonld.set_document_loader.
    It serves known @context URLs from local files; optionally allows remote fetch.
    """
    pathmap: Dict[str, str] = {url: os.path.join(context_dir, fname)
                               for url, fname in REQUIRED_CONTEXT_URLS.items()}

    def loader(url: str):
        if url in pathmap and os.path.exists(pathmap[url]):
            with open(pathmap[url], "r", encoding="utf-8") as f:
                doc = json.load(f)
            return {"contextUrl": None, "documentUrl": url, "document": doc}

        if allow_remote:
            doc = fetch_remote_json(url)
            return {"contextUrl": None, "documentUrl": url, "document": doc}

        raise FileNotFoundError(
            f"Missing JSON-LD context for {url}. "
            f"Put it under {context_dir} or run with --allow-remote-contexts."
        )
    return loader

# --------------------------- QR decode (OpenCV) ---------------------------

def decode_qr_image(image_path: str) -> str:
    import cv2
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Could not read image: {image_path}")
    det = cv2.QRCodeDetector()
    # Try multi first
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
    # Fallback single
    data, points, _ = det.detectAndDecode(img)
    if not data:
        raise ValueError("No QR code detected or decoding failed.")
    return data

# ------------------------------ Base45 -----------------------------------

_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_IDX = {c: i for i, c in enumerate(_B45)}

def base45_decode(s: str) -> bytes:
    # Keep only valid Base45 characters (including space)
    s = "".join(ch for ch in s if ch in _B45_IDX)
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

# ------------------------ COSE parse & verify -----------------------------

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
    # Build Sig_structure
    sig_structure = ["Signature1", protected_bstr, b"", payload_bstr]
    to_be_signed = cbor2.dumps(sig_structure, canonical=True)
    # Convert raw r||s to DER for cryptography
    if len(signature) % 2 != 0:
        raise ValueError(f"Unexpected ECDSA signature length: {len(signature)}")
    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    der_sig = encode_dss_signature(r, s)
    # Verify
    public_key.verify(der_sig, to_be_signed, ec.ECDSA(hashes.SHA256()))

# ----------------------------- Utilities ---------------------------------

def hexdump(b: bytes, n=16) -> str:
    return " ".join(f"{x:02x}" for x in b[:n])

def b64u_to_bytes(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def pubkey_from_jwk_ec_p256(jwk_dict: dict):
    # Prefer x5c if present (ensures exact leaf cert key)
    x5c = jwk_dict.get("x5c")
    if x5c:
        try:
            leaf_der = base64.b64decode(x5c[0])
            cert = x509.load_der_x509_certificate(leaf_der)
            return cert.public_key()
        except Exception:
            pass
    # Fall back to x/y coordinates
    if jwk_dict.get("kty") != "EC" or jwk_dict.get("crv") not in ("P-256", "secp256r1"):
        return None
    x = int.from_bytes(b64u_to_bytes(jwk_dict["x"]), "big")
    y = int.from_bytes(b64u_to_bytes(jwk_dict["y"]), "big")
    curve = ec.SECP256R1()
    return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()

# -------------------- DID:web & trustlist authenticity --------------------

ENV_BASE = {
    "prod": "https://tng-cdn.who.int",
    "uat":  "https://tng-cdn-uat.who.int",
    "dev":  "https://tng-cdn-dev.who.int",
}

def did_web_to_url(did: str) -> str:
    """
    did:web:tng-cdn-dev.who.int:v2:trustlist:DCC:XM:DSC
      -> https://tng-cdn-dev.who.int/v2/trustlist/DCC/XM/DSC/did.json
    did:web:example.com
      -> https://example.com/.well-known/did.json
    """
    assert did.startswith("did:web:"), f"Unsupported DID method: {did}"
    parts = did[len("did:web:"):].split(":")
    host = parts[0]
    path = "/".join(parts[1:])
    if path:
        return f"https://{host}/{path}/did.json"
    else:
        return f"https://{host}/.well-known/did.json"

def build_trustlist_did(env: str, domain: str, participant: str, usage: str) -> str:
    base_host = ENV_BASE[env].replace("https://", "")
    # participant may be '-' to mean "all"
    return f"did:web:{base_host}:v2:trustlist:{domain}:{participant}:{usage}"

def fetch_json(url: str) -> dict:
    r = requests.get(url, timeout=25)
    r.raise_for_status()
    return r.json()

def dereference_verification_method(did_or_didurl: str) -> Tuple[dict, dict]:
    """
    Return (signer_did_document, verification_method_obj).
    If a fragment is present (#...), locate that method; else pick a referenced one.
    """
    if "#" in did_or_didurl:
        did, _ = did_or_didurl.split("#", 1)
        vm_id = did_or_didurl
    else:
        did = did_or_didurl
        vm_id = None

    did_doc = fetch_json(did_web_to_url(did))
    vms = did_doc.get("verificationMethod", [])

    if vm_id:
        for vm in vms:
            if vm.get("id") == vm_id:
                return did_doc, vm
        raise ValueError(f"verificationMethod not found: {vm_id}")

    # Otherwise, try assertionMethod/authentication references
    vm_map = {vm.get("id"): vm for vm in vms}
    for ref_group in ("assertionMethod", "authentication"):
        for ref in did_doc.get(ref_group, []) or []:
            if isinstance(ref, str) and ref in vm_map:
                return did_doc, vm_map[ref]
            if isinstance(ref, dict) and ref.get("id") in vm_map:
                return did_doc, vm_map[ref["id"]]
    if vms:
        return did_doc, vms[0]
    raise ValueError("No verificationMethod available in signer DID")

# --- replace this function ---
def canonicalize_without_proof(did_doc: dict, loader) -> bytes:
    """
    Remove 'proof' and normalize with URDNA2015 to N-Quads (JSON-LD 1.1).
    """
    doc_wo_proof = {k: v for k, v in did_doc.items() if k != "proof"}
    nquads = jsonld.normalize(
        doc_wo_proof,
        {
            "algorithm": "URDNA2015",
            "format": "application/n-quads",
            "processingMode": "json-ld-1.1",
            "documentLoader": loader,
        },
    )
    return nquads.encode("utf-8")


def verify_jsonwebsignature2020(did_doc: dict, loader) -> Tuple[str, str]:
    """
    Verify top-level proof (JsonWebSignature2020) on a DID doc.
    Returns (verificationMethod_id, alg).
    Raises on failure.
    """
    proof = did_doc.get("proof")
    if not proof or proof.get("type") != "JsonWebSignature2020":
        raise ValueError("DID doc has no JsonWebSignature2020 proof")

    jws_compact = proof.get("jws")
    if not isinstance(jws_compact, str) or jws_compact.count(".") != 2:
        raise ValueError("Invalid JWS compact in proof")

    vm_ref = proof.get("verificationMethod")
    if not vm_ref:
        raise ValueError("Missing verificationMethod in proof")

    _, vm = dereference_verification_method(vm_ref)
    vm_jwk = vm.get("publicKeyJwk")
    if not vm_jwk:
        raise ValueError("verificationMethod has no publicKeyJwk")

    payload = canonicalize_without_proof(did_doc, loader)

    jwk_obj = jwk.JWK(**vm_jwk)
    sig = jws.JWS()
    sig.deserialize(jws_compact)
    sig.verify(jwk_obj, detached_payload=payload)  # raises on failure

    # Parse protected header for logging (alg, b64:false expected)
    header_b64 = jws_compact.split(".", 2)[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    return vm.get("id", vm_ref), header.get("alg", "unknown")

def fetch_trustlist_doc(env: str, domain: str, participant: str, usage: str) -> Tuple[str, dict]:
    did = build_trustlist_did(env, domain, participant, usage)
    url = did_web_to_url(did)
    return url, fetch_json(url)

def extract_pubkeys_from_trustlist_doc(doc: dict) -> List[Tuple[Optional[str], object]]:
    """
    From a (verified) trustlist DID document, return [(kid, public_key)] for EC P-256 keys.
    Prefers x5c; falls back to JWK x/y.
    """
    keys: List[Tuple[Optional[str], object]] = []
    for vm in doc.get("verificationMethod", []):
        jwk_obj = vm.get("publicKeyJwk")
        if not jwk_obj:
            continue
        pk = pubkey_from_jwk_ec_p256(jwk_obj)
        if pk is not None:
            keys.append((jwk_obj.get("kid"), pk))
    return keys

# --------------------------------- Main -----------------------------------

def main():
    ap = argparse.ArgumentParser(description="Verify HC1/COSE ES256 from QR image using GDHCN trustlist with DID proof verification.")
    ap.add_argument("--img", required=True, help="Path to QR image (jpg/png/webp).")
    ap.add_argument("--gdhcn", action="store_true", help="Fetch keys from GDHCN trustlist (recommended).")
    ap.add_argument("--gdhcn-env", choices=["prod", "uat", "dev"], default="prod", help="GDHCN environment (default: prod).")
    ap.add_argument("--participant", default="-", help="Participant code (e.g., XM, BEL). '-' means 'all'. Default: '-'.")
    ap.add_argument("--domain", default="DCC", help="Trust domain (default: DCC).")
    ap.add_argument("--usage", default="DSC", help="Key usage (default: DSC = Document Signing Cert).")
    ap.add_argument("--no-verify-did-proof", action="store_true", help="Skip DID JsonWebSignature2020 proof verification (NOT recommended).")
    ap.add_argument("--allow-unverified-trustlist", action="store_true", help="Proceed with keys even if DID proof verification fails (prints a warning).")
    ap.add_argument("--cert", default=None, help="Fallback: PEM/DER/Base64-DER certificate/public key.")
    ap.add_argument("--context-dir", default="contexts", help="Folder with local JSON-LD @context files (default: ./contexts)")
    ap.add_argument("--allow-remote-contexts", action="store_true", help="Allow fetching @context URLs from the web if missing locally (default: off)")
    args = ap.parse_args()

    # 1) Read QR → content string
    qr_text = decode_qr_image(args.img).strip()
    print(f"📷 QR content: {qr_text[:60]}{'...' if len(qr_text) > 60 else ''}")

    # 2) Strip 'HC1:' if present → Base45
    body = qr_text[4:] if qr_text.upper().startswith("HC1:") else qr_text
    b45 = base45_decode(body)
    print(f"🔧 Base45 decoded length: {len(b45)}")

    # 3) zlib/deflate → COSE bytes
    try:
        cose_bytes = zlib.decompress(b45)
    except zlib.error:
        cose_bytes = zlib.decompress(b45, wbits=-15)
    print(f"🔧 Decompressed length: {len(cose_bytes)}  Head: {hexdump(cose_bytes)}")

    # 4) Parse COSE_Sign1
    protected_bstr, payload_bstr, signature = load_cose_from_bytes(cose_bytes)
    prot = cbor2.loads(protected_bstr)
    alg = prot.get(1)
    kid_hdr = prot.get(4)
    kid_hdr_b64 = base64.b64encode(kid_hdr).decode() if isinstance(kid_hdr, (bytes, bytearray)) else None
    print(f"🧭 Protected headers: alg={alg}  kid_b64={kid_hdr_b64}")

    # Save artifacts
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

    # 5) Build list of candidate public keys
    candidates: List[Tuple[Optional[str], object]] = []

    # 5a) GDHCN trustlist (with DID proof verification by default)
    if args.gdhcn:
        try:
            url, trust_doc = fetch_trustlist_doc(args.gdhcn_env, args.domain, args.participant, args.usage)
            print(f"🌐 Fetched trustlist DID: {url}")
            print("📚 DID @context:", trust_doc.get("@context"))

            # Install local-first JSON-LD loader BEFORE proof verification
            loader = make_local_context_loader(args.context_dir, allow_remote=args.allow_remote_contexts)
            jsonld.set_document_loader(loader)

            # Preflight contexts so errors are clear and actionable
            print("🔍 Preflighting JSON-LD contexts...")
            preflight_contexts(trust_doc, loader)

            if args.no_verify_did_proof:
                print("⚠️ Skipping DID proof verification (NOT recommended).")
            else:
                try:
                    vm_id, alg_proof = verify_jsonwebsignature2020(trust_doc, loader)
                    print(f"🔏 DID proof verified ✓  (vm: {vm_id}, alg: {alg_proof})")
                except Exception as e:
                    # Write artifacts to help diagnose JSON-LD issues
                    Path("trustlist.did.json").write_text(json.dumps(trust_doc, indent=2), encoding="utf-8")
                    tl_wo = {k: v for k, v in trust_doc.items() if k != "proof"}
                    Path("trustlist.no-proof.json").write_text(json.dumps(tl_wo, indent=2), encoding="utf-8")
                    print(f"⚠️  GDHCN trustlist proof failed: {type(e).__name__}({e})")
                    print("   Saved trustlist.did.json and trustlist.no-proof.json for inspection.")
                    if args.allow_unverified_trustlist:
                        print("   Proceeding due to --allow-unverified-trustlist.")
                    else:
                        raise


            gkeys = extract_pubkeys_from_trustlist_doc(trust_doc)
            print(f"🔑 Extracted {len(gkeys)} public key(s) from trustlist.")
            # If kid present in COSE, try that key first
            if kid_hdr_b64:
                prioritized = [(k, pk) for (k, pk) in gkeys if k == kid_hdr_b64] + [(k, pk) for (k, pk) in gkeys if k != kid_hdr_b64]
                candidates.extend(prioritized)
            else:
                candidates.extend(gkeys)
        except Exception as e:
            print("⚠️  GDHCN trustlist fetch/verify failed:", repr(e))

    # 5b) Fallback local certificate/public key
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
        print("❌ No public keys available (trustlist failure and no usable --cert).")
        sys.exit(3)

    # 6) Verify COSE against candidates
    last_err = None
    tried = 0
    for kid, pk in candidates:
        tried += 1
        try:
            verify_es256(pk, protected_bstr, payload_bstr, signature)
            print(f"✅ Signature VALID with key kid={kid}")
            if args.gdhcn and not args.no_verify_did_proof:
                print("   (Trustlist DID proof was verified ✓)" if not args.allow_unverified_trustlist else "   (Trustlist proof was NOT verified)")
            return
        except Exception as e:
            last_err = e

    print("❌ Signature verification FAILED against all candidates.")
    if last_err:
        print("   Last error:", repr(last_err))
    print(f"   Tried {tried} keys (env={args.gdhcn_env}, domain={args.domain}, usage={args.usage}, participant={args.participant})")

if __name__ == "__main__":
    main()
