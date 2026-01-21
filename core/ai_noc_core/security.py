import hmac, hashlib

def verify_hmac(secret: bytes, body: bytes, signature_hex: str) -> bool:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, (signature_hex or "").strip().lower())

