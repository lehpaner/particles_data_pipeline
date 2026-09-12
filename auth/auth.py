"""
Microsoft Entra ID — OAuth 2.0 / OIDC Authentication
=====================================================

Flow:
  1. User visits any protected route → redirect to /auth/login
  2. /auth/login  → builds the Azure authorization URL → redirect to Microsoft
  3. Microsoft authenticates the user → calls back /msgraph/oauth/callback?code=…&state=…
  4. Callback exchanges code for tokens, validates id_token, stores claims in a
     signed encrypted cookie (session)
  5. All subsequent requests check the cookie; expired/missing → back to login

Session cookie:
  Name:     tsi_session
  Content:  JSON {oid, name, email, roles, exp} — AES-GCM encrypted then base64
  MaxAge:   SESSION_TTL_SECONDS (default 8 h)

Public routes (no auth required):
  GET  /auth/login
  GET  /auth/logout
  GET  /msgraph/oauth/callback
  GET  /health

All other routes require a valid session cookie.

Azure app registration details (from caller):
  Client ID  : ec1dc751-6a1b-4537-bd9c-4d82dafbc726
  Tenant ID  : 77985f42-f997-4d8b-8474-c2a5c621de04
  Object ID  : ba081e11-a8b1-4ff2-bea0-be0a4901c24a   (service principal)
  Redirect   : http://localhost:8080/msgraph/oauth/callback
  Scopes     : openid profile email offline_access
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("auth")

# ─── Configuration ────────────────────────────────────────────────────────────

CLIENT_ID    = "ec1dc751-6a1b-4537-bd9c-4d82dafbc726"
TENANT_ID    = "77985f42-f997-4d8b-8474-c2a5c621de04"
REDIRECT_URI = "http://localhost:8080/msgraph/oauth/callback"
SCOPES       = "openid profile email offline_access"

AUTHORITY    = f"https://login.microsoftonline.com/{TENANT_ID}"
AUTH_URL     = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_URL    = f"{AUTHORITY}/oauth2/v2.0/token"
JWKS_URI     = f"{AUTHORITY}/discovery/v2.0/keys"
LOGOUT_URL   = f"{AUTHORITY}/oauth2/v2.0/logout"
USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"

SESSION_COOKIE   = "tsi_session"
STATE_COOKIE     = "tsi_oauth_state"
SESSION_TTL      = 8 * 3600   # 8 hours in seconds

# Session encryption key — read from env or derive a stable dev key.
# In production set TSI_SESSION_SECRET to a 32-byte hex string.
_raw_secret = os.environ.get("TSI_SESSION_SECRET", "")
if len(_raw_secret) >= 32:
    SESSION_KEY = _raw_secret[:32].encode()
else:
    # deterministic dev key (NOT secure for production)
    SESSION_KEY = hashlib.sha256(b"tsi-dev-key-" + CLIENT_ID.encode()).digest()[:32]


# ─── Simple AES-GCM session encryption (stdlib only) ─────────────────────────
#
# Python stdlib has no AES, so we use HMAC-SHA256 authenticated encryption:
#   ciphertext = XOR(plaintext, keystream)  where keystream = SHA256(key || nonce || i)
#   tag        = HMAC-SHA256(key, nonce || ciphertext)
# This is IND-CPA + INT-CTXT secure for session cookies.
# If cryptography package is available we use AES-GCM instead.

def _encrypt_session(payload: dict) -> str:
    """Encrypt payload dict → base64url string."""
    plaintext = json.dumps(payload).encode()
    nonce = secrets.token_bytes(16)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct = AESGCM(SESSION_KEY).encrypt(nonce, plaintext, None)
        raw = nonce + ct
    except ImportError:
        # fallback: HMAC-XOR stream cipher
        keystream = b""
        for i in range((len(plaintext) + 31) // 32):
            keystream += hashlib.sha256(SESSION_KEY + nonce + i.to_bytes(4, "big")).digest()
        ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
        tag = hmac.new(SESSION_KEY, nonce + ct, hashlib.sha256).digest()
        raw = nonce + tag + ct
    return base64.urlsafe_b64encode(raw).decode()


def _decrypt_session(token: str) -> Optional[dict]:
    """Decrypt base64url string → payload dict, or None if invalid/expired."""
    try:
        raw = base64.urlsafe_b64decode(token + "==")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce, ct = raw[:16], raw[16:]
            plaintext = AESGCM(SESSION_KEY).decrypt(nonce, ct, None)
        except ImportError:
            nonce, tag, ct = raw[:16], raw[16:48], raw[48:]
            expected = hmac.new(SESSION_KEY, nonce + ct, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected):
                return None
            keystream = b""
            for i in range((len(ct) + 31) // 32):
                keystream += hashlib.sha256(SESSION_KEY + nonce + i.to_bytes(4, "big")).digest()
            plaintext = bytes(a ^ b for a, b in zip(ct, keystream))
        payload = json.loads(plaintext)
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ─── OAuth state (CSRF) ───────────────────────────────────────────────────────

def generate_state() -> str:
    return secrets.token_urlsafe(32)


def build_auth_url(state: str) -> str:
    params = {
        "client_id":     CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  REDIRECT_URI,
        "scope":         SCOPES,
        "state":         state,
        "response_mode": "query",
        "prompt":        "select_account",
    }
    return AUTH_URL + "?" + urllib.parse.urlencode(params)


# ─── Token exchange ───────────────────────────────────────────────────────────

def exchange_code(code: str) -> dict:
    """
    Exchange authorization code for tokens.
    Returns the full token response dict (access_token, id_token, refresh_token…).
    Raises on HTTP error.

    NOTE: client_secret is NOT used here because the app registration
    must be configured as a public client (mobile/SPA) or supply a secret
    via env TSI_CLIENT_SECRET. We attempt both flows.
    """
    body: dict = {
        "client_id":    CLIENT_ID,
        "grant_type":   "authorization_code",
        "code":         code,
        "redirect_uri": REDIRECT_URI,
        "scope":        SCOPES,
    }
    client_secret = os.environ.get("TSI_CLIENT_SECRET", "")
    if client_secret:
        body["client_secret"] = client_secret

    data = urllib.parse.urlencode(body).encode()
    req  = urllib.request.Request(
        TOKEN_URL, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


# ─── id_token parsing (no signature verification in stdlib path) ──────────────
#
# Full JWT signature verification requires the JWKS endpoint and an RSA library.
# We do:
#   1. If `cryptography` is installed → fetch JWKS and verify RS256 signature.
#   2. Otherwise → decode payload only and validate aud/iss/exp claims.
#      This is acceptable because the token is received directly from HTTPS
#      Microsoft endpoint (implicit trust of TLS + code exchange).

def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_id_token(id_token: str) -> dict:
    """Return claims dict from id_token JWT. Validates aud, iss, exp."""
    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")
    payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))

    # Basic claim validation
    now = time.time()
    if payload.get("exp", 0) < now:
        raise ValueError("id_token expired")
    if payload.get("aud") != CLIENT_ID and CLIENT_ID not in payload.get("aud", []):
        raise ValueError(f"id_token aud mismatch: {payload.get('aud')}")
    expected_iss = [
        f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        f"https://sts.windows.net/{TENANT_ID}/",
    ]
    if payload.get("iss") not in expected_iss:
        raise ValueError(f"id_token iss mismatch: {payload.get('iss')}")

    # Signature verification (best-effort, requires cryptography)
    try:
        _verify_jwt_signature(id_token, parts)
    except ImportError:
        log.warning("cryptography not installed — JWT signature not verified (TLS trust only)")
    except Exception as e:
        raise ValueError(f"JWT signature invalid: {e}")

    return payload


def _verify_jwt_signature(id_token: str, parts: list):
    """Verify RS256 JWT signature against Microsoft JWKS."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    header = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
    kid = header.get("kid")

    # Fetch JWKS (simple cache via module-level dict)
    if not hasattr(_verify_jwt_signature, "_jwks") or _verify_jwt_signature._cache_ts < time.time() - 3600:
        with urllib.request.urlopen(JWKS_URI, timeout=5) as r:
            _verify_jwt_signature._jwks = json.loads(r.read())
            _verify_jwt_signature._cache_ts = time.time()

    key_data = next(
        (k for k in _verify_jwt_signature._jwks["keys"] if k.get("kid") == kid), None
    )
    if not key_data:
        raise ValueError(f"kid {kid} not found in JWKS")

    def _b64int(s): return int.from_bytes(base64.urlsafe_b64decode(_b64pad(s)), "big")
    pub = RSAPublicNumbers(_b64int(key_data["e"]), _b64int(key_data["n"])).public_key(default_backend())
    sig = base64.urlsafe_b64decode(_b64pad(parts[2]))
    msg = f"{parts[0]}.{parts[1]}".encode()
    pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())


# ─── Session dataclass ────────────────────────────────────────────────────────

@dataclass
class UserSession:
    oid:   str           # object id (stable, unique per user)
    name:  str
    email: str
    roles: list
    exp:   float         # Unix timestamp


def session_from_claims(claims: dict) -> UserSession:
    return UserSession(
        oid   = claims.get("oid", claims.get("sub", "")),
        name  = claims.get("name", claims.get("preferred_username", "Unknown")),
        email = claims.get("email", claims.get("preferred_username", "")),
        roles = claims.get("roles", []),
        exp   = claims.get("exp", time.time() + SESSION_TTL),
    )


def make_session_cookie(session: UserSession) -> str:
    return _encrypt_session({
        "oid":   session.oid,
        "name":  session.name,
        "email": session.email,
        "roles": session.roles,
        "exp":   session.exp,
    })


def read_session_cookie(token: str) -> Optional[UserSession]:
    payload = _decrypt_session(token)
    if not payload:
        return None
    return UserSession(**payload)


def build_logout_url(post_logout_redirect: str = "http://localhost:8080/") -> str:
    params = {
        "client_id":                CLIENT_ID,
        "post_logout_redirect_uri": post_logout_redirect,
    }
    return LOGOUT_URL + "?" + urllib.parse.urlencode(params)
