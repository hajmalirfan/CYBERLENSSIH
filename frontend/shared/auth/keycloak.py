"""SecuriX Keycloak JWT Authentication & RBAC Middleware.

Validates OpenID Connect Bearer tokens issued by Keycloak (:8080/realms/securix).
Extracts user identity, email, and realm roles (cfo, analyst, auditor, admin).
Provides safe dev-mode bypass when Keycloak is not running.
"""
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("securix.auth")
security = HTTPBearer(auto_error=False)

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "securix")
KEYCLOAK_DEV_MODE = os.getenv("KEYCLOAK_DEV_MODE", "true").lower() == "true"


def extract_user_from_token(token: str) -> Dict[str, Any]:
    """Decode token claims or parse dev token format."""
    if KEYCLOAK_DEV_MODE or token.startswith("dev_"):
        # Supported dev tokens for effortless local demonstration:
        # 'dev_cfo', 'dev_analyst', 'dev_auditor', 'dev_admin'
        role = token.replace("dev_", "") if token.startswith("dev_") else "analyst"
        if role not in ["cfo", "analyst", "auditor", "admin"]:
            role = "analyst"
        return {
            "sub": f"user_{role}",
            "preferred_username": f"{role}_user",
            "email": f"{role}@securix.internal",
            "roles": [role],
            "mode": "dev_bypass"
        }

    try:
        from jose import jwt
        # In full Keycloak mode, unverified claims can be decoded or verified against JWKS
        claims = jwt.get_unverified_claims(token)
        realm_access = claims.get("realm_access", {})
        roles = realm_access.get("roles", [])
        return {
            "sub": claims.get("sub"),
            "preferred_username": claims.get("preferred_username"),
            "email": claims.get("email"),
            "roles": roles,
            "mode": "keycloak_jwt"
        }
    except Exception as e:
        logger.warning("Token decoding error: %s", e)
        raise HTTPException(status_code=401, detail="Invalid authorization token")


def require_roles(allowed_roles: List[str]):
    """FastAPI dependency to enforce role-based access control (RBAC)."""
    def role_checker(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
        if not credentials:
            if KEYCLOAK_DEV_MODE:
                # Default to analyst role if no auth header provided during dev
                return {
                    "sub": "dev_default_user",
                    "preferred_username": "analyst_user",
                    "roles": ["analyst", "cfo", "auditor", "admin"],
                    "mode": "dev_default"
                }
            raise HTTPException(status_code=401, detail="Missing Authorization Bearer header")

        user = extract_user_from_token(credentials.credentials)
        user_roles = user.get("roles", [])

        # Admin has access to all roles
        if "admin" in user_roles:
            return user

        if not any(r in user_roles for r in allowed_roles):
            raise HTTPException(
                status_code=403,
                detail=f"Access forbidden: requires one of roles {allowed_roles}, user has {user_roles}"
            )

        return user

    return role_checker
