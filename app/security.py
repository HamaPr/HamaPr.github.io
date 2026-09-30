import hmac
from fastapi import Header, HTTPException, status
from .settings import get_settings

settings = get_settings()

def _extract(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    return authorization[7:].strip()

def require_write(authorization: str | None = Header(default=None)) -> None:
    token = _extract(authorization)
    if not hmac.compare_digest(token, settings.write_token):
        raise HTTPException(status_code=403, detail="Invalid write token")

def require_read(authorization: str | None = Header(default=None)) -> None:
    token = _extract(authorization)
    if not (hmac.compare_digest(token, settings.read_token) or hmac.compare_digest(token, settings.write_token)):
        raise HTTPException(status_code=403, detail="Invalid read token")
