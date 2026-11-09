"""Getting eSigner access tokens from SSL.com's OAuth2 token endpoint.

The CSC API needs an OAuth access token (:meth:`SignRequest.set_access_token`).
These functions request one and return it as an :class:`AccessToken`::

    token = get_access_token(username, password, client_id, client_secret)
    request.set_access_token(token)            # or token.access_token

    # before it expires, renew it without the password:
    if token.expires_within(60):
        token = refresh_access_token(token.refresh_token, client_id, client_secret)

Each function posts to ``token_url`` when given, otherwise to the token
endpoint of ``environment`` (``"production"`` by default).

:func:`request_access_token` sends any token request body as-is, for grant
types or extra fields the helpers don't cover. Credentials are only sent to
``token_url``; they are never logged or included in error messages.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

import requests

from .environments import (  # noqa: F401  (re-exported)
    PRODUCTION_OAUTH_TOKEN_URL,
    SANDBOX_OAUTH_TOKEN_URL,
    EnvironmentLike,
    resolve_environment,
)
from .errors import OAuthError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AccessToken:
    """An OAuth2 token response."""

    access_token: str = field(repr=False)
    token_type: str = "Bearer"
    #: Lifetime in seconds, counted from :attr:`created_at`.
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = field(default=None, repr=False)
    #: Unix time the token was issued (the server's ``created_at``, or the
    #: local time of the response when the server omits it).
    created_at: float = field(default_factory=time.time)
    #: The full JSON response, including any fields not listed above.
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_response(cls, data: Mapping[str, Any]) -> "AccessToken":
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            raise OAuthError("response has no access_token")
        expires_in = data.get("expires_in")
        created_at = data.get("created_at")
        return cls(
            access_token=token,
            token_type=str(data.get("token_type") or "Bearer"),
            expires_in=int(expires_in) if expires_in is not None else None,
            refresh_token=data.get("refresh_token") or None,
            created_at=float(created_at) if created_at is not None else time.time(),
            raw=dict(data),
        )

    @property
    def expires_at(self) -> Optional[float]:
        """Unix time the token expires, or ``None`` if the server didn't say."""
        if self.expires_in is None:
            return None
        return self.created_at + self.expires_in

    def expires_within(self, seconds: float = 0) -> bool:
        """True if the token is expired or expires within ``seconds``."""
        expires_at = self.expires_at
        return expires_at is not None and time.time() + seconds >= expires_at

    @property
    def authorization(self) -> str:
        """``Authorization`` header value, e.g. ``"Bearer eyJ..."``."""
        return f"{self.token_type} {self.access_token}"

    def __str__(self) -> str:
        return self.access_token


def request_access_token(
    token_request: Mapping[str, Any],
    token_url: Optional[str] = None,
    *,
    environment: EnvironmentLike = "production",
    session: Optional[requests.Session] = None,
    timeout: Optional[float] = 30,
) -> AccessToken:
    """POST ``token_request`` as JSON to ``token_url`` (default: the token
    endpoint of ``environment``) and return the token.

    ``token_request`` is the token request body, for example::

        {"grant_type": "password", "username": "...", "password": "...",
         "client_id": "..."}

    Raises :class:`OAuthError` if the request fails or the server rejects it.
    """
    token_url = token_url or resolve_environment(environment).oauth_token_url
    session = session or requests.Session()
    grant_type = token_request.get("grant_type", "?")
    try:
        resp = session.post(
            token_url,
            json=dict(token_request),
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise OAuthError(f"token request to {token_url} failed: {e}") from e

    try:
        data = resp.json()
    except ValueError:
        data = None

    if not resp.ok:
        reason = f"HTTP {resp.status_code}"
        if isinstance(data, dict):
            detail = data.get("error_description") or data.get("error")
            if detail:
                reason += f": {detail}"
        raise OAuthError(f"{grant_type} grant rejected by {token_url}: {reason}")
    if not isinstance(data, dict):
        raise OAuthError(f"{token_url} did not return a JSON object")

    token = AccessToken.from_response(data)
    logger.info("obtained access token (%s grant, expires in %ss)", grant_type, token.expires_in)
    return token


def get_access_token(
    username: str,
    password: str,
    client_id: str,
    client_secret: str,
    token_url: Optional[str] = None,
    *,
    environment: EnvironmentLike = "production",
    session: Optional[requests.Session] = None,
    timeout: Optional[float] = 30,
) -> AccessToken:
    """Get an access token with the OAuth2 password grant."""
    body = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    return request_access_token(
        body, token_url, environment=environment, session=session, timeout=timeout
    )


def refresh_access_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    token_url: Optional[str] = None,
    *,
    environment: EnvironmentLike = "production",
    session: Optional[requests.Session] = None,
    timeout: Optional[float] = 30,
) -> AccessToken:
    """Get a new access token with the OAuth2 refresh-token grant."""
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    return request_access_token(
        body, token_url, environment=environment, session=session, timeout=timeout
    )
