"""SSL.com environments: the endpoints a client and the OAuth helpers use.

``"production"`` (the default) signs with production credentials;
``"sandbox"`` is for testing. Credentials and access tokens are issued per
environment and don't work in the other one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union
from urllib.parse import urlsplit

#: SSL.com sandbox OAuth2 token endpoint (pairs with ``https://cs-try.ssl.com``).
SANDBOX_OAUTH_TOKEN_URL = "https://oauth-sandbox.ssl.com/oauth2/token"
#: SSL.com production OAuth2 token endpoint (pairs with ``https://cs.ssl.com``).
PRODUCTION_OAUTH_TOKEN_URL = "https://login.ssl.com/oauth2/token"
#: SSL.com C2PA timestamp authority, shared by both environments. It requires
#: a bearer token (:meth:`ProvenanceClient.set_tsa_token`).
SSL_TSA_URL = "https://ts-c2pa.ssl.com/ecc"


@dataclass(frozen=True)
class Environment:
    """A named set of endpoints. ``tsa_url`` may be ``None`` to disable
    timestamping."""

    name: str
    csc_endpoint: str
    oauth_token_url: str
    tsa_url: Optional[str]


SANDBOX = Environment(
    name="sandbox",
    csc_endpoint="https://cs-try.ssl.com",
    oauth_token_url=SANDBOX_OAUTH_TOKEN_URL,
    tsa_url=SSL_TSA_URL,
)

PRODUCTION = Environment(
    name="production",
    csc_endpoint="https://cs.ssl.com",
    oauth_token_url=PRODUCTION_OAUTH_TOKEN_URL,
    tsa_url=SSL_TSA_URL,
)

_BUILT_IN = {env.name: env for env in (SANDBOX, PRODUCTION)}


def tsa_requires_token(tsa_url: Optional[str]) -> bool:
    """True if ``tsa_url`` is an SSL.com timestamp authority, which only
    answers authenticated requests."""
    if not tsa_url:
        return False
    host = (urlsplit(tsa_url).hostname or "").lower()
    return host == "ssl.com" or host.endswith(".ssl.com")

EnvironmentLike = Union[str, Environment]


def resolve_environment(environment: EnvironmentLike) -> Environment:
    """Return the :class:`Environment` for a name (case-insensitive) or the
    environment itself. Raises :class:`ValueError` for an unknown name."""
    if isinstance(environment, Environment):
        return environment
    if isinstance(environment, str):
        env = _BUILT_IN.get(environment.strip().lower())
        if env is not None:
            return env
    raise ValueError(
        f"unknown environment {environment!r}; expected one of "
        f"{', '.join(repr(name) for name in _BUILT_IN)} or an Environment"
    )
