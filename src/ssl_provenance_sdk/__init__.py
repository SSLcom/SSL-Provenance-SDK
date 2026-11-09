"""SSL.com Provenance SDK: sign assets with C2PA manifests using eSigner
credentials through SSL.com's CSC API.

The Python SDK counterpart of the SSL.com Provenance API (HTTP).
"""

from .ai_disclosure import TRAINED_ALGORITHMIC_MEDIA, AiDisclosure
from .client import ProvenanceClient, SignRequest
from .csc_api import CredentialInfo, CscApi
from .environments import (
    PRODUCTION,
    PRODUCTION_OAUTH_TOKEN_URL,
    SANDBOX,
    SANDBOX_OAUTH_TOKEN_URL,
    Environment,
)
from .errors import (
    AiDisclosureUnsupportedError,
    C2paSigningError,
    CawgUnsupportedError,
    CscApiError,
    InvalidAiDisclosureError,
    InvalidCawgRoleError,
    InvalidCustomAssertionError,
    MissingCredentialIdError,
    MissingTsaTokenError,
    NoCredentialError,
    OAuthError,
    ProvenanceError,
    TrustListDownloadError,
    UnsupportedMediaTypeError,
)
from .media import SUPPORTED_MIME_TYPES
from .oauth import (
    AccessToken,
    get_access_token,
    refresh_access_token,
    request_access_token,
)
from .trust import C2PA_TRUST_LIST_URL, C2PA_TSA_TRUST_LIST_URL, download_trust_anchors

__version__ = "1.0.0"

__all__ = [
    "ProvenanceClient",
    "SignRequest",
    "AiDisclosure",
    "TRAINED_ALGORITHMIC_MEDIA",
    "CscApi",
    "CredentialInfo",
    "SUPPORTED_MIME_TYPES",
    "AccessToken",
    "get_access_token",
    "refresh_access_token",
    "request_access_token",
    "SANDBOX_OAUTH_TOKEN_URL",
    "PRODUCTION_OAUTH_TOKEN_URL",
    "Environment",
    "SANDBOX",
    "PRODUCTION",
    "download_trust_anchors",
    "C2PA_TRUST_LIST_URL",
    "C2PA_TSA_TRUST_LIST_URL",
    "ProvenanceError",
    "MissingCredentialIdError",
    "MissingTsaTokenError",
    "InvalidCawgRoleError",
    "InvalidCustomAssertionError",
    "InvalidAiDisclosureError",
    "AiDisclosureUnsupportedError",
    "UnsupportedMediaTypeError",
    "CawgUnsupportedError",
    "CscApiError",
    "NoCredentialError",
    "OAuthError",
    "C2paSigningError",
    "TrustListDownloadError",
]
