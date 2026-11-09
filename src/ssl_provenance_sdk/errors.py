"""Exception hierarchy for the SDK.

Each exception mirrors one error of the SSL.com Provenance API and carries
the HTTP status code the API answers with (``status_code``), so callers migrating from the HTTP API can keep their
error handling keyed on the same values.
"""

from __future__ import annotations


class ProvenanceError(Exception):
    """Base class for every error raised by the SDK."""

    #: HTTP status the SSL.com Provenance API returns for this error.
    status_code: int = 500

    def to_dict(self) -> dict:
        """The JSON error body the HTTP service would have returned."""
        return {"error": str(self)}


class MissingCredentialIdError(ProvenanceError):
    """``C2PA-Certificate-Id`` was not supplied (HTTP 400)."""

    status_code = 400

    def __init__(self) -> None:
        super().__init__("credential ID not present in request")


class MissingTsaTokenError(ProvenanceError):
    """The SSL.com timestamp authority is configured without the TSA token it
    requires (HTTP 400)."""

    status_code = 400

    def __init__(self, tsa_url: str) -> None:
        super().__init__(
            f"the SSL.com timestamp authority ({tsa_url}) requires a TSA token: "
            "call set_tsa_token() on the client or the request, or pass "
            "tsa_token= to ProvenanceClient"
        )


class InvalidCawgRoleError(ProvenanceError):
    """CAWG roles were supplied without a CAWG credential (HTTP 400)."""

    status_code = 400

    def __init__(self, roles: str) -> None:
        super().__init__(f"CAWG-Role requires CAWG-Certificate-Id: {roles}")


class InvalidCustomAssertionError(ProvenanceError):
    """A custom assertion is malformed (HTTP 400)."""

    status_code = 400

    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid C2PA-Custom-Assertion header: {reason}")


class InvalidAiDisclosureError(ProvenanceError):
    """An AI disclosure is malformed (HTTP 400)."""

    status_code = 400

    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid AI disclosure: {reason}")


class UnsupportedMediaTypeError(ProvenanceError):
    """The content type is not one c2pa can embed into (HTTP 415)."""

    status_code = 415

    def __init__(self, mime: str) -> None:
        super().__init__(f"Unsupported media type: {mime}")


class CawgUnsupportedError(ProvenanceError):
    """A CAWG identity assertion was requested where it can't be embedded (HTTP 422)."""

    status_code = 422

    def __init__(self, reason: str) -> None:
        super().__init__(f"CAWG identity assertion not supported: {reason}")


class AiDisclosureUnsupportedError(ProvenanceError):
    """An AI disclosure was requested for an asset that already carries
    Content Credentials (HTTP 422)."""

    status_code = 422

    def __init__(self, reason: str) -> None:
        super().__init__(f"AI disclosure not supported: {reason}")


class CscApiError(ProvenanceError):
    """The CSC API returned an error or an unexpected response (HTTP 500).

    ``prefix`` distinguishes the failure the way ``CscApiError``'s variants do
    in the Rust service: ``"CSC API error"`` (the API answered with an error),
    ``"HTTP error"`` (transport), ``"JSON error"`` and ``"Base64 decode error"``.
    """

    def __init__(self, reason: str, prefix: str = "CSC API error") -> None:
        super().__init__(f"{prefix}: {reason}")


class NoCredentialError(ProvenanceError):
    """Credential info (certificate chain / algorithm) could not be fetched (HTTP 500)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"No credential info: {reason}")


class C2paSigningError(ProvenanceError):
    """c2pa rejected the manifest or failed while signing (HTTP 500)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"C2PA error: {reason}")


class TrustListDownloadError(ProvenanceError):
    """A trust list could not be downloaded or is not a PEM bundle (HTTP 502)."""

    status_code = 502

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"failed to download trust list from {url}: {reason}")


class OAuthError(ProvenanceError):
    """An access token could not be obtained from the OAuth2 endpoint (HTTP 401)."""

    status_code = 401

    def __init__(self, reason: str) -> None:
        super().__init__(f"OAuth error: {reason}")
