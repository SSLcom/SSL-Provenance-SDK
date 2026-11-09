"""Setter-style SDK for embedding C2PA manifests signed through the CSC API.

:class:`ProvenanceClient` holds configuration shared by many signing
operations (environment endpoints, TSA, trust anchors); :class:`SignRequest`
holds the inputs for one signing operation.

=========================  ===========================================
Input                      SDK setter
=========================  ===========================================
``Authorization``          :meth:`SignRequest.set_access_token`
``C2PA-Certificate-Id``    :meth:`SignRequest.set_c2pa_certificate_id`
``Content-Type``           :meth:`SignRequest.set_content_type`
``CAWG-Certificate-Id``    :meth:`SignRequest.set_cawg_certificate_id`
``CAWG-Role``              :meth:`SignRequest.add_cawg_role`
``C2PA-Custom-Assertion``  :meth:`SignRequest.add_custom_assertion` (+ variants)
``ai_disclosure``          :meth:`SignRequest.set_ai_disclosure`
request body               :meth:`SignRequest.set_asset` (bytes)
environment                :class:`ProvenanceClient` / :meth:`~ProvenanceClient.set_environment`
CSC endpoint               :meth:`ProvenanceClient.set_csc_endpoint`
TSA URL                    :meth:`ProvenanceClient.set_tsa_url`
TSA token                  :meth:`SignRequest.set_tsa_token` or :meth:`ProvenanceClient.set_tsa_token`
=========================  ===========================================

The asset goes in as ``bytes`` and the result comes back as ``bytes``: the
signed asset with the manifest embedded or, for ``application/pdf``, the
sidecar C2PA manifest (``application/c2pa``).
"""

from __future__ import annotations

import contextlib
import datetime
import io
import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union

import c2pa
import requests

from . import _native
from .ai_disclosure import AiDisclosure
from .assertions import (
    normalize_custom_assertions,
    parse_cawg_roles,
    parse_encoded_custom_assertions,
)
from .csc_api import CscApi
from .environments import (
    Environment,
    EnvironmentLike,
    resolve_environment,
    tsa_requires_token,
)
from .errors import (
    C2paSigningError,
    AiDisclosureUnsupportedError,
    CawgUnsupportedError,
    CscApiError,
    InvalidCawgRoleError,
    MissingCredentialIdError,
    MissingTsaTokenError,
    NoCredentialError,
    ProvenanceError,
    UnsupportedMediaTypeError,
)
from .manifest import (
    MANIFEST_JSON,
    MANIFEST_JSON_EDIT,
    ai_generated_manifest,
    build_c2pa_settings_json,
    manifest_definition,
    parent_ingredient_json,
)
from .media import (
    PDF_MIME_TYPE,
    c2pa_format,
    is_supported,
    normalize_content_type,
    wrap_jxl_codestream,
)
from .oauth import AccessToken
from .signer import CAWG_X509_SIG_TYPE, CscSigner
from .timestamp import TsaForwarder, bearer_headers

logger = logging.getLogger(__name__)


class ProvenanceClient:
    """Service-level configuration shared by many signing operations.

    ``environment`` (``"production"``, the default, or ``"sandbox"``, or an
    :class:`~ssl_provenance_sdk.environments.Environment`) sets the CSC API,
    TSA and OAuth token endpoints. ``tsa_token`` authenticates to the
    timestamp authority; the SSL.com TSA used by both environments requires
    it. Every value has a built-in default and is set only through the
    constructor and setters; nothing is read from environment variables.
    Setters return the client, so calls can be chained::

        client = ProvenanceClient("production", tsa_token=tsa_token)
    """

    def __init__(
        self,
        environment: EnvironmentLike = "production",
        trust_anchors: Optional[str] = None,
        tsa_token: Optional[str] = None,
    ) -> None:
        self.set_environment(environment)
        self._tsa_token: Optional[str] = tsa_token or None
        self._timeout: Optional[float] = 60
        self._session: Optional[requests.Session] = None
        self._trust_anchors: Optional[str] = None
        self.set_trust_anchors(trust_anchors)

    # -- configuration setters ------------------------------------------------

    def set_environment(self, environment: EnvironmentLike) -> "ProvenanceClient":
        """Switch to ``environment`` (a name, case-insensitive, or an
        :class:`~ssl_provenance_sdk.environments.Environment`), replacing the
        CSC, TSA and OAuth endpoints, including any you overrode. Raises
        :class:`ValueError` for an unknown name."""
        env = resolve_environment(environment)
        self._environment = env
        self._csc_endpoint = env.csc_endpoint.rstrip("/")
        self._tsa_url: Optional[str] = env.tsa_url or None
        self._oauth_token_url = env.oauth_token_url
        return self

    def set_csc_endpoint(self, endpoint: str) -> "ProvenanceClient":
        """CSC API base URL (default: the environment's)."""
        self._csc_endpoint = endpoint.rstrip("/")
        return self

    def set_tsa_url(self, url: Optional[str]) -> "ProvenanceClient":
        """Timestamp authority URL (default: the environment's,
        ``https://ts-c2pa.ssl.com/ecc``). ``None`` disables timestamping."""
        self._tsa_url = url or None
        return self

    def set_oauth_token_url(self, url: str) -> "ProvenanceClient":
        """OAuth2 token endpoint (default: the environment's). Pass
        :attr:`oauth_token_url` to
        :func:`~ssl_provenance_sdk.oauth.get_access_token` as ``token_url``."""
        self._oauth_token_url = url
        return self

    def set_tsa_token(self, token: Optional[str]) -> "ProvenanceClient":
        """Default TSA token for every request, sent to the TSA as a bearer
        token; :meth:`SignRequest.set_tsa_token` overrides it per request.
        Required, here or on the request, by the SSL.com TSA (``*.ssl.com``):
        signing without it raises :class:`MissingTsaTokenError`. Also accepted
        as ``ProvenanceClient(tsa_token=...)``."""
        self._tsa_token = token or None
        return self

    def set_trust_anchors(self, pem_bundle: Optional[str]) -> "ProvenanceClient":
        """In-memory PEM bundle of trust anchors (typically the C2PA trust list
        and C2PA TSA trust list, concatenated) used to validate certificate
        chains already present in incoming assets. Also accepted as
        ``ProvenanceClient(trust_anchors=...)``.

        Signing never downloads trust lists: get the bundle once with
        :func:`download_trust_anchors`, keep the string in memory and pass the
        same string to every client. ``None`` (the default) leaves certificate trust
        unconfigured."""
        self._trust_anchors = pem_bundle or None
        return self

    def set_timeout(self, seconds: Optional[float]) -> "ProvenanceClient":
        """Timeout for CSC API calls, in seconds (default 60)."""
        self._timeout = seconds
        return self

    def set_session(self, session: requests.Session) -> "ProvenanceClient":
        """``requests`` session used for CSC and TSA calls
        (proxies, retries, custom CA bundles...)."""
        self._session = session
        return self

    # -- read-only views --------------------------------------------------------

    @property
    def environment(self) -> Environment:
        """The environment last selected; endpoint overrides don't change it."""
        return self._environment

    @property
    def oauth_token_url(self) -> str:
        return self._oauth_token_url

    @property
    def csc_endpoint(self) -> str:
        return self._csc_endpoint

    @property
    def tsa_url(self) -> Optional[str]:
        return self._tsa_url

    @property
    def trust_anchors(self) -> Optional[str]:
        return self._trust_anchors

    def c2pa_settings_json(self) -> str:
        """c2pa settings (trust anchors, EKUs, created-assertion labels) applied
        to every signing operation."""
        return build_c2pa_settings_json(self._trust_anchors)

    # -- signing ---------------------------------------------------------------------

    def new_request(self) -> "SignRequest":
        """Start a :class:`SignRequest` bound to this client."""
        return SignRequest(self)

    def sign(self, request: "SignRequest") -> bytes:
        """Embed a C2PA manifest into the request's asset.

        Returns:
            The signed asset bytes, with the manifest embedded. For
            ``application/pdf`` the PDF is not modified; the sidecar C2PA
            manifest bytes (``application/c2pa``) are returned instead.

        Raises:
            ProvenanceError: a subclass naming the failure.
        """
        plan = request.validate()
        tsa_token = request.tsa_token or self._tsa_token
        if not tsa_token and tsa_requires_token(self._tsa_url):
            raise MissingTsaTokenError(self._tsa_url)
        credential_id = plan.credential_id
        content_type = plan.content_type
        cawg_credential_id = plan.cawg_credential_id
        cawg_roles = plan.cawg_roles
        custom_assertions = plan.custom_assertions
        ai_disclosure = plan.ai_disclosure
        asset = plan.asset

        if custom_assertions:
            logger.info(
                "adding %d custom assertion(s): %s",
                len(custom_assertions),
                ", ".join(a["label"] for a in custom_assertions),
            )

        session = self._session or requests.Session()
        api = CscApi(request.access_token or "", self._csc_endpoint, session, self._timeout)
        tsa_headers = bearer_headers(tsa_token)

        # Fetch certificate chain + signing algorithm.
        try:
            info = api.get_credential_info(credential_id)
        except CscApiError as e:
            raise NoCredentialError(str(e)) from e

        signer = CscSigner(
            api,
            credential_id,
            info.certs,
            info.signature_algorithm,
            self._tsa_url,
            tsa_headers,
            session,
        )

        # Build the identity-assertion signer for the requested CAWG
        # credential, reusing the claim signer when it names the same one.
        cawg_signer: Optional[CscSigner] = None
        if cawg_credential_id is not None:
            if cawg_credential_id != credential_id:
                try:
                    cawg_info = api.get_credential_info(cawg_credential_id)
                except CscApiError as e:
                    raise NoCredentialError(str(e)) from e
                cawg_signer = CscSigner(
                    api,
                    cawg_credential_id,
                    cawg_info.certs,
                    cawg_info.signature_algorithm,
                    self._tsa_url,
                    tsa_headers,
                    session,
                )
            else:
                cawg_signer = signer
            logger.info(
                "CAWG identity assertion enabled (credential: %s)",
                cawg_signer.credential_id,
            )

        settings_json = self.c2pa_settings_json()

        try:
            with contextlib.ExitStack() as stack:
                # c2pa's callback signer takes only a TSA URL; route the claim
                # timestamp through a loopback forwarder to add the bearer token.
                c2pa_tsa_url = self._tsa_url
                if self._tsa_url and tsa_headers:
                    forwarder = stack.enter_context(
                        TsaForwarder(self._tsa_url, tsa_headers, session)
                    )
                    c2pa_tsa_url = forwarder.url

                if content_type == PDF_MIME_TYPE:
                    return _sign_pdf_sidecar(
                        settings_json,
                        signer,
                        c2pa_tsa_url,
                        asset,
                        custom_assertions,
                        ai_disclosure,
                    )

                return _sign_embedded(
                    settings_json,
                    signer,
                    cawg_signer,
                    cawg_roles,
                    c2pa_tsa_url,
                    content_type,
                    asset,
                    custom_assertions,
                    ai_disclosure,
                )
        except c2pa.C2paError as e:
            cause = _signing_cause(signer, cawg_signer)
            logger.error("Signing failed: %s", cause or e)
            if isinstance(cause, ProvenanceError):
                raise cause from e
            raise C2paSigningError(str(cause or e)) from e


def _signing_cause(*signers: Optional[CscSigner]) -> Optional[BaseException]:
    """The exception raised inside a CSC callback, if any; c2pa reports only
    that the callback failed."""
    for s in signers:
        if s is not None and s.last_error is not None:
            return s.last_error
    return None


def _context(settings_json: str) -> c2pa.Context:
    return c2pa.Context(c2pa.Settings.from_json(settings_json))


def _sign_pdf_sidecar(
    settings_json: str,
    signer: CscSigner,
    tsa_url: Optional[str],
    asset: bytes,
    custom_assertions: Sequence[dict],
    ai_disclosure: Optional[AiDisclosure] = None,
) -> bytes:
    """PDF has no write handler in c2pa; produce a sidecar manifest through the
    data-hashed embeddable workflow instead. The sidecar always starts a new
    manifest store, so an AI disclosure is always allowed here."""
    fmt = PDF_MIME_TYPE
    base = ai_generated_manifest(ai_disclosure) if ai_disclosure else MANIFEST_JSON
    builder = c2pa.Builder(
        manifest_definition(base, custom_assertions), _context(settings_json)
    )
    c2pa_signer = signer.to_c2pa_signer(tsa_url)
    try:
        if ai_disclosure is None:
            # Capture the incoming (manifest-less) PDF as a parentOf ingredient
            # so the c2pa.opened action can reference the original by its hash.
            builder.add_ingredient_from_stream(
                parent_ingredient_json(fmt, fmt), fmt, io.BytesIO(asset)
            )

        # Create a placeholder to size the manifest.
        placeholder = _native.data_hashed_placeholder(
            builder, c2pa_signer.reserve_size(), fmt
        )

        # Hash the original PDF with an exclusion for the (not-embedded)
        # placeholder; c2pa computes the hash from the asset stream.
        data_hash = {
            "exclusions": [{"start": 0, "length": len(placeholder)}],
            "name": "source_hash",
            "alg": "sha256",
            "hash": [],
            "pad": [],
        }
        return _native.sign_data_hashed_embeddable(
            builder, c2pa_signer, json.dumps(data_hash), fmt, asset
        )
    finally:
        c2pa_signer.close()
        builder.close()


def _sign_embedded(
    settings_json: str,
    signer: CscSigner,
    cawg_signer: Optional[CscSigner],
    cawg_roles: Sequence[str],
    tsa_url: Optional[str],
    content_type: str,
    asset: bytes,
    custom_assertions: Sequence[dict],
    ai_disclosure: Optional[AiDisclosure] = None,
) -> bytes:
    # JPEG XL: a bare codestream must be wrapped into a container before a
    # manifest can be embedded; container input passes through.
    if content_type == "image/jxl":
        asset = wrap_jxl_codestream(asset)
    fmt = c2pa_format(content_type)

    # If the asset already carries a manifest, add a new manifest to the
    # existing store (chaining the prior manifest in as a parent ingredient)
    # rather than replacing it with a brand new store.
    has_manifest = _has_manifest(settings_json, fmt, asset)
    if ai_disclosure is not None and has_manifest:
        # c2pa.created must be the first action of a manifest with no parentOf
        # ingredient, which can't hold when there is earlier provenance.
        raise AiDisclosureUnsupportedError(
            "the asset already carries Content Credentials; an AI-generated "
            "c2pa.created action can only be declared on an asset without them"
        )

    if ai_disclosure is not None:
        logger.info(
            "Asset has no manifest; adding a manifest with an AI-generated c2pa.created action"
        )
        # No ingredient: the asset is the AI output itself, not derived from one.
        builder = c2pa.Builder(
            manifest_definition(ai_generated_manifest(ai_disclosure), custom_assertions),
            _context(settings_json),
        )
    elif has_manifest:
        logger.info("Asset already has a manifest; adding a new manifest to the store")
        builder = c2pa.Builder(
            manifest_definition(MANIFEST_JSON_EDIT, custom_assertions),
            _context(settings_json),
        )
        # Edit intent captures the source as a parent ingredient (preserving
        # its manifest store) and adds a c2pa.opened action.
        builder.set_intent(c2pa.C2paBuilderIntent.EDIT)
    else:
        logger.info("Asset has no manifest; adding a manifest with a c2pa.opened action")
        builder = c2pa.Builder(
            manifest_definition(MANIFEST_JSON, custom_assertions),
            _context(settings_json),
        )
        builder.add_ingredient_from_stream(
            parent_ingredient_json(content_type, fmt), fmt, io.BytesIO(asset)
        )

    c2pa_signer = signer.to_c2pa_signer(tsa_url)
    try:
        if cawg_signer is not None:
            # The CAWG identity assertion is a dynamic assertion
            # (`cawg.identity`): the identity credential COSE-signs the signer
            # payload (referencing the hard-binding assertion) with its own TSA
            # countersignature, while the claim is signed as usual.
            _native.add_credential_holder_identity(
                c2pa_signer,
                CAWG_X509_SIG_TYPE,
                cawg_signer.reserve_bytes(),
                cawg_signer.identity_signature,
                roles=cawg_roles,
            )

        out = io.BytesIO()
        builder.sign(c2pa_signer, fmt, io.BytesIO(asset), out)
        return out.getvalue()
    finally:
        c2pa_signer.close()
        builder.close()


def _has_manifest(settings_json: str, fmt: str, asset: bytes) -> bool:
    try:
        reader = c2pa.Reader(fmt, io.BytesIO(asset), None, context=_context(settings_json))
    except Exception:  # noqa: BLE001 - unreadable/absent manifest means "no manifest"
        return False
    try:
        return reader.get_active_manifest() is not None
    except Exception:  # noqa: BLE001
        return False
    finally:
        reader.close()


@dataclass(frozen=True)
class _ValidatedRequest:
    credential_id: str
    content_type: str
    cawg_credential_id: Optional[str]
    cawg_roles: List[str]
    custom_assertions: List[dict]
    asset: bytes
    ai_disclosure: Optional[AiDisclosure] = None


class SignRequest:
    """Inputs for one signing operation. Setters return the request, so calls
    chain::

        signed: bytes = (
            client.new_request()
            .set_access_token(token)
            .set_c2pa_certificate_id(credential_id)
            .set_content_type("image/jpeg")
            .set_asset(photo_bytes)
            .sign()
        )
    """

    def __init__(self, client: Optional[ProvenanceClient] = None) -> None:
        self._client = client
        self._access_token: Optional[str] = None
        self._tsa_token: Optional[str] = None
        self._c2pa_certificate_id: Optional[str] = None
        self._content_type: Optional[str] = None
        self._cawg_certificate_id: Optional[str] = None
        self._cawg_roles: List[str] = []
        self._custom_assertions: List[dict] = []
        self._ai_disclosure: Optional[AiDisclosure] = None
        self._asset: Optional[bytes] = None

    # -- setters -----------------------------------------------------------------------

    def set_access_token(self, token: Union[str, "AccessToken"]) -> "SignRequest":
        """CSC API access token.

        Accepts the bare token, ``"Bearer <token>"``, or an
        :class:`~ssl_provenance_sdk.oauth.AccessToken` from
        :func:`~ssl_provenance_sdk.oauth.get_access_token`.
        """
        if isinstance(token, AccessToken):
            token = token.access_token
        token = token.strip()
        if token and not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        self._access_token = token
        return self

    def set_tsa_token(self, token: Optional[str]) -> "SignRequest":
        """TSA token for this request, overriding the client's
        (:meth:`ProvenanceClient.set_tsa_token`). ``None`` falls back to the
        client's. Required, here or on the client, by the SSL.com TSA."""
        self._tsa_token = token or None
        return self

    def set_c2pa_certificate_id(self, credential_id: str) -> "SignRequest":
        """eSigner credential ID that signs the C2PA claim
        (required)."""
        self._c2pa_certificate_id = credential_id
        return self

    def set_content_type(self, content_type: str) -> "SignRequest":
        """MIME type of the asset (required). Parameters such as
        ``; charset=utf-8`` are ignored."""
        self._content_type = content_type
        return self

    def set_cawg_certificate_id(self, credential_id: Optional[str]) -> "SignRequest":
        """eSigner credential ID that signs a CAWG identity assertion
        (optional). When set, a ``cawg.identity``
        assertion is embedded. May equal the C2PA certificate ID."""
        self._cawg_certificate_id = credential_id
        return self

    def add_cawg_role(self, role: str) -> "SignRequest":
        """Add named-actor role(s) to the identity assertion, e.g. ``cawg.creator``. Comma-separated values add several roles.
        Requires :meth:`set_cawg_certificate_id`."""
        self._cawg_roles.extend(parse_cawg_roles([role]))
        return self

    def set_cawg_roles(self, roles: Iterable[str]) -> "SignRequest":
        """Replace the named-actor roles (see :meth:`add_cawg_role`)."""
        self._cawg_roles = parse_cawg_roles(roles)
        return self

    def add_custom_assertion(
        self,
        label: str,
        data: Any,
        kind: Optional[str] = None,
        created: Optional[bool] = None,
    ) -> "SignRequest":
        """Embed a custom assertion.

        Args:
            label: Assertion label; reverse-domain format for custom assertions
                (e.g. ``com.example.review``).
            data: The assertion payload, any JSON-serializable value.
            kind: ``"Cbor"`` (default) or ``"Json"``: how it is serialized.
            created: ``True`` puts it in ``created_assertions``; the default
                puts it in ``gathered_assertions``.
        """
        definition: dict = {"label": label, "data": data}
        if kind is not None:
            definition["kind"] = kind
        if created is not None:
            definition["created"] = created
        return self.add_custom_assertion_definition(definition)

    def add_custom_assertion_definition(
        self, definition: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]
    ) -> "SignRequest":
        """Embed custom assertion(s) given as a definition object
        (``{"label", "data", "kind"?, "created"?}``) or a list of them."""
        if isinstance(definition, Mapping):
            definition = dict(definition)
        elif isinstance(definition, Sequence) and not isinstance(definition, (str, bytes)):
            definition = [dict(d) if isinstance(d, Mapping) else d for d in definition]
        self._custom_assertions.extend(normalize_custom_assertions(definition))
        return self

    def add_encoded_custom_assertion(self, value: str) -> "SignRequest":
        """Embed custom assertion(s) given as base64url-encoded JSON definitions,
        optionally comma-separated."""
        self._custom_assertions.extend(parse_encoded_custom_assertions([value]))
        return self

    def set_ai_disclosure(
        self,
        software_agent: Union[str, Mapping[str, Any], AiDisclosure, None],
        description: Optional[str] = None,
        when: Union[str, "datetime.datetime", None] = None,
    ) -> "SignRequest":
        """Declare the asset as AI-generated (``ai_disclosure``).

        The manifest then records a single ``c2pa.created`` action with
        ``digitalSourceType`` ``trainedAlgorithmicMedia`` naming the AI tool,
        instead of the default ``c2pa.opened`` action and parent ingredient.

        ``software_agent`` is the AI tool: a name, or a mapping with ``name``
        (required), optional ``version`` and up to 16 namespaced extension keys
        such as ``com.ssl.modelIdentifier``. ``description`` defaults to
        ``"Generated by <name>"``; ``when`` (RFC 3339 string or timezone-aware
        ``datetime``) defaults to the time of signing. An
        :class:`~ssl_provenance_sdk.ai_disclosure.AiDisclosure` is also
        accepted, and ``None`` removes the disclosure.

        Only for assets without Content Credentials: signing an asset that
        already has a manifest raises :class:`AiDisclosureUnsupportedError`.
        The values are signer-asserted; you are responsible for their accuracy.
        Raises :class:`InvalidAiDisclosureError` if they are malformed.
        """
        if software_agent is None or isinstance(software_agent, AiDisclosure):
            self._ai_disclosure = software_agent
        else:
            self._ai_disclosure = AiDisclosure.create(software_agent, description, when)
        return self

    def set_asset(self, data: Union[bytes, bytearray, memoryview]) -> "SignRequest":
        """The raw asset bytes to sign."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"asset must be bytes, not {type(data).__name__}")
        self._asset = bytes(data)
        return self

    # -- getters -------------------------------------------------------------------

    @property
    def access_token(self) -> Optional[str]:
        return self._access_token

    @property
    def tsa_token(self) -> Optional[str]:
        """The request's own TSA token (``None`` means the client's is used)."""
        return self._tsa_token

    @property
    def c2pa_certificate_id(self) -> Optional[str]:
        return self._c2pa_certificate_id

    @property
    def content_type(self) -> Optional[str]:
        return self._content_type

    @property
    def cawg_certificate_id(self) -> Optional[str]:
        return self._cawg_certificate_id

    @property
    def cawg_roles(self) -> List[str]:
        return list(self._cawg_roles)

    @property
    def custom_assertions(self) -> List[dict]:
        return list(self._custom_assertions)

    @property
    def ai_disclosure(self) -> Optional[AiDisclosure]:
        return self._ai_disclosure

    @property
    def asset(self) -> Optional[bytes]:
        return self._asset

    # -- execution --------------------------------------------------------------------

    def validate(self) -> _ValidatedRequest:
        """Check the inputs, raising a :class:`ProvenanceError` subclass naming
        the first problem found."""
        asset = self._asset if self._asset is not None else b""

        credential_id = self._c2pa_certificate_id or ""
        if not credential_id:
            raise MissingCredentialIdError()

        content_type = normalize_content_type(self._content_type)
        if not is_supported(content_type):
            raise UnsupportedMediaTypeError(content_type)

        cawg_credential_id = (self._cawg_certificate_id or "").strip() or None

        # The PDF sidecar workflow uses c2pa's data-hashed embeddable path,
        # which never processes dynamic assertions such as CAWG identity.
        if cawg_credential_id is not None and content_type == PDF_MIME_TYPE:
            raise CawgUnsupportedError(
                "the application/pdf sidecar workflow does not support dynamic assertions"
            )

        if self._cawg_roles and cawg_credential_id is None:
            raise InvalidCawgRoleError(", ".join(self._cawg_roles))

        return _ValidatedRequest(
            credential_id=credential_id,
            content_type=content_type,
            cawg_credential_id=cawg_credential_id,
            cawg_roles=list(self._cawg_roles),
            custom_assertions=list(self._custom_assertions),
            asset=asset,
            ai_disclosure=self._ai_disclosure.resolved() if self._ai_disclosure else None,
        )

    def sign(self) -> bytes:
        """Sign with the bound client (a default :class:`ProvenanceClient` if
        the request was created without one) and return the signed bytes.

        See :meth:`ProvenanceClient.sign` for what the bytes contain."""
        if self._client is None:
            self._client = ProvenanceClient()
        return self._client.sign(self)
