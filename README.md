# SSL Provenance API SDK

The SSL Provenance API SDK is a Python library for adding [C2PA](https://c2pa.org/) content
credentials to digital assets. It creates (or adds to) manifests and signs them through SSL.com's Provenance API; your signing keys never leave SSL.com.

With the SDK you can:

- embed a signed C2PA manifest into images, video and audio files.
- add a CAWG identity assertion naming the creator or other actors;
- attach your own custom assertions;
- add a new manifest to the manifest store of assets that already carry content credentials, preserving their
  history.

The integration is straightforward: configure a `ProvenanceClient` once, then for each
asset build a `SignRequest`, pass the asset as `bytes`, and get the signed asset back as
`bytes`.

**Contents**

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Integration in four steps](#3-integration-in-four-steps)
4. [Integration patterns](#4-integration-patterns)
5. [Feature guides](#5-feature-guides)
6. [Verifying signed output](#6-verifying-signed-output)
7. [API reference](#7-api-reference)
8. [Error handling](#8-error-handling)
9. [Troubleshooting](#9-troubleshooting)
10. [Platform support and limitations](#10-platform-support-and-limitations)
11. [Running the tests](#11-running-the-tests)
12. [Building and publishing](#12-building-and-publishing)
13. [License](#13-license)

---

## 1. Prerequisites

| You need | Notes |
|---|---|
| Python 3.10 or newer | See [Platform support](#10-platform-support-and-limitations) |
| An SSL.com eSigner account with a document-signing credential | Its **credential ID** identifies the certificate that signs the C2PA claim |
| An eSigner **access token** | An OAuth access token for the API. Get one with `get_access_token`; tokens expire, so refresh them with `refresh_access_token` (see [Access tokens](#access-tokens-oauth)) |
| A **TSA token** | Authenticates to the SSL.com timestamp authority, which rejects unauthenticated requests. Set it once on the client, `ProvenanceClient(tsa_token=...)`, or per request with `set_tsa_token()`; see [Timestamp authority](#timestamp-authority-tsa) |
| *(Optional)* a second credential for CAWG identity | If you want to optional add a creator organization or individual or both |
| Outbound network access | To the API endpoints, the timestamp authority (TSA) and, when you call `download_trust_anchors`, the trust-list URLs; see [Trust anchors](#trust-anchors) |

SSL.com provides two environments: **production** (the SDK default) and **sandbox**,
for testing. Choose one with `ProvenanceClient("production")` or
`ProvenanceClient("sandbox")` and the SDK uses that environment's endpoints; see
[Environments](#environments). Use credentials and tokens issued for the environment you
choose. The SDK never looks up credential IDs: always pass the
C2PA credential ID (and, for CAWG identity, the CAWG credential ID) explicitly.

## 2. Installation

The package will soon be published on pip, meanwhile install from a built wheel or a source checkout instead:

```bash
pip install ssl_provenance_sdk-1.0.0-py3-none-any.whl   # wheel from dist/
pip install /path/to/ssl_provenance_sdk                 # source checkout
```

The import name is `ssl_provenance_sdk`.

Install the SDK into the **same interpreter or virtual environment** your application
(or IDE) runs. The SDK depends on `c2pa-python` (imported as `c2pa`), `requests`, `cbor2`
and `asn1crypto`. Prebuilt wheels exist for all of them, so nothing is compiled during
installation.

## 3. Integration in four steps

### Step 1 — Configure a client once

```python
from ssl_provenance_sdk import ProvenanceClient, get_access_token

client = ProvenanceClient(tsa_token=tsa_token)     # access to the SSL.com C2PA TSA
access_token = get_access_token(username, password, client_id, client_secret)
```

Create the client at application startup and reuse it.

### Step 2 — Build a signing request

```python
request = (
    client.new_request()
    .set_access_token(access_token)
    .set_c2pa_certificate_id(credential_id)
    .set_content_type("image/jpeg")
    .set_asset(photo_bytes)                  # bytes, bytearray or memoryview
)
```

Use a new request for each asset. Setters return the request, so calls chain.

### Step 3 — Sign

```python
signed: bytes = request.sign()
```

`sign()` blocks while it calls the Provenance API (and the SSL C2PA TSA). It returns the
asset with the C2PA manifest embedded, in the same format.

### Step 4 — Store the result and handle errors

```python
from ssl_provenance_sdk import ProvenanceError

try:
    signed = request.sign()
except ProvenanceError as e:
    log.warning("signing failed (%s): %s", e.status_code, e)
    raise
else:
    storage.put("photos/signed.jpg", signed)
```

Every SDK error is a `ProvenanceError` subclass; see [Error handling](#8-error-handling).

## 4. Integration patterns

### Signing files on disk

The SDK works on bytes, so your code owns file I/O:

```python
from pathlib import Path

def sign_file(src: Path, dst: Path, content_type: str) -> None:
    signed = (
        client.new_request()
        .set_access_token(access_token)
        .set_c2pa_certificate_id(credential_id)
        .set_content_type(content_type)
        .set_asset(src.read_bytes())
        .sign()
    )
    dst.write_bytes(signed)
```
Check the [`examples/`](examples/) folder for full examples.

## 5. Feature guides

### Assets that already carry content credentials

No extra code is needed. If the asset already has a C2PA manifest, the SDK adds a new
manifest to the existing manifest store and records the previous one as the parent
ingredient, so the asset's provenance history is preserved. Otherwise it creates a new
store, records the original asset as a `parentOf` ingredient, and declares a
`c2pa.opened` action that references it (or, for an
[AI-generated asset](#ai-generated-assets), a `c2pa.created` action naming the AI tool).

### CAWG identity assertions

A [CAWG identity assertion](https://cawg.io/identity/) (`cawg.identity`) attests to the
identity of a named actor, such as the creator.

```python
signed = (
    client.new_request()
    .set_access_token(access_token)
    .set_c2pa_certificate_id(credential_id)
    .set_cawg_certificate_id(identity_credential_id)   
    .add_cawg_role("cawg.creator")  # optional; repeat or comma-separate
    .set_content_type("image/jpeg")
    .set_asset(photo_bytes)
    .sign()
)
```

- The identity is signed through the API and carries its own RFC 3161 timestamp.
- Use a separate credential when the creator's identity certificate differs from the
  claim-signing certificate, or the same ID to have one credential sign both.
- Roles are passed through as-is, so custom role URIs are accepted. Setting roles without
  a CAWG credential is an error.
- Each asset costs one extra signature, one TSA request and, for a separate
  credential, one credential lookup. The manifest grows by about 20 KB.

### Custom assertions

Attach your own custom data to the manifest. It is covered by the claim signature like every
other assertion.

```python
request = (
    client.new_request()
    # ... credentials, content type, asset ...
    .add_custom_assertion("com.example.review", {"reviewer": "jane", "rating": 5})
    .add_custom_assertion("com.example.notes", {"text": "hello"}, kind="Json", created=True)
)
```

| Field | Required | Description |
|---|---|---|
| `label` | Yes | Reverse-domain label (e.g. `com.example.review`); C2PA-defined labels are also accepted |
| `data` | Yes | Any JSON-serialisable value your label's schema calls for |
| `kind` | No | `"Cbor"` (default) or `"Json"`: how the assertion is serialised |
| `created` | No | `True` puts it in `created_assertions`; the default puts it in `gathered_assertions` |

You can also pass a definition object or list with `add_custom_assertion_definition()`,
or base64url-encoded JSON (comma-separated for several) with
`add_encoded_custom_assertion()`, which is useful when the definitions arrive from another
system already encoded.

The SDK validates only the envelope (a non-empty string `label` and a `data` member) and
raises `InvalidCustomAssertionError` from the setter, before any network call.

### AI-generated assets

If an AI tool generated the asset, declare it with `set_ai_disclosure()` and name the tool.
Content Credentials viewers, such as the
[Content Credentials verify site](https://contentcredentials.org/verify), then show the asset
as AI-generated together with the tool's name.

```python
request = (
    client.new_request()
    # ... credentials, content type, asset ...
    .set_ai_disclosure(
        {
            "name": "Acme Image Generator",                 # required
            "version": "3.1",                               # optional
            "com.ssl.modelIdentifier": "acme-imagegen-3.1-xl",  # optional extension keys
        },
        description="Generated by Acme Image Generator from a text prompt",  # optional
        when="2026-10-01T10:00:00Z",                        # optional
    )
)
request.set_ai_disclosure("Acme Image Generator")           # shorthand: name only
```

The manifest then declares the standard C2PA 2.2 creation action instead of the default
`c2pa.opened` action and parent ingredient:

```json
{
  "action": "c2pa.created",
  "when": "2026-10-01T10:00:00Z",
  "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
  "softwareAgent": { "name": "Acme Image Generator", "version": "3.1", "com.ssl.modelIdentifier": "acme-imagegen-3.1-xl" },
  "description": "Generated by Acme Image Generator from a text prompt"
}
```

- It is the only action, and the actions assertion sets `allActionsIncluded: true`.
- No parent ingredient is added, because the asset is the AI output itself.
- `digitalSourceType` is the IPTC term
  [`trainedAlgorithmicMedia`](https://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia),
  which means media created by a generative AI model.
- `softwareAgent` names the AI tool. The claim generator is still `SSL Provenance API`.

| Argument | Required | Description |
|---|---|---|
| `software_agent` | Yes | The AI tool's name, or a mapping with `name` (required), `version` (optional) and up to 16 namespaced extension keys such as `com.ssl.modelIdentifier` |
| `description` | No | How the asset was generated. Defaults to `Generated by <name>` |
| `when` | No | When the asset was generated: an RFC 3339 timestamp such as `2026-10-01T10:00:00Z`, or a timezone-aware `datetime`. Stored in UTC. Defaults to the time of signing |

Extension keys use reverse-domain notation (at least two segments, each starting with a
letter or digit and containing only letters, digits, `-` or `_`) and can't use the reserved
`c2pa` or `cawg` namespaces. Every value must be a non-empty string of at most 65,535 bytes.
The setter raises `InvalidAiDisclosureError` for malformed input, before any network call.
`AiDisclosure.from_dict()` accepts the SSL Provenance API's `ai_disclosure` JSON object
(`{"softwareAgent": ..., "description": ..., "when": ...}`) and can be passed to
`set_ai_disclosure()` directly.

You can combine an AI disclosure with custom assertions and CAWG identity assertions.

An AI disclosure can only start a provenance history. If the asset already carries a C2PA
manifest, `sign()` raises `AiDisclosureUnsupportedError` (422). Sign such an asset without
the disclosure: its existing provenance, which may already record that it is AI-generated,
is kept and extended.

> **The AI disclosure is a claim made by the signer.** The SDK embeds and signs the values
> you supply but doesn't check how the asset was produced. For assets you received from a
> third party, you are responsible for their accuracy.

## 6. Verifying signed output

Use `c2pa-python`, installed with the SDK, to inspect what was signed, for example in
your integration tests:

```python
import io, json
import c2pa

reader = c2pa.Reader("image/jpeg", io.BytesIO(signed))
store = json.loads(reader.json())
reader.close()

manifest = store["manifests"][store["active_manifest"]]
print(store["validation_state"]) # "Valid" or "Trusted"
print([a["label"] for a in manifest["assertions"]])
```

`validation_state` is `Trusted` only when the signing certificate chains to a trust
anchor the reader knows about. To check that, configure the reader with the C2PA trust
lists. Public tools such as the [Content Credentials verify site](https://verify.contentauthenticity.org/)
also display the result.

## 7. API reference

### Client configuration (`ProvenanceClient`)

`ProvenanceClient(environment="production", trust_anchors=None, tsa_token=None)`. Every setting has a
built-in default and changes only through its setter; the SDK reads nothing from
environment variables. If your application keeps configuration in the environment, read
it yourself and pass the values to the constructor and setters.

#### Environments

The environment, `"production"` (the default) or `"sandbox"` (for testing), sets the
endpoints the client uses:

| Endpoint | Sandbox | Production (default) | Override with |
|---|---|---|---|
| API | `https://cs-try.ssl.com` | `https://cs.ssl.com` | `set_csc_endpoint(url)` |
| Timestamp authority (TSA) | `https://ts-c2pa.ssl.com/ecc` | `https://ts-c2pa.ssl.com/ecc` | `set_tsa_url(url)` (`None` disables timestamping) |
| OAuth token endpoint | `https://oauth-sandbox.ssl.com/oauth2/token` | `https://login.ssl.com/oauth2/token` | `set_oauth_token_url(url)` |

```python
client = ProvenanceClient("production", tsa_token=tsa_token)  # all SSL production endpoints
```

`set_environment(name)` switches an existing client and replaces any endpoint you
overrode. Names are case-insensitive, and an unknown name raises `ValueError`. You can also
pass an `Environment(name, csc_endpoint, oauth_token_url, tsa_url)` of your own; the
built-in ones are exported as `SANDBOX` and `PRODUCTION`. The `environment`, `csc_endpoint`,
`tsa_url` and `oauth_token_url` properties show the values in use.

#### Timestamp authority (SSL C2PA TSA)

Every signature is timestamped by the SSL C2PA TSA so it stays verifiable after the signing
certificate expires. The C2PA Conformant SSL TSA only accepts authenticated requests, so signing needs a TSA token.
It is a static token, separate from the OAuth access token. Set it once on the client, which is enough when one token
serves every request, or per request, for example when each of your customers has its
own token:

```python
client = ProvenanceClient("production", tsa_token=tsa_token)   # default for every request
client.set_tsa_token(tsa_token)                                 # same, on an existing client

request = client.new_request().set_tsa_token(customer_tsa_token)  # this request only
```

A token set on the request wins over the client's; `request.set_tsa_token(None)` falls
back to the client's.

#### Other settings

| Setter | Default |
|---|---|
| `set_tsa_token(token)` | *(none)*; default TSA token for every request, required by the SSL.com C2PA TSA unless each request sets one. Also `ProvenanceClient(tsa_token=token)` |
| `set_trust_anchors(pem)` | *(none)*; in-memory trust-anchor PEM bundle. Also `ProvenanceClient(trust_anchors=pem)` |
| `set_timeout(seconds)` | 60 seconds, for API calls |
| `set_session(session)` | A new `requests.Session`; supply one for API, TSA and OAuth calls (proxies, retries, CA bundles) |

| Method | Description |
|---|---|
| `new_request()` | Returns a `SignRequest` bound to this client |
| `sign(request)` | Signs a request; same as `request.sign()` |
| `c2pa_settings_json()` | The c2pa settings applied to every signing operation |

#### Trust anchors

The C2PA trust anchors are used to validate certificates already present in incoming assets.
Signing never downloads trust lists. Call `download_trust_anchors` once (at startup),
keep the merged PEM string in memory and pass that same string to every client:

```python
from ssl_provenance_sdk import (
    C2PA_TRUST_LIST_URL, C2PA_TSA_TRUST_LIST_URL, ProvenanceClient, download_trust_anchors,
)

trust_anchors = download_trust_anchors(C2PA_TRUST_LIST_URL, C2PA_TSA_TRUST_LIST_URL)

client_a = ProvenanceClient(trust_anchors=trust_anchors)
client_b = ProvenanceClient().set_trust_anchors(trust_anchors)   # same string, no download
```

`download_trust_anchors(trust_list_url, tsa_trust_list_url, *, session=None, timeout=30)`
downloads both lists, merges them and returns one PEM string; nothing is written to disk.
Pass `None` as the TSA URL to download only the signing list. On failure it raises
`TrustListDownloadError`. `C2PA_TRUST_LIST_URL` and `C2PA_TSA_TRUST_LIST_URL` are the
official C2PA lists and the defaults.

Clients keep a reference to the string; they don't copy, download or re-read it. To refresh
the lists (for example once a day in a long-running service), call `download_trust_anchors`
again and pass the new string to each client with `set_trust_anchors`.
[`examples/sign_full.py`](examples/sign_full.py) shows this with error handling.

Without trust anchors, signing still works, but existing credentials can't be validated
as trusted.

### Access tokens (OAuth)

The API needs an OAuth access token. Get one with `get_access_token`, passing the
client's `oauth_token_url` so the token comes from the same environment as the client.
It comes back as an `AccessToken`:

```python
from ssl_provenance_sdk import get_access_token, refresh_access_token

token = get_access_token(username, password, client_id, client_secret, client.oauth_token_url)
request.set_access_token(token)                           # or token.access_token

if token.expires_within(60):                              # renew without the password
    token = refresh_access_token(token.refresh_token, client_id, client_secret,
                                 client.oauth_token_url)
```

`client_id` and `client_secret` identify your OAuth client; both are required. Instead of
`token_url` you can pass `environment="sandbox"` (or `"production"`, the default) to use
that environment's token endpoint:

| Function | Description |
|---|---|
| `get_access_token(username, password, client_id, client_secret, token_url=None, *, environment="production", session=None, timeout=30)` | Password grant |
| `refresh_access_token(refresh_token, client_id, client_secret, token_url=None, *, environment="production", session=None, timeout=30)` | Refresh-token grant |
| `request_access_token(token_request, token_url=None, *, environment="production", session=None, timeout=30)` | Sends any token request body (a dict, e.g. `{"grant_type": "password", "username": ..., "password": ..., "client_id": ..., "client_secret": ...}`) as JSON |

`SANDBOX_OAUTH_TOKEN_URL` and `PRODUCTION_OAUTH_TOKEN_URL` hold the two token endpoints.

`AccessToken` has `access_token`, `token_type`, `expires_in`, `refresh_token`, `created_at`
and `raw` (the full JSON response), plus `expires_at`, `expires_within(seconds)` and
`authorization` (the `Authorization` header value). Its `repr` hides the token values.
On failure these functions raise `OAuthError`; credentials never appear in error messages
or logs.

### Signing request (`SignRequest`)

| Setter | Required | Description |
|---|---|---|
| `set_access_token(token)` | Yes | eSigner access token (a string or an `AccessToken`); `"Bearer "` is added if missing |
| `set_tsa_token(token)` | Yes, here or on the client | TSA token for this request, overriding the client's; see [Timestamp authority](#timestamp-authority-tsa) |
| `set_c2pa_certificate_id(id)` | Yes | Credential that signs the C2PA claim |
| `set_content_type(mime)` | Yes | Asset MIME type; parameters such as `; charset=…` are ignored |
| `set_asset(data)` | Yes | Asset as `bytes`, `bytearray` or `memoryview` |
| `set_cawg_certificate_id(id)` | No | Credential that signs the CAWG identity assertion |
| `add_cawg_role(role)` | No | Adds named actor role(s); comma-separated values add several |
| `set_cawg_roles(roles)` | No | Replaces the role list |
| `add_custom_assertion(label, data, kind=None, created=None)` | No | Adds one custom assertion |
| `set_ai_disclosure(software_agent, description=None, when=None)` | No | Declares the asset as AI-generated; see [AI-generated assets](#ai-generated-assets). `None` removes it |
| `add_custom_assertion_definition(obj_or_list)` | No | Adds definition object(s) |
| `add_encoded_custom_assertion(value)` | No | Adds base64url-encoded JSON definition(s) |

| Method | Description |
|---|---|
| `sign()` | Signs and returns `bytes` |
| `validate()` | Runs the input checks without signing; raises the same errors as `sign()` |

Read-only properties mirror each setter: `access_token`, `tsa_token`, `c2pa_certificate_id`,
`content_type`, `cawg_certificate_id`, `cawg_roles`, `custom_assertions`, `ai_disclosure`, `asset`.

### Supported content types

| Category | Content types |
|---|---|
| Images | `image/jpeg`, `image/jxl`, `image/png`, `image/svg+xml`, `image/gif`, `image/tiff`, `image/webp`, `image/x-adobe-dng`, `image/avif`, `image/heif`, `image/heic` |
| Video | `video/x-msvideo`, `video/mp4`, `video/quicktime` |
| Audio | `audio/flac`, `audio/mpeg`, `audio/mp4`, `audio/wav` |

### Logging

The SDK logs through Python's standard `logging` module under the `ssl_provenance_sdk`
logger and never configures handlers itself. Enable it in your application:

```python
import logging
logging.getLogger("ssl_provenance_sdk").setLevel(logging.INFO)
```

At `INFO` it reports whether an asset already had a manifest, custom assertion labels,
CAWG use and TSA response sizes. Signing and TSA failures are logged at `ERROR`.

## 8. Error handling

All errors derive from `ProvenanceError`. Each has a `status_code` (an HTTP-style code,
convenient when you expose signing through a web service) and `to_dict()`, which returns
`{"error": "<message>"}`.

| Exception | `status_code` | Raised when | What to do |
|---|---|---|---|
| `MissingCredentialIdError` | 400 | No C2PA certificate ID was set | Fix the request |
| `MissingTsaTokenError` | 400 | Neither the request nor the client has a TSA token | Call `set_tsa_token()` on the client or the request |
| `InvalidCawgRoleError` | 400 | Roles were set without a CAWG certificate ID | Set a CAWG credential or drop the roles |
| `InvalidCustomAssertionError` | 400 | A custom assertion is malformed (raised by the setter) | Fix the definition |
| `InvalidAiDisclosureError` | 400 | An AI disclosure is malformed (raised by the setter) | Fix the software agent, description or timestamp |
| `UnsupportedMediaTypeError` | 415 | The content type isn't supported | Check the content type |
| `AiDisclosureUnsupportedError` | 422 | An AI disclosure was set for an asset that already has Content Credentials | Sign it without `set_ai_disclosure` |
| `TrustListDownloadError` | 502 | `download_trust_anchors` couldn't download a trust list, or it isn't a PEM bundle | Check network access and the URL; sign without trust anchors or keep the previous bundle |
| `OAuthError` | 401 | `get_access_token`, `refresh_access_token` or `request_access_token` couldn't get a token (wrong credentials or client ID, expired refresh token, endpoint unreachable) | Check the credentials and token URL; log in again if the refresh token expired |
| `NoCredentialError` | 500 | The credential's certificate chain couldn't be fetched (invalid or expired token, wrong credential ID or endpoint) | Refresh the token; check the ID and endpoint |
| `CscApiError` | 500 | The API failed while signing | Retry; check quota and credential status |
| `C2paSigningError` | 500 | c2pa rejected the manifest, or signing or timestamping failed | Inspect the message |

Input errors (400, 415, 422) are detected before any network call, so they are cheap
and safe to surface to end users. Of the 500 errors, `CscApiError` and TSA failures are
often transient and worth one retry. A `C2paSigningError` saying c2pa rejected the
manifest (for example, a custom assertion it can't accept) will fail again until the
request changes.

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ModuleNotFoundError: No module named 'c2pa'` | The SDK isn't installed in the interpreter that runs your code. Install it into that environment, and in an IDE check that the project interpreter is the same one |
| `NoCredentialError` with an `invalid_token` or 401-style message | The access token is missing, expired, or issued for the other environment (sandbox vs production) |
| `C2paSigningError: ... TSA request failed` | The timestamp authority is unreachable or rejected the request. Check the TSA token, allow outbound HTTPS to the TSA host, or configure a reachable TSA with `set_tsa_url` |
| Signed asset reads back as `Valid`, not `Trusted` | The reader doesn't trust your certificate's root. Configure the reader with the C2PA trust lists |

## 10. Platform support and limitations

**Platforms.** Prebuilt wheels are available for:

| Platform | Python |
|---|---|
| Linux x86_64 and ARM64 (glibc 2.28+: RHEL/Rocky/Alma 8+, Debian 10+, Ubuntu 20.04+, Amazon Linux 2023) | 3.10+ |
| Windows x64 | 3.10+ |
| Windows ARM64 | 3.11+ |
| macOS (Intel and Apple silicon) | 3.10+ |

Older glibc distributions (CentOS 7, Amazon Linux 2) and musl-based ones (Alpine) have no
prebuilt wheel for the bundled c2pa library.

**c2pa-python version.** The SDK requires `c2pa-python>=0.38,<0.39`. CAWG identity
signing uses features c2pa-python doesn't expose publicly yet. It is implemented in
[`src/ssl_provenance_sdk/_native.py`](src/ssl_provenance_sdk/_native.py), which calls the
native c2pa library through c2pa-python's private internals (`c2pa.c2pa._lib`) and declares
the C function signatures itself. Those internals can change in any c2pa-python release, so
the dependency is pinned to a tested minor version. To move to a newer c2pa-python, check
that the C signatures in `_native.py` still match the bundled library, run the full test
suite, then widen the pin in `pyproject.toml`.

## 11. Running the tests

```bash
pip install -e ".[test]"
pytest
```

The tests cover input validation and parsing, plus end-to-end signing through c2pa
against an in-process fake API with a throwaway PKI: new manifests, re-signing,
CAWG identity (verified as trusted) and custom assertions. They need no
credentials or network access.

The live timestamp test is opt-in because it calls the real SSL.com C2PA TSA, using your
TSA token:

```bash
SSL_PROVENANCE_LIVE_TSA=1 SSL_PROVENANCE_TSA_TOKEN=<token> pytest tests/test_timestamp.py
SSL_PROVENANCE_LIVE_TSA=https://ts-c2pa.ssl.com/ecc SSL_PROVENANCE_TSA_TOKEN=<token> pytest tests/test_timestamp.py  # explicit TSA URL
```

## 12. Building and publishing

Run these from the project root.

1. **Set the version.** It lives in `src/ssl_provenance_sdk/__init__.py` (`__version__`).
   PyPI refuses a version number that is already published, so bump it for every release.
2. **Install the build tools and run the tests.**

   ```bash
   pip install -e ".[dev]"      # build, twine and the test dependencies
   pytest
   ```

3. **Build** the wheel and source distribution into `dist/`:

   ```bash
   rm -rf dist build
   python -m build
   ```

   This creates `ssl_provenance_sdk-<version>-py3-none-any.whl` and
   `ssl_provenance_sdk-<version>.tar.gz`.
4. **Check the files**, and that the wheel installs in a clean environment:

   ```bash
   twine check dist/*
   python -m venv /tmp/sdktest
   /tmp/sdktest/bin/pip install dist/*.whl
   /tmp/sdktest/bin/python -c "import ssl_provenance_sdk as s; print(s.__version__)"
   ```

To publish to a private index instead (Artifactory, Nexus, GitLab, AWS CodeArtifact, Azure
Artifacts), upload with `twine upload --repository-url https://your.index/repository/pypi/ dist/*`;
users then install with `pip install --index-url https://your.index/simple/ ssl-provenance-sdk`.

## 13. License

Licensed under the [Apache License, Version 2.0](LICENSE). Unless required by applicable
law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the
License.

Copyright 2026 - SSL Corp
ssl.com/c2pa
