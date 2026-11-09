"""Environment selection: client endpoints and OAuth token URLs (no network)."""

import pytest

from ssl_provenance_sdk import (
    PRODUCTION,
    PRODUCTION_OAUTH_TOKEN_URL,
    SANDBOX,
    SANDBOX_OAUTH_TOKEN_URL,
    Environment,
    MissingTsaTokenError,
    ProvenanceClient,
    get_access_token,
    refresh_access_token,
)

from ssl_provenance_sdk.environments import tsa_requires_token

from test_oauth import RESPONSE, FakeResponse, FakeSession


def test_production_is_the_default():
    for client in (ProvenanceClient(), ProvenanceClient("production")):
        assert client.environment == PRODUCTION
        assert client.csc_endpoint == "https://cs.ssl.com"
        assert client.tsa_url == "https://ts-c2pa.ssl.com/ecc"
        assert client.oauth_token_url == PRODUCTION_OAUTH_TOKEN_URL


def test_sandbox():
    client = ProvenanceClient("sandbox")
    assert client.environment == SANDBOX
    assert client.csc_endpoint == "https://cs-try.ssl.com"
    assert client.tsa_url == "https://ts-c2pa.ssl.com/ecc"
    assert client.oauth_token_url == SANDBOX_OAUTH_TOKEN_URL


def test_names_are_case_insensitive():
    assert ProvenanceClient(" Production ").environment == PRODUCTION
    assert ProvenanceClient("SANDBOX").environment == SANDBOX


def test_unknown_environment():
    with pytest.raises(ValueError, match="staging"):
        ProvenanceClient("staging")
    with pytest.raises(ValueError):
        ProvenanceClient().set_environment("staging")


def test_trust_anchors_keyword_still_works():
    assert ProvenanceClient(trust_anchors="PEM").trust_anchors == "PEM"
    assert ProvenanceClient("production", trust_anchors="PEM").trust_anchors == "PEM"


def test_overrides_and_set_environment():
    client = (
        ProvenanceClient("production")
        .set_csc_endpoint("https://csc.example/")
        .set_tsa_url(None)
        .set_oauth_token_url("https://oauth.example/token")
    )
    assert client.environment == PRODUCTION
    assert client.csc_endpoint == "https://csc.example"
    assert client.tsa_url is None
    assert client.oauth_token_url == "https://oauth.example/token"

    # Switching environment replaces every override.
    client.set_environment("sandbox")
    assert client.csc_endpoint == SANDBOX.csc_endpoint
    assert client.tsa_url == SANDBOX.tsa_url
    assert client.oauth_token_url == SANDBOX_OAUTH_TOKEN_URL


def test_custom_environment():
    env = Environment("onprem", "https://csc.internal/", "https://oauth.internal/token", None)
    client = ProvenanceClient(env)
    assert client.environment is env
    assert client.csc_endpoint == "https://csc.internal"
    assert client.tsa_url is None
    assert client.oauth_token_url == "https://oauth.internal/token"


def test_oauth_uses_environment_token_url():
    session = FakeSession(FakeResponse(200, RESPONSE))
    get_access_token("u", "p", "c", "s", session=session)
    get_access_token("u", "p", "c", "s", environment="sandbox", session=session)
    refresh_access_token("r", "c", "s", environment=SANDBOX, session=session)
    # An explicit token_url wins over the environment.
    get_access_token("u", "p", "c", "s", "https://oauth.test/t", environment="sandbox", session=session)
    assert [url for url, _ in session.calls] == [
        PRODUCTION_OAUTH_TOKEN_URL,
        SANDBOX_OAUTH_TOKEN_URL,
        SANDBOX_OAUTH_TOKEN_URL,
        "https://oauth.test/t",
    ]


def test_oauth_unknown_environment():
    with pytest.raises(ValueError):
        get_access_token("u", "p", "c", "s", environment="staging", session=FakeSession(None))


class _NoNetwork:
    """A session that fails the test if the SDK tries to send anything."""

    def post(self, *args, **kwargs):
        raise AssertionError("unexpected network call")

    get = post


def _sign(client, request_tsa_token=None):
    return (
        client.set_session(_NoNetwork())
        .new_request()
        .set_tsa_token(request_tsa_token)
        .set_access_token("token")
        .set_c2pa_certificate_id("cred-1")
        .set_content_type("image/jpeg")
        .set_asset(b"\xff\xd8\xff")
        .sign()
    )


@pytest.mark.parametrize(
    "url, required",
    [
        ("https://ts-c2pa.ssl.com/ecc", True),
        ("https://TS-C2PA.SSL.COM/rsa", True),
        ("https://ssl.com/tsa", True),
        ("http://timestamp.digicert.com", False),
        ("https://notssl.com/tsa", False),
        (None, False),
    ],
)
def test_tsa_requires_token(url, required):
    assert tsa_requires_token(url) is required


@pytest.mark.parametrize("environment", ["production", "sandbox"])
def test_ssl_tsa_without_token_fails_before_any_network_call(environment):
    with pytest.raises(MissingTsaTokenError, match="ts-c2pa.ssl.com") as e:
        _sign(ProvenanceClient(environment))
    assert e.value.status_code == 400


@pytest.mark.parametrize(
    "client, request_token",
    [
        (ProvenanceClient(tsa_token="tsa-token"), None),
        (ProvenanceClient().set_tsa_token("tsa-token"), None),
        (ProvenanceClient(), "tsa-token"),  # request only
        (ProvenanceClient(tsa_token="client-token"), "request-token"),  # both
        (ProvenanceClient().set_tsa_url(None), None),  # timestamping off
        (ProvenanceClient().set_tsa_url("http://timestamp.digicert.com"), None),  # other TSA
    ],
    ids=["constructor", "client-setter", "request-setter", "both", "no-tsa", "other-tsa"],
)
def test_tsa_token_check_passes(client, request_token):
    # Past the TSA check, the first thing signing does is call the CSC API.
    with pytest.raises(AssertionError, match="unexpected network call"):
        _sign(client, request_token)


def test_request_tsa_token_overrides_client():
    client = ProvenanceClient(tsa_token="client-token")
    request = client.new_request()
    assert request.tsa_token is None  # falls back to the client's
    assert request.set_tsa_token("request-token").tsa_token == "request-token"
    assert request.set_tsa_token(None).tsa_token is None


@pytest.mark.parametrize(
    "client_token, request_token, sent",
    [
        ("client-token", None, "client-token"),
        (None, "request-token", "request-token"),
        ("client-token", "request-token", "request-token"),
    ],
)
def test_tsa_token_sent_to_tsa(monkeypatch, client_token, request_token, sent):
    import ssl_provenance_sdk.client as client_module

    used = []
    real = client_module.bearer_headers
    monkeypatch.setattr(client_module, "bearer_headers", lambda t: used.append(t) or real(t))
    with pytest.raises(AssertionError, match="unexpected network call"):
        _sign(ProvenanceClient(tsa_token=client_token), request_token)
    assert used == [sent]
