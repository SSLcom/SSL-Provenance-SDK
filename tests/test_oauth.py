"""OAuth token helpers (no network: a fake session answers POSTs)."""

import time

import pytest
import requests

from ssl_provenance_sdk import (
    AccessToken,
    OAuthError,
    SignRequest,
    get_access_token,
    refresh_access_token,
    request_access_token,
)

TOKEN_URL = "https://oauth.test/oauth2/token"
RESPONSE = {
    "access_token": "eyJ.test.token",
    "token_type": "Bearer",
    "expires_in": 3566,
    "refresh_token": "refresh-1",
    "created_at": 1792442078,
}


class FakeResponse:
    def __init__(self, status: int, body) -> None:
        self.status_code = status
        self.ok = status < 400
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession:
    def __init__(self, response) -> None:
        self.response = response
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append((url, json))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_request_access_token_sends_json_request_as_is():
    session = FakeSession(FakeResponse(200, RESPONSE))
    body = {"grant_type": "password", "username": "u", "password": "p", "client_id": "c"}
    token = request_access_token(body, TOKEN_URL, session=session)

    assert session.calls == [(TOKEN_URL, body)]
    assert token.access_token == "eyJ.test.token"
    assert token.refresh_token == "refresh-1"
    assert token.expires_at == 1792442078 + 3566
    assert token.raw == RESPONSE
    assert token.authorization == "Bearer eyJ.test.token"
    assert "eyJ" not in repr(token) and "refresh-1" not in repr(token)


def test_password_and_refresh_grants():
    session = FakeSession(FakeResponse(200, RESPONSE))
    get_access_token("u", "p", "c", "s", TOKEN_URL, session=session)
    refresh_access_token("refresh-1", "c", "s", TOKEN_URL, session=session)
    assert session.calls == [
        (
            TOKEN_URL,
            {"grant_type": "password", "username": "u", "password": "p", "client_id": "c", "client_secret": "s"},
        ),
        (
            TOKEN_URL,
            {"grant_type": "refresh_token", "refresh_token": "refresh-1", "client_id": "c", "client_secret": "s"},
        ),
    ]


def test_expiry():
    now = time.time()
    fresh = AccessToken("t", expires_in=3600, created_at=now)
    assert not fresh.expires_within(60)
    assert fresh.expires_within(3600)
    assert AccessToken("t", expires_in=10, created_at=now - 20).expires_within()
    assert not AccessToken("t").expires_within(10**9)  # no expiry reported


def test_access_token_accepted_by_sign_request():
    req = SignRequest().set_access_token(AccessToken("eyJ.test.token"))
    assert req.access_token == "Bearer eyJ.test.token"


@pytest.mark.parametrize(
    "response, message",
    [
        (FakeResponse(401, {"error": "invalid_grant", "error_description": "bad credentials"}), "bad credentials"),
        (FakeResponse(500, ValueError("no json")), "HTTP 500"),
        (FakeResponse(200, {"token_type": "Bearer"}), "no access_token"),
        (FakeResponse(200, ValueError("no json")), "JSON object"),
        (requests.ConnectionError("down"), "failed"),
    ],
)
def test_errors_do_not_leak_password(response, message):
    session = FakeSession(response)
    with pytest.raises(OAuthError) as excinfo:
        get_access_token("u", "s3cret-pass", "c", "s", TOKEN_URL, session=session)
    assert excinfo.value.status_code == 401
    assert message in str(excinfo.value)
    assert "s3cret-pass" not in str(excinfo.value)
