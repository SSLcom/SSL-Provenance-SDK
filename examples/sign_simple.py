"""The simplest possible signing example using the SSL.com Provenance API.

Choosing the environment ("sandbox" for testing or "production") loads its
OAuth, API and timestamp endpoints; everything else uses the defaults.

Usage:
    python examples/sign_simple.py
"""

from pathlib import Path

from ssl_provenance_sdk import ProvenanceClient, get_access_token

here = Path(__file__).parent

client = ProvenanceClient("production")

token = get_access_token(
    "YOUR_ESIGNER_USERNAME",
    "YOUR_ESIGNER_PASSWORD",
    "YOUR_OAUTH_CLIENT_ID",
    "YOUR_OAUTH_CLIENT_SECRET",
)

signed = (
    client.new_request()
    .set_access_token(token)
    .set_tsa_token("YOUR_TSA_TOKEN")  # SSL.com C2PA timestamping authority token
    .set_c2pa_certificate_id("983da863-ce7f-42b5-b227-c9076c7b34af") # default SSL Provenance API C2PA certificate
    .set_content_type("image/jpeg")
    .set_asset((here / "sample.jpg").read_bytes())
    .sign()
)

(here / "signed_simple.jpg").write_bytes(signed)
print(f"wrote {len(signed)} bytes to {here / 'signed_simple.jpg'}")
