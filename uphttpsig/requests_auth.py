import requests.auth
from urllib.parse import urlparse

from .sign import HeaderSigner


class HTTPSignatureAuth(requests.auth.AuthBase):
    """
    Sign a request using the http-signature scheme.
    """

    def __init__(self, key_id="", secret="", algorithm=None, headers=None):
        headers = headers or []
        self.header_signer = HeaderSigner(
            key_id=key_id, secret=secret, algorithm=algorithm, headers=headers
        )
        self.uses_host = "host" in [h.lower() for h in headers]

    def __call__(self, r):
        headers = self.header_signer.sign(
            r.headers,
            host=urlparse(r.url).netloc if self.uses_host else None,
            method=r.method,
            path=r.path_url,
        )
        r.headers.update(headers)
        return r
