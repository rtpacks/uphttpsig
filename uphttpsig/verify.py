import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .sign import CRYPTO_HASHES, Signer
from .utils import (
    ALGORITHMS,
    HASHES,
    CaseInsensitiveDict,
    HttpSigException,
    ct_bytes_compare,
    ensure_bytes,
    generate_message,
    parse_authorization_header,
    parse_signature_header,
)


class Verifier(Signer):
    """
    Verifies signed text against a secret.
    For HMAC, the secret is the shared secret.
    For RSA, the secret is the PUBLIC key.
    """

    def __init__(self, secret, algorithm=None):
        if algorithm is None:
            from .sign import DEFAULT_SIGN_ALGORITHM

            algorithm = DEFAULT_SIGN_ALGORITHM

        assert algorithm in ALGORITHMS, "Unknown algorithm"
        secret = ensure_bytes(secret)

        self._rsa = None
        self._hash = None
        self.sign_algorithm, self.hash_algorithm = algorithm.split("-")

        if self.sign_algorithm == "rsa":
            try:
                rsa_key = serialization.load_pem_public_key(secret)
                self._rsa = rsa_key
                self._hash = HASHES[self.hash_algorithm]
            except ValueError:
                raise HttpSigException("Invalid key.")
        elif self.sign_algorithm == "hmac":
            self._hash = HASHES[self.hash_algorithm]
            self._secret = secret

    def _verify(self, data, signature):
        data = ensure_bytes(data)
        signature = ensure_bytes(signature)

        if self.sign_algorithm == "rsa":
            h = CRYPTO_HASHES[self.hash_algorithm]
            try:
                self._rsa.verify(
                    base64.b64decode(signature),
                    data,
                    padding.PKCS1v15(),
                    h,
                )
                return True
            except InvalidSignature:
                return False
        elif self.sign_algorithm == "hmac":
            h = self._sign_hmac(data)
            s = base64.b64decode(signature)
            return ct_bytes_compare(h, s)
        else:
            raise HttpSigException("Unsupported algorithm.")


class HeaderVerifier(Verifier):
    """Verifies an HTTP signature from given headers."""

    def __init__(
        self,
        headers,
        secret,
        required_headers=None,
        method=None,
        path=None,
        host=None,
        sign_header="authorization",
    ):
        required_headers = required_headers or ["date"]
        self.headers = CaseInsensitiveDict(headers)

        if sign_header.lower() == "authorization":
            auth = parse_authorization_header(self.headers["authorization"])
            if len(auth) == 2:
                self.auth_dict = auth[1]
            else:
                raise HttpSigException("Invalid authorization header.")
        else:
            self.auth_dict = parse_signature_header(self.headers[sign_header])

        self.required_headers = [s.lower() for s in required_headers]
        self.method = method
        self.path = path
        self.host = host

        super(HeaderVerifier, self).__init__(
            secret, algorithm=self.auth_dict["algorithm"]
        )

    def verify(self):
        auth_headers = self.auth_dict.get("headers", "date").split(" ")

        if len(set(self.required_headers) - set(auth_headers)) > 0:
            error_headers = ", ".join(set(self.required_headers) - set(auth_headers))
            raise Exception("%s is a required header(s)" % error_headers)

        signing_str = generate_message(
            auth_headers, self.headers, self.host, self.method, self.path
        )

        return self._verify(signing_str, self.auth_dict["signature"])
