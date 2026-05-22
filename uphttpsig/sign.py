import base64
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .utils import (
    ALGORITHMS,
    HASHES,
    CaseInsensitiveDict,
    HttpSigException,
    build_signature_template,
    ensure_bytes,
    generate_message,
)

DEFAULT_SIGN_ALGORITHM = "hmac-sha256"

CRYPTO_HASHES = {
    "sha1": hashes.SHA1(),
    "sha256": hashes.SHA256(),
    "sha512": hashes.SHA512(),
}


class Signer(object):
    """
    When using an RSA algo, the secret is a PEM-encoded private key.
    When using an HMAC algo, the secret is the HMAC signing secret.

    Password-protected keyfiles are not supported.
    """

    def __init__(self, secret, algorithm=None):
        if algorithm is None:
            algorithm = DEFAULT_SIGN_ALGORITHM

        assert algorithm in ALGORITHMS, "Unknown algorithm"
        secret = ensure_bytes(secret)

        self._rsa = None
        self._hash = None
        self.sign_algorithm, self.hash_algorithm = algorithm.split("-")

        if self.sign_algorithm == "rsa":
            try:
                rsa_key = serialization.load_pem_private_key(secret, password=None)
                self._rsa = rsa_key
                self._hash = HASHES[self.hash_algorithm]
            except ValueError:
                raise HttpSigException("Invalid key.")
        elif self.sign_algorithm == "hmac":
            self._hash = HASHES[self.hash_algorithm]
            self._secret = secret

    @property
    def algorithm(self):
        return "%s-%s" % (self.sign_algorithm, self.hash_algorithm)

    def _sign_rsa(self, data):
        data = ensure_bytes(data)
        h = CRYPTO_HASHES[self.hash_algorithm]
        return self._rsa.sign(data, padding.PKCS1v15(), h)

    def _sign_hmac(self, data):
        data = ensure_bytes(data)
        return hmac.new(self._secret, data, self._hash).digest()

    def sign(self, data):
        data = ensure_bytes(data)
        signed = None
        if self._rsa:
            signed = self._sign_rsa(data)
        elif self._hash:
            signed = self._sign_hmac(data)
        if not signed:
            raise SystemError("No valid encryptor found.")
        return base64.b64encode(signed).decode("ascii")


class HeaderSigner(Signer):
    """
    Generic object that will sign headers as a dictionary using the
    http-signature scheme.
    """

    def __init__(
        self, key_id, secret, algorithm=None, headers=None, sign_header="authorization"
    ):
        if algorithm is None:
            algorithm = DEFAULT_SIGN_ALGORITHM

        super(HeaderSigner, self).__init__(secret=secret, algorithm=algorithm)
        self.headers = headers or ["date"]
        self.signature_template = build_signature_template(
            key_id, algorithm, headers, sign_header
        )
        self.sign_header = sign_header

    def sign(self, headers, host=None, method=None, path=None):
        headers = CaseInsensitiveDict(headers)
        required_headers = self.headers or ["date"]
        signable = generate_message(required_headers, headers, host, method, path)

        signature = super(HeaderSigner, self).sign(signable)
        headers[self.sign_header] = self.signature_template % signature

        return headers
