import base64
import hashlib
import re
from urllib.request import parse_http_list

ALGORITHMS = frozenset([
    "rsa-sha1",
    "rsa-sha256",
    "rsa-sha512",
    "hmac-sha1",
    "hmac-sha256",
    "hmac-sha512",
])

HASHES = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


class HttpSigException(Exception):
    pass


def ensure_bytes(data):
    if isinstance(data, str):
        return data.encode("ascii")
    return bytes(data)


def ct_bytes_compare(a, b):
    """Constant-time byte comparison."""
    a = ensure_bytes(a)
    b = ensure_bytes(b)

    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0


def generate_message(required_headers, headers, host=None, method=None, path=None):
    headers = CaseInsensitiveDict(headers)

    if not required_headers:
        required_headers = ["date"]

    signable_list = []
    for h in required_headers:
        h = h.lower()
        if h == "(request-target)":
            if not method or not path:
                raise HttpSigException(
                    'method and path arguments required when using "(request-target)"'
                )
            signable_list.append("%s: %s %s" % (h, method.lower(), path))
        elif h == "host":
            if not host:
                if "host" in headers:
                    host = headers[h]
                else:
                    raise HttpSigException('missing required header "%s"' % h)
            signable_list.append("%s: %s" % (h, host))
        else:
            if h not in headers:
                raise HttpSigException('missing required header "%s"' % h)
            signable_list.append("%s: %s" % (h, headers[h]))

    return "\n".join(signable_list).encode("ascii")


def parse_signature_header(sign_value):
    values = {}
    if sign_value:
        fields = parse_http_list(sign_value)
        for item in fields:
            if "=" in item:
                key, value = item.split("=", 1)
                if not (len(key) and len(value)):
                    continue
                if value[0] == '"':
                    value = value[1:-1]
                values[key] = value
    return CaseInsensitiveDict(values)


def parse_authorization_header(header):
    if not isinstance(header, str):
        header = header.decode("ascii")

    auth = header.split(" ", 1)
    if len(auth) > 2:
        raise ValueError(
            'Invalid authorization header. (eg. Method key1=value1,key2="value, \\"2\\"")'
        )

    values = {}
    if len(auth) == 2:
        values = parse_signature_header(auth[1])

    return auth[0], values


def build_signature_template(key_id, algorithm, headers, sign_header="authorization"):
    param_map = {
        "keyId": key_id,
        "algorithm": algorithm,
        "signature": "%s",
    }
    if headers:
        headers = [h.lower() for h in headers]
        param_map["headers"] = " ".join(headers)
    kv = map('{0[0]}="{0[1]}"'.format, param_map.items())
    kv_string = ",".join(kv)
    if sign_header.lower() == "authorization":
        return "Signature %s" % kv_string

    return kv_string


class CaseInsensitiveDict(dict):
    """A case-insensitive dictionary for header storage."""

    def __init__(self, d=None, **kwargs):
        super(CaseInsensitiveDict, self).__init__(**kwargs)
        if d:
            self.update((k.lower(), v) for k, v in d.items())

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())


def get_fingerprint(key):
    """
    Takes an ssh public key and generates the fingerprint.
    See: http://tools.ietf.org/html/rfc4716 for more info
    """
    if key.startswith("ssh-rsa"):
        key = key.split(" ")[1]
    else:
        regex = r"\-{4,5}[\w\| ]+\-{4,5}"
        key = re.split(regex, key)[1]

    key = key.replace("\n", "")
    key = key.strip().encode("ascii")
    key = base64.b64decode(key)
    fp_plain = hashlib.md5(key).hexdigest()
    return ":".join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
