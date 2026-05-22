# uphttpsig

`uphttpsig` is a Python 3.11 compatible replacement for the legacy
`httpsig` package API.

Use the `uphttpsig` import paths in place of the original `httpsig` paths:

```python
from uphttpsig.sign import Signer, HeaderSigner
from uphttpsig.verify import Verifier, HeaderVerifier
from uphttpsig.requests_auth import HTTPSignatureAuth
```

The implementation replaces `pycryptodome`, `six`, and `pkg_resources` usage
with Python 3 standard-library code plus `cryptography`.
