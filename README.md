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

## Publishing

Tagged releases are published to PyPI by GitHub Actions using PyPI Trusted
Publishing. Configure the PyPI project with this trusted publisher:

- Owner: `rtpacks`
- Repository: `uphttpsig`
- Workflow: `publish.yml`
- Environment: `pypi`

Then push a version tag, for example:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```
