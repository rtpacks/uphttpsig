try:
    from importlib.metadata import PackageNotFoundError, version
except ImportError:  # pragma: no cover - Python < 3.8 fallback
    from importlib_metadata import PackageNotFoundError, version

from .sign import HeaderSigner, Signer
from .verify import HeaderVerifier, Verifier

try:
    __version__ = version("uphttpsig")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ("Signer", "HeaderSigner", "Verifier", "HeaderVerifier")
