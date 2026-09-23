"""Host evidence: a reviewed read-only bundle script, its parsers, and snapshot merging."""

from .ingest import apply_host_bundles, parse_bundle
from .script import BUNDLE_SCRIPT, BUNDLE_VERSION

__all__ = ["BUNDLE_SCRIPT", "BUNDLE_VERSION", "apply_host_bundles", "parse_bundle"]
