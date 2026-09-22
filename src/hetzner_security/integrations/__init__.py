"""Parsers for external signal sources; no scanner is executed implicitly."""

from .trivy import parse_trivy

__all__ = ["parse_trivy"]

