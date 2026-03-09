"""Static CWE to STRIDE category mapping."""

from __future__ import annotations

import json
import re
from pathlib import Path

_MAP_FILE = Path(__file__).resolve().parent.parent.parent.parent / "data" / "cwe_stride_map.json"

_cache: dict[str, list[str]] | None = None


def _load_map() -> dict[str, list[str]]:
    global _cache
    if _cache is None:
        with open(_MAP_FILE) as f:
            raw = json.load(f)
        _cache = {k: v for k, v in raw.items() if not k.startswith("_")}
    return _cache


def cwe_to_stride(cwe_id: str) -> list[str]:
    """Map a CWE ID (e.g. 'CWE-89') to STRIDE categories.

    Returns the mapped categories, or ["I"] as a fallback for unknown CWEs.
    """
    mapping = _load_map()
    # Normalise: accept "CWE-89", "cwe-89", "89"
    normalised = cwe_id.upper().strip()
    if not normalised.startswith("CWE-"):
        digits = re.sub(r"\D", "", normalised)
        if digits:
            normalised = f"CWE-{digits}"
    return mapping.get(normalised, ["I"])


def cwes_to_stride(cwes: list[str]) -> set[str]:
    """Map multiple CWE IDs to a combined set of STRIDE categories."""
    result: set[str] = set()
    for cwe in cwes:
        result.update(cwe_to_stride(cwe))
    return result
