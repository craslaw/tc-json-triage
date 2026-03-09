"""Tests for CWE↔STRIDE mapping."""

from tc_json_triage.mapping.cwe_stride import cwe_to_stride, cwes_to_stride


def test_known_cwe_mapping():
    assert "T" in cwe_to_stride("CWE-89")
    assert "I" in cwe_to_stride("CWE-89")


def test_case_insensitive():
    assert cwe_to_stride("cwe-89") == cwe_to_stride("CWE-89")


def test_numeric_only():
    assert cwe_to_stride("89") == cwe_to_stride("CWE-89")


def test_unknown_cwe_defaults_to_info_disclosure():
    result = cwe_to_stride("CWE-99999")
    assert result == ["I"]


def test_cwes_to_stride_combines():
    # CWE-89 → T,I  and CWE-287 → S,E
    result = cwes_to_stride(["CWE-89", "CWE-287"])
    assert result >= {"T", "I", "S", "E"}


def test_empty_list():
    assert cwes_to_stride([]) == set()
