"""Tests for src/afe/gateway/resource_paths.py's normalize_resource_path()."""

from __future__ import annotations

import pytest

from afe.gateway.resource_paths import normalize_resource_path


@pytest.mark.parametrize(
    "path, expected",
    [
        # No leading slash gets one added.
        ("finance/payroll.csv", "/finance/payroll.csv"),
        # Backslashes convert to forward slashes.
        ("finance\\payroll.csv", "/finance/payroll.csv"),
        # Already-canonical path is returned unchanged.
        ("/finance/payroll.csv", "/finance/payroll.csv"),
        # Mixed: backslashes AND a missing leading slash together.
        ("finance\\reports\\payroll.csv", "/finance/reports/payroll.csv"),
    ],
)
def test_normalize_resource_path(path, expected):
    assert normalize_resource_path(path) == expected


def test_normalize_resource_path_is_idempotent():
    once = normalize_resource_path("finance\\payroll.csv")
    twice = normalize_resource_path(once)
    assert once == twice == "/finance/payroll.csv"


def test_normalize_resource_path_collapses_traversal_segments():
    # "reports/../finance/payroll.csv" looks like it's under /reports as a raw
    # string, but ".." backs out of it — the real target is /finance/payroll.csv.
    # Collapsing this before comparison is what closes the traversal bypass.
    assert (
        normalize_resource_path("reports/../finance/payroll.csv")
        == "/finance/payroll.csv"
    )


def test_normalize_resource_path_leaves_unresolvable_escape_unresolved():
    # This escapes above any reasonable root even after collapsing "..". It is
    # deliberately left starting with ".." rather than silently stripped or
    # coerced into a leading-slash form: a ".."-prefixed string can never match
    # a real folder or file_override entry, so it's fail-secure by construction —
    # not because this function does anything special to detect the escape.
    result = normalize_resource_path("../../etc/passwd")
    assert result.startswith("..")
