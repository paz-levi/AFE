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
