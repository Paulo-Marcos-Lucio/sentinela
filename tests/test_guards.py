"""Checagens que sondam o alvo por conta própria pulam host inacessível (evita 2× timeout)."""

from __future__ import annotations

from conftest import make_context, make_probe
from sentinela.checks.cors import CorsChecker
from sentinela.checks.http_methods import HttpMethodsChecker
from sentinela.checks.well_known import WellKnownChecker


def test_checkers_pulam_host_inacessivel() -> None:
    ctx = make_context(primary=make_probe(error="ConnectError", status=0))
    assert list(CorsChecker().run(ctx)) == []
    assert list(HttpMethodsChecker().run(ctx)) == []
    assert list(WellKnownChecker().run(ctx)) == []
