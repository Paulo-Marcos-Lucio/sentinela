"""Testes do registro de checagens e da CLI."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import sentinela.cli as cli
from sentinela.core.config import ScanConfig
from sentinela.core.models import Category, Finding, ScanResult, Severity, Target
from sentinela.core.registry import build_checkers

runner = CliRunner()


# ----------------------------- registro ----------------------------- #
def test_intrusivo_excluido_por_padrao() -> None:
    ids = {c.id for c in build_checkers(ScanConfig(intrusive=False))}
    assert "exposure" not in ids


def test_intrusivo_incluido_quando_autorizado() -> None:
    ids = {c.id for c in build_checkers(ScanConfig(intrusive=True))}
    assert "exposure" in ids


def test_only_filtra_checagens() -> None:
    checkers = build_checkers(ScanConfig(only=frozenset({"cors"})))
    assert [c.id for c in checkers] == ["cors"]


def test_skip_filtra_checagens() -> None:
    ids = {c.id for c in build_checkers(ScanConfig(skip=frozenset({"cors"})))}
    assert "cors" not in ids


# ------------------------------- CLI -------------------------------- #
def _fake_result(sev: Severity) -> ScanResult:
    target = Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")
    r = ScanResult(target=target, tool_version="0.1.0", checks_run=["security-headers"])
    r.add(
        Finding(
            id="X",
            title="t",
            category=Category.HEADERS,
            severity=sev,
            description="d",
            recommendation="r",
        )
    )
    return r


def test_cli_versao() -> None:
    result = runner.invoke(cli.app, ["versao"])
    assert result.exit_code == 0
    assert "Sentinela" in result.stdout


def test_cli_checagens() -> None:
    result = runner.invoke(cli.app, ["checagens"])
    assert result.exit_code == 0
    assert "security-headers" in result.stdout


def test_cli_scan_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda target, config: _fake_result(Severity.LOW))
    result = runner.invoke(cli.app, ["scan", "alvo.com"])
    assert result.exit_code == 0


def test_cli_scan_falhar_em(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda target, config: _fake_result(Severity.HIGH))
    result = runner.invoke(cli.app, ["scan", "alvo.com", "--falhar-em", "alta"])
    assert result.exit_code == 1


def test_cli_alvo_invalido() -> None:
    result = runner.invoke(cli.app, ["scan", "ftp://x"])
    assert result.exit_code == 2
