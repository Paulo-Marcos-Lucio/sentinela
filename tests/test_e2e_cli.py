"""Ponta a ponta: CLI → motor real → arquivo em disco → código de saída.

Só a REDE é falsa. Todos os outros testes de CLI monkeypatcham `run_scan`, e os
renderizadores são testados isolados — a costura entre eles não era percorrida por
teste nenhum. Consequência medida: `destino.write_text(...)` podia virar `pass`, o
`render_console` podia ser desligado e a opção `-o` podia ser ignorada, tudo com a
suíte verde. O artefato entregue ao cliente é o ARQUIVO, não o objeto `ScanResult`.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import sentinela.cli as cli
import sentinela.core.engine as engine
from sentinela.core.http import Probe

runner = CliRunner()

_CABECALHOS_RUINS = {"Content-Type": "text/html", "Server": "nginx/1.18.0"}


class _ClienteFalso:
    """Substitui o `HttpClient` dentro do motor: nenhuma conexão de rede acontece."""

    def __init__(self, **_kwargs: object) -> None:
        pass

    def request(self, method: str, url: str, **_kwargs: object) -> Probe:
        return Probe(
            url=url,
            status_code=200,
            headers=dict(_CABECALHOS_RUINS),
            body_snippet="<html><body>oi</body></html>",
            final_url=url,
        )

    def get(self, url: str, **kwargs: object) -> Probe:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        return

    def __enter__(self) -> _ClienteFalso:
        return self

    def __exit__(self, *exc: object) -> None:
        return


@pytest.fixture(autouse=True)
def _sem_rede(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "HttpClient", _ClienteFalso)


def _scan(*args: str) -> object:
    return runner.invoke(cli.app, ["scan", "https://exemplo.com", "--somente", "security-headers", *args])


def test_e2e_grava_json_e_falha_no_nivel_pedido(tmp_path) -> None:  # type: ignore[no-untyped-def]
    destino = tmp_path / "r.json"
    resultado = _scan("-f", "json", "-o", str(destino), "--falhar-em", "media")

    assert resultado.exit_code == 1  # há achado >= média → o gate de CI fecha
    assert destino.exists(), "o relatório entregue ao cliente não foi escrito"
    dados = json.loads(destino.read_text(encoding="utf-8"))
    assert dados["schema"] == "suite-appsec/1"
    assert dados["summary"]["score"]["grade"] in {"A", "B", "C", "D", "F"}
    assert any(f["id"] == "CSP_AUSENTE" for f in dados["findings"])
    assert dados["checks_run"] == ["security-headers"]


def test_e2e_escreve_em_stdout_com_o_hifen(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resultado = _scan("-f", "json", "-o", "-", "--falhar-em", "nenhum")
    assert resultado.exit_code == 0
    assert not list(tmp_path.iterdir())  # `-o -` NÃO cria arquivo
    dados = json.loads(resultado.stdout[resultado.stdout.index("{") :])
    assert dados["tool"] == "sentinela"


def test_e2e_console_mostra_o_achado_e_o_plano_de_acao() -> None:
    resultado = _scan("--falhar-em", "nenhum")
    assert resultado.exit_code == 0
    assert "Content-Security-Policy ausente" in resultado.stdout
    assert "Plano de ação" in resultado.stdout


def test_e2e_falhar_em_nenhum_nao_derruba_o_build() -> None:
    assert _scan("--falhar-em", "nenhum").exit_code == 0


def test_e2e_falhar_em_aceita_vocabulario_em_ingles() -> None:
    # A mesma linha de CI tem que funcionar nos dois idiomas.
    assert _scan("--fail-on", "medium").exit_code == 1
    assert _scan("--fail-on", "critical").exit_code == 0


def test_falhar_em_desconhecido_e_erro_de_uso() -> None:
    resultado = _scan("--falhar-em", "gravissima")
    assert resultado.exit_code == 2


def test_falhar_em_info_pega_qualquer_achado() -> None:
    assert _scan("--falhar-em", "info").exit_code == 1


# --------------------------------------------------------------------------- #
# ID de checagem inexistente. Sem este portão, `--somente securityheaders` (sem o
# hífen) rodava ZERO checagens, imprimia "Nota 100/100 · A" e saía com 0: o pipeline
# fica verde para sempre e ninguém percebe.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("flag", ["--somente", "--only", "--pular", "--skip"])
def test_id_de_checagem_inexistente_sai_com_2_e_lista_os_validos(flag: str) -> None:
    resultado = runner.invoke(cli.app, ["scan", "https://exemplo.com", flag, "securityheaders"])
    assert resultado.exit_code == 2
    saida = resultado.stdout + (resultado.stderr or "")
    assert "security-headers" in saida  # o erro é acionável: lista os IDs válidos


def test_id_de_checagem_valido_continua_rodando() -> None:
    assert _scan("--falhar-em", "nenhum").exit_code == 0
