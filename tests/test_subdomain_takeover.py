"""Testes de descoberta de subdomínios e subdomain takeover (com rede falsificada)."""

from __future__ import annotations

import pytest

import sentinela.checks.subdomain_takeover as st
from conftest import FakeClient, make_context, make_probe, make_target
from sentinela.core.config import ScanConfig


def _ctx(client: FakeClient | None = None, discover: bool = True, host: str = "example.com"):
    return make_context(
        client=client or FakeClient(),
        config=ScanConfig(discover=discover),
        target=make_target(f"https://{host}/"),
    )


def _ids(ctx) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.id for f in st.SubdomainTakeoverChecker().run(ctx)}


def test_sem_flag_descobrir_nao_roda(monkeypatch: pytest.MonkeyPatch) -> None:
    chamado = {"v": False}

    def _nao_deve(_d: str):  # type: ignore[no-untyped-def]
        chamado["v"] = True
        return ["x.example.com"]

    monkeypatch.setattr(st, "discover_subdomains", _nao_deve)
    assert _ids(_ctx(discover=False)) == set()
    assert chamado["v"] is False


def test_crt_inconclusivo_declara_que_nao_avaliou(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fonte de CT fora do ar ou com cota estourada não pode virar silêncio.

    `SUBDOMAIN_TAKEOVER` é CRÍTICO e vale 40 pontos na nota. Antes, uma máquina com a
    cota gasta produzia um laudo limpo e outra máquina produzia o achado — e nada no
    relatório distinguia "não achei" de "não consegui procurar".
    """
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: None)
    achados = list(st.SubdomainTakeoverChecker().run(_ctx()))
    assert [f.id for f in achados] == ["DESCOBERTA_NAO_AVALIADA"]
    assert achados[0].severity.weight == 0  # declarar limite não pode punir o alvo


def test_superficie_reportada(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["www.example.com", "api.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: None)
    assert "SUPERFICIE_SUBDOMINIOS" in _ids(_ctx())


def test_takeover_github_pages_confirmado(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["blog.example.com", "www.example.com"])
    cnames = {"blog.example.com": "example.github.io", "www.example.com": "example.com"}
    monkeypatch.setattr(st, "_resolve_cname", lambda h: cnames.get(h))

    def handler(method: str, url: str, headers):  # type: ignore[no-untyped-def]
        if "blog.example.com" in url:
            return make_probe(body="There isn't a GitHub Pages site here", final_url=url)
        return make_probe(body="<html>ok</html>", final_url=url)

    ids = _ids(_ctx(client=FakeClient(handler=handler)))
    assert "SUBDOMAIN_TAKEOVER" in ids


def test_github_pages_legitimo_nao_gera_takeover(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["docs.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "example.github.io")

    def handler(method: str, url: str, headers):  # type: ignore[no-untyped-def]
        return make_probe(body="<html>site real e funcionando</html>", final_url=url)

    ids = _ids(_ctx(client=FakeClient(handler=handler)))
    assert "SUBDOMAIN_TAKEOVER" not in ids
    assert "SUBDOMAIN_TAKEOVER_POSSIVEL" not in ids
    assert "SUPERFICIE_SUBDOMINIOS" in ids


def test_takeover_azure_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["cdn.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "orphan.azurewebsites.net")
    monkeypatch.setattr(st, "_resolves", lambda _h: False)  # alvo do CNAME é NXDOMAIN
    assert "SUBDOMAIN_TAKEOVER" in _ids(_ctx())


def test_azure_ainda_provisionado_nao_gera_takeover(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["cdn.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "vivo.azurewebsites.net")
    monkeypatch.setattr(st, "_resolves", lambda _h: True)  # alvo existe
    ids = _ids(_ctx())
    assert "SUBDOMAIN_TAKEOVER" not in ids


def test_cname_sem_servico_conhecido_ignorado(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["mail.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "ghs.googlehosted.com")
    ids = _ids(_ctx())
    assert "SUBDOMAIN_TAKEOVER" not in ids
    assert "SUBDOMAIN_TAKEOVER_POSSIVEL" not in ids


def test_ip_puro_nao_roda(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["x"])
    assert _ids(_ctx(host="8.8.8.8")) == set()


def test_match_servico_rejeita_elb_ec2_aceita_s3() -> None:
    # FP de campo: ELB/EC2/RDS sob amazonaws.com NÃO são reivindicáveis -> não casam serviço.
    assert st._match_servico("foo-123.us-east-1.elb.amazonaws.com") is None
    assert st._match_servico("ec2-1-2-3-4.compute-1.amazonaws.com") is None
    assert st._match_servico("bar.rds.amazonaws.com") is None
    # Endpoints de bucket S3 reais (region-aware) casam:
    assert st._match_servico("bucket.s3.amazonaws.com") is not None
    assert st._match_servico("bucket.s3.us-east-1.amazonaws.com") is not None
    assert st._match_servico("bucket.s3-website-us-east-1.amazonaws.com") is not None


def test_elb_da_aws_nao_gera_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reproduz o FP de mercadolivre: CNAME órfão p/ ELB não vira takeover nem 'possível'.
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["prodeng-internal.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "x-167725658.us-east-1.elb.amazonaws.com")
    ids = _ids(_ctx())
    assert "SUBDOMAIN_TAKEOVER" not in ids
    assert "SUBDOMAIN_TAKEOVER_POSSIVEL" not in ids


def test_s3_orfao_com_fingerprint_ainda_e_critico(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["files.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "meu-bucket.s3.amazonaws.com")

    def handler(method: str, url: str, headers):  # type: ignore[no-untyped-def]
        return make_probe(body="NoSuchBucket - The specified bucket does not exist", final_url=url)

    assert "SUBDOMAIN_TAKEOVER" in _ids(_ctx(client=FakeClient(handler=handler)))


# --------------------------------------------------------------------------- #
# BARREIRA DE ESCOPO. Este checker enumera o Certificate Transparency e dispara GETs
# de verdade. Sem barreira, um alvo em plataforma gerenciada fazia a ferramenta
# enumerar o namespace do PROVEDOR (`github.io`, `amazonaws.com`), requisitar hosts de
# terceiros e emitir CRÍTICO sobre ativo alheio — dentro do relatório do cliente, e sem
# nenhuma declaração de autorização (`--descobrir` é independente de `--autorizado`).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("alvo", "escopo"),
    [
        ("paulo.github.io", "paulo.github.io"),
        ("meu-bucket.s3.amazonaws.com", "meu-bucket.s3.amazonaws.com"),
        ("cliente.blogspot.com", "cliente.blogspot.com"),
        ("cliente.zendesk.com", "cliente.zendesk.com"),  # fora da PSL privada: cai na lista curada
        ("www.empresa.com.br", "empresa.com.br"),  # domínio próprio: escopo é o registrável
    ],
)
def test_ct_nunca_e_consultado_acima_do_alvo_autorizado(
    monkeypatch: pytest.MonkeyPatch, alvo: str, escopo: str
) -> None:
    consultado: list[str] = []

    def _espiao(dominio: str) -> list[str]:
        consultado.append(dominio)
        return []

    monkeypatch.setattr(st, "discover_subdomains", _espiao)
    _ids(_ctx(host=alvo))
    assert consultado == [escopo]


def test_cname_orfao_sem_resposta_e_info(monkeypatch: pytest.MonkeyPatch) -> None:
    # CNAME p/ serviço takeover-able mas sem resposta HTTP -> INFO (dangling), NÃO MEDIUM.
    monkeypatch.setattr(st, "discover_subdomains", lambda _d: ["old.example.com"])
    monkeypatch.setattr(st, "_resolve_cname", lambda _h: "gone.herokudns.com")

    def handler(method: str, url: str, headers):  # type: ignore[no-untyped-def]
        return make_probe(error="ConnectError", status=0, final_url=url)

    findings = list(st.SubdomainTakeoverChecker().run(_ctx(client=FakeClient(handler=handler))))
    poss = [f for f in findings if f.id == "SUBDOMAIN_TAKEOVER_POSSIVEL"]
    assert poss and poss[0].severity.name == "INFO"
