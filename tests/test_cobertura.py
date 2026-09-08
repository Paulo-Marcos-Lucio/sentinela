"""Cobertura da varredura e seu efeito na nota (achado 1.2 da auditoria 2026-09-07).

O buraco: `--somente` / `--perfil rapido` levavam o mesmo alvo de F/exit 1 a A/exit 0
sem uma linha dizendo o que ficou de fora. A correção tem três invariantes, todos aqui:
(1) o resumo só diz "higiene sólida" quando a cobertura foi plena;
(2) varredura parcial não emite conceito A;
(3) omissão intrusiva-por-modo NÃO é lacuna — senão nenhuma varredura padrão tiraria A.
"""

from __future__ import annotations

from sentinela.core.config import ScanConfig
from sentinela.core.coverage import Coverage, compute_coverage
from sentinela.core.models import Category, Finding, ScanError, Severity
from sentinela.core.scoring import compute_score

# (id, intrusiva) — registro sintético, para não depender do conjunto real de checagens.
_TODOS = [
    ("security-headers", False),
    ("tls", False),
    ("dns-email", False),
    ("well-known", False),
    ("exposure", True),
]


def _cfg(**kw: object) -> ScanConfig:
    return ScanConfig(**kw)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# compute_coverage: o que conta como parcial
# --------------------------------------------------------------------------- #
def test_varredura_completa_nao_intrusiva_e_plena() -> None:
    # As 4 não-intrusivas rodaram; a intrusiva foi pulada por MODO, não por lacuna.
    cov = compute_coverage(
        _cfg(),
        checks_run=["security-headers", "tls", "dns-email", "well-known"],
        errors=[],
        todos=_TODOS,
    )
    assert cov.plena and not cov.parcial
    assert cov.por_modo == ("exposure",)
    assert cov.base_total == 4


def test_somente_reduz_a_cobertura_e_e_parcial() -> None:
    cov = compute_coverage(
        _cfg(only=frozenset({"security-headers"})),
        checks_run=["security-headers"],
        errors=[],
        todos=_TODOS,
    )
    assert cov.parcial
    assert set(cov.por_operador) == {"tls", "dns-email", "well-known"}


def test_checagem_que_falhou_torna_parcial_por_erro() -> None:
    cov = compute_coverage(
        _cfg(),
        checks_run=["security-headers", "well-known"],
        errors=[ScanError("tls", "timeout"), ScanError("dns-email", "sem resolvedor")],
        todos=_TODOS,
    )
    assert cov.parcial
    assert set(cov.por_erro) == {"tls", "dns-email"}
    assert not cov.por_operador  # o que faltou faltou por erro, não por escolha


def test_intrusiva_pulada_por_modo_nao_torna_parcial() -> None:
    # A regra-chave: se contasse, nenhuma varredura padrão tiraria A.
    cov = compute_coverage(
        _cfg(),
        checks_run=["security-headers", "tls", "dns-email", "well-known"],
        errors=[],
        todos=_TODOS,
    )
    assert not cov.parcial
    assert "exposure" in cov.por_modo


def test_modo_autorizado_traz_a_intrusiva_para_a_base() -> None:
    cov = compute_coverage(
        _cfg(intrusive=True),
        checks_run=["security-headers", "tls", "dns-email", "well-known", "exposure"],
        errors=[],
        todos=_TODOS,
    )
    assert cov.plena and cov.por_modo == ()
    assert cov.base_total == 5


# --------------------------------------------------------------------------- #
# compute_score: os tetos
# --------------------------------------------------------------------------- #
def _cov_parcial() -> Coverage:
    return Coverage(
        executadas=("security-headers",),
        por_operador=("tls", "dns-email"),
        por_modo=("exposure",),
        por_erro=(),
    )


def _cov_plena() -> Coverage:
    return Coverage(
        executadas=("security-headers", "tls", "dns-email", "well-known"),
        por_operador=(),
        por_modo=("exposure",),
        por_erro=(),
    )


def test_cobertura_plena_e_sem_achado_pode_tirar_A() -> None:
    score = compute_score([], _cov_plena())
    assert score.grade == "A" and score.value == 100
    assert "sólida" in score.summary.lower()


def test_cobertura_parcial_sem_achado_nao_tira_A() -> None:
    # Invariante 2: parcial não certifica A. _cov_parcial roda 1 de 3 checagens da base
    # (frac ≈ .33 < .5) ⇒ o teto que ESCALA rebaixa até D, não só um degrau A→B.
    score = compute_score([], _cov_parcial())
    assert score.grade == "D"
    # Invariante 1: o resumo nomeia o que ficou de fora, não diz "sólida".
    assert "sólida" not in score.summary.lower()
    assert "parcial" in score.summary.lower()
    assert "tls" in score.summary and "dns-email" in score.summary


# --------------------------------------------------------------------------- #
# Teto de cobertura ESCALA com a fração executada (não é um degrau fixo A→B).
# --------------------------------------------------------------------------- #
def _cov_frac(executadas: int, omitidas: int) -> Coverage:
    """Cobertura parcial com fração controlada: `executadas`/(executadas+omitidas)."""
    base = [f"chk-{i}" for i in range(executadas + omitidas)]
    return Coverage(
        executadas=tuple(base[:executadas]),
        por_operador=tuple(base[executadas:]),
        por_modo=(),
        por_erro=(),
    )


def test_teto_de_cobertura_escala_com_a_fracao() -> None:
    # Mesmo conjunto (vazio) de achados; só a fração de checagens executada muda.
    assert compute_score([], _cov_frac(3, 1)).grade == "B"  # frac .75 ⇒ teto B
    assert compute_score([], _cov_frac(2, 2)).grade == "C"  # frac .50 ⇒ teto C
    assert compute_score([], _cov_frac(1, 3)).grade == "D"  # frac .25 ⇒ teto D
    assert compute_score([], _cov_frac(1, 9)).grade == "D"  # frac .10 ⇒ nunca melhor que D


def test_conceito_nunca_melhora_quando_a_fracao_cai() -> None:
    # Invariante de monotonicidade: com achados fixos, reduzir a cobertura nunca eleva o
    # conceito. (A ordem A<B<C<D<F é crescente em severidade.)
    ordem = "ABCDF"
    fracoes = [_cov_frac(9, 1), _cov_frac(3, 1), _cov_frac(2, 2), _cov_frac(1, 3)]
    graus = [ordem.index(compute_score([], cov).grade) for cov in fracoes]
    assert graus == sorted(graus), graus  # não decresce em severidade conforme a fração cai


def test_teto_de_cobertura_nunca_eleva_conceito_ja_pior() -> None:
    # Nota-por-valor já em C (4 MÉDIOS = -32 ⇒ 68) com cobertura alta (teto B): o teto NÃO
    # promove C para B. `_pior_conceito` sempre mantém o pior dos dois.
    medios = [
        Finding(
            id=f"CSP_ESTILO_INLINE_{i}",
            title="x",
            category=Category.HEADERS,
            severity=Severity.MEDIUM,
            description="d",
            recommendation="r",
        )
        for i in range(4)
    ]
    score = compute_score(medios, _cov_frac(3, 1))  # frac .75 ⇒ teto B
    assert score.value == 68 and score.grade == "C"


def test_sem_cobertura_mantem_comportamento_antigo() -> None:
    # Retrocompatível: quem chama só com achados (testes antigos, chamadas diretas).
    score = compute_score([])
    assert score.grade == "A" and score.value == 100


def test_teto_de_cobertura_nao_eleva_F() -> None:
    # Um achado crítico teta em F; a cobertura parcial não pode "promover" para B.
    critico = Finding(
        id="EXFILTRACAO_DE_DADOS",
        title="x",
        category=Category.EXPOSURE,
        severity=Severity.CRITICAL,
        description="d",
        recommendation="r",
    )
    score = compute_score([critico], _cov_parcial())
    assert score.grade == "F"


def test_achado_acionavel_com_cobertura_parcial_menciona_lacuna() -> None:
    medio = Finding(
        id="CSP_ESTILO_INLINE",
        title="x",
        category=Category.HEADERS,
        severity=Severity.MEDIUM,
        description="d",
        recommendation="r",
    )
    score = compute_score([medio], _cov_parcial())
    assert "parcial" in score.summary.lower()
    assert "tls" in score.summary
