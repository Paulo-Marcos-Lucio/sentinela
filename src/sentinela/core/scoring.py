"""Nota de higiene de segurança (0–100) e conceito (A–F).

Importante: esta **não** é uma pontuação de risco formal. É uma métrica
indicativa e transparente, derivada dos achados por um algoritmo simples e
auditável — justamente para não cair no anti-padrão de prometer um número
"científico" de risco. Serve para comunicar tendência ao cliente, não para
substituir uma análise de risco completa.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinela.core.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class Score:
    value: int  # 0–100
    grade: str  # A, B, C, D ou F
    summary: str

    @property
    def color(self) -> str:
        return {
            "A": "#3fb950",
            "B": "#56d364",
            "C": "#d29922",
            "D": "#ff7b72",
            "F": "#f85149",
        }.get(self.grade, "#8b949e")


def _grade_for(value: int) -> str:
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 60:
        return "C"
    if value >= 45:
        return "D"
    return "F"


# Achados que QUEBRAM a confiança no canal e devem TETAR a nota em F: um navegador
# bloqueia o acesso (cert inválido) ou nem chegamos a avaliar (alvo inacessível).
# Somar/subtrair pesos aqui inverteria o sinal — um cert morto pontuaria acima de um
# site bem operado. Ver auditoria de campo 2026-07-22.
_CERT_QUEBRADO = frozenset({"CERT_EXPIRADO", "CERT_NAO_CONFIAVEL", "CERT_HOSTNAME_INVALIDO"})

# Frase que acompanha o teto de CONCEITO — sem ela, "80/100 · conceito D" parece bug.
_AVISO_TETO_CONCEITO = (
    " O conceito está limitado por gravidade: a nota numérica mede higiene, o conceito "
    "reprova pela presença de achado grave (como num exame prático — acerta 90% dos "
    "pontos e reprova direto por avançar o sinal vermelho)."
)


def _teto_de_conceito(grade: str, findings: list[Finding]) -> str:
    """Limita o CONCEITO pela pior severidade presente, sem tocar no VALOR.

    Motivo: um `.env` de produção publicado na internet lia "conceito C" — 100 − 40 = 60.
    O defeito não é a aritmética (que continua reconstruível à mão), é o RÓTULO. Tetar o
    VALOR resolveria o rótulo mas achataria 16–21 pontos de faixa: o cliente que corrige
    5 achados baixos não veria a nota mover, justamente no regime em que ele está pagando
    para remediar. Tetar só o conceito dá a mesma garantia de produto de graça.
    """
    if any(f.severity is Severity.CRITICAL for f in findings):
        return "F"
    if any(f.severity is Severity.HIGH for f in findings) and grade in ("A", "B", "C"):
        return "D"
    return grade


def compute_score(findings: list[Finding]) -> Score:
    """Calcula a nota subtraindo de 100 os pesos de cada achado.

    Achados informativos não penalizam. O piso é 0. O cálculo é intencionalmente
    linear e explicável — qualquer cliente consegue reconstruí-lo à mão. Duas
    exceções TETAM a nota em F, porque penalidade linear inverteria o sinal:
    (1) alvo inacessível (não foi possível avaliar → a nota não pode ser boa);
    (2) falha de confiança no certificado (o navegador bloqueia o acesso).

    Além disso, o CONCEITO (só ele, nunca o valor) é limitado pela pior severidade:
    qualquer achado CRÍTICO reprova em F; qualquer achado ALTO limita o conceito a D.
    """
    penalty = sum(f.severity.weight for f in findings)
    value = max(0, 100 - penalty)
    ids = {f.id for f in findings}
    inacessivel = "ALVO_INACESSIVEL" in ids
    cert_quebrado = bool(ids & _CERT_QUEBRADO)

    if inacessivel or cert_quebrado:
        value = min(value, 40)  # coerente com a faixa F (<45)
        grade = "F"
    else:
        grade = _grade_for(value)
    grade_por_valor = grade
    grade = _teto_de_conceito(grade, findings)

    if inacessivel:
        summary = (
            "Não foi possível estabelecer a conexão principal com o alvo — a avaliação da "
            "superfície ficou incompleta. A nota reflete a impossibilidade de verificação, "
            "não um veredito de segurança."
        )
        return Score(value=value, grade=grade, summary=summary)
    if cert_quebrado:
        summary = (
            "Falha de confiança no certificado TLS: o navegador bloqueia o acesso e a "
            "identidade do servidor não é garantida. Corrigir o certificado é pré-requisito "
            "para qualquer outra avaliação."
        )
        return Score(value=value, grade=grade, summary=summary)

    actionable = [f for f in findings if f.severity is not Severity.INFO]
    if not actionable:
        summary = (
            "Nenhum problema acionável identificado pelas checagens não-intrusivas. "
            "Higiene de segurança sólida na superfície analisada."
        )
    else:
        criticos = sum(1 for f in findings if f.severity is Severity.CRITICAL)
        altos = sum(1 for f in findings if f.severity is Severity.HIGH)
        if criticos:
            summary = (
                f"{criticos} achado(s) crítico(s) exigem ação imediata antes de qualquer outra correção."
            )
        elif altos:
            summary = (
                f"{altos} achado(s) de severidade alta representam risco relevante e devem ser priorizados."
            )
        else:
            summary = (
                "Sem achados críticos ou altos; há oportunidades de endurecimento "
                "(hardening) de severidade média/baixa."
            )
    if grade != grade_por_valor:
        summary += _AVISO_TETO_CONCEITO

    return Score(value=value, grade=grade, summary=summary)
