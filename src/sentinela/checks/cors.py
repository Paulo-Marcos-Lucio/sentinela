"""Detecção de configurações inseguras de CORS.

Envia UMA requisição extra com um cabeçalho ``Origin`` forjado e observa como o
servidor responde em ``Access-Control-Allow-Origin`` (ACAO) e
``Access-Control-Allow-Credentials`` (ACAC). É uma sonda de baixo impacto (uma
requisição GET), considerada não-intrusiva.
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Origem de teste, deliberadamente estranha ao alvo, para detectar reflexão.
_PROBE_ORIGIN = "https://sentinela-cors-probe.example"


class CorsChecker(Checker):
    id = "cors"
    name = "Configuração de CORS"
    category = Category.CORS
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        probe = ctx.client.get(ctx.target.url, headers={"Origin": _PROBE_ORIGIN})
        if not probe.ok:
            return

        acao = probe.header("Access-Control-Allow-Origin")
        acac = (probe.header("Access-Control-Allow-Credentials") or "").lower() == "true"
        if acao is None:
            return  # sem CORS habilitado para esta origem — nada a relatar

        reflete = acao.strip() == _PROBE_ORIGIN
        curinga = acao.strip() == "*"

        if reflete and acac:
            yield Finding(
                id="CORS_REFLEXAO_COM_CREDENCIAIS",
                title="CORS reflete qualquer origem com credenciais",
                category=self.category,
                severity=Severity.HIGH,
                description=(
                    "O servidor refletiu a origem arbitrária enviada e ainda "
                    "permite credenciais (`Access-Control-Allow-Credentials: true`)."
                ),
                evidence=f"Origin: {_PROBE_ORIGIN} → Access-Control-Allow-Origin: {acao}",
                impact=(
                    "Qualquer site controlado por um atacante pode fazer requisições "
                    "autenticadas à API em nome da vítima e ler as respostas — "
                    "vazamento de dados e ações não autorizadas."
                ),
                recommendation=(
                    "Nunca reflita a origem cegamente. Valide `Origin` contra uma "
                    "allowlist estrita e só então ecoe o valor; combine com "
                    "credentials apenas para origens confiáveis."
                ),
                references=(ref.MDN_CORS, ref.OWASP_CORS),
            )
        elif curinga and acac:
            # Navegadores bloqueiam '*' + credentials, mas indica config equivocada.
            yield Finding(
                id="CORS_CURINGA_COM_CREDENCIAIS",
                title="CORS com curinga e credenciais",
                category=self.category,
                severity=Severity.MEDIUM,
                description=(
                    "A política combina `Access-Control-Allow-Origin: *` com credenciais habilitadas."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}; credentials=true",
                impact=(
                    "Configuração contraditória: sinaliza intenção de expor a API "
                    "amplamente. Ainda que o navegador rejeite a combinação, revela "
                    "uma política de CORS mal desenhada e propensa a erros."
                ),
                recommendation="Restrinja a uma allowlist explícita de origens confiáveis.",
                references=(ref.MDN_CORS, ref.OWASP_CORS),
            )
        elif reflete:
            yield Finding(
                id="CORS_REFLEXAO_ORIGEM",
                title="CORS reflete origem arbitrária",
                category=self.category,
                severity=Severity.LOW,
                description="O servidor ecoa qualquer `Origin` recebida, sem credenciais.",
                evidence=f"Origin: {_PROBE_ORIGIN} → Access-Control-Allow-Origin: {acao}",
                impact=(
                    "Sem credenciais o risco é menor, mas refletir qualquer origem "
                    "ainda expõe respostas a sites de terceiros e costuma ser sintoma "
                    "de configuração permissiva demais."
                ),
                recommendation="Valide `Origin` contra uma allowlist em vez de refletir.",
                references=(ref.MDN_CORS, ref.OWASP_CORS),
            )
