"""Proveniência do laudo: a que CÓDIGO e a que REGRAS este relatório se prende.

Um reteste só é comparável quando os dois laudos declaram contra o que rodaram. O envelope
carregava apenas ``version: "0.1.0"`` — e, sem uma única tag no repositório, esse nome já
designou dezenas de árvores diferentes. Consequência prática: "quatro achados sumiram" era
ambíguo, porque tanto podia ser correção do alvo quanto mudança da regra entre as execuções.

Três selos desfazem a ambiguidade, e cada um responde a uma pergunta distinta:

``commit``
    QUAL código rodou. Ordem de descoberta: ``SENTINELA_COMMIT`` (o CI já sabe o SHA e o
    código instalado por wheel não tem ``.git``) → ``git rev-parse HEAD`` no diretório do
    próprio pacote → ``None``. Ausência de git NUNCA quebra a varredura: ``null`` é a
    resposta honesta "não sei", e é melhor que um laudo que não sai.

``ruleset_hash``
    QUAL catálogo rodou — ids, escala de severidade e taxonomia. Deliberadamente NÃO cobre
    a lógica de detecção: refinar um regex de detecção não muda este hash, e é assim que
    tem de ser, porque para isso existe o ``commit``. Os dois juntos respondem "mudou a
    regra ou mudou o alvo?"; sozinho, nenhum dos dois responde.

``artifact_sha256``
    QUAL documento foi entregue. Calculado sobre o próprio laudo SEM este campo, com a
    receita publicada no docstring de :func:`serializar_com_selo` — hash que o destinatário
    não consegue recalcular sozinho não prova nada.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess  # noqa: S404 - só `git rev-parse`, com argv fixo e sem shell (ver _git_head)
from pathlib import Path

from sentinela.core.models import _SEVERITY_WEIGHTS, Severity
from sentinela.knowledge.mapping import _TAGS, OWASP_EDICAO

_SHA40 = re.compile(r"^[0-9a-f]{40}$")

# Formato do documento canônico do catálogo. Versionado porque mudar a MONTAGEM do texto
# muda todos os hashes sem mudar uma vírgula das regras — quem comparar dois laudos com
# prefixos de versão diferentes tem de saber que a comparação não vale.
_RULESET_FORMATO = "sentinela/ruleset/1"

_TIMEOUT_GIT = 5.0


def descobrir_commit(base: Path | None = None) -> str | None:
    """SHA de 40 hex do código que rodou, ou ``None`` quando não dá para saber.

    ``base`` é o diretório consultado pelo git (padrão: o do próprio pacote, não o
    diretório de trabalho — quem responde é o código que rodou, não a pasta de onde o
    operador chamou a ferramenta).
    """
    do_ambiente = os.environ.get("SENTINELA_COMMIT", "").strip().lower()
    # Valor malformado é IGNORADO, não propagado: carimbar `commit: "HEAD"` ou
    # `commit: "v2"` daria aparência de rastreabilidade a um laudo não rastreável.
    if _SHA40.match(do_ambiente):
        return do_ambiente
    return _git_head(base or Path(__file__).resolve().parent)


def _git_head(base: Path) -> str | None:
    """``git rev-parse HEAD`` em ``base``, tolerante a tudo que pode dar errado.

    Sem git no PATH, fora de um repositório, num repositório sem commits ou com o git
    travado: o resultado é ``None``. Uma varredura jamais falha por causa do carimbo.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - argv fixo, sem shell, sem entrada do alvo
            ["git", "-C", str(base), "rev-parse", "HEAD"],  # noqa: S607 - `git` do PATH, por portabilidade
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_GIT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    saida = proc.stdout.strip().lower()
    return saida if _SHA40.match(saida) else None


def hash_do_catalogo() -> str:
    """``sha256:<hex>`` do catálogo de regras vigente (ids + severidades + taxonomia).

    A severidade de CADA achado não entra — ela é contextual (o mesmo id sai Média ou Alta
    conforme o alvo), e fixá-la aqui seria afirmar o que a ferramenta só sabe depois de
    olhar. O que entra é a ESCALA: mexer no peso de "Alta" muda a nota de todos os laudos
    futuros sem mudar um único achado, e isso é mudança de regra.
    """
    linhas = [_RULESET_FORMATO, f"owasp_edition={OWASP_EDICAO}"]
    linhas += [f"severity {sev.name}={_SEVERITY_WEIGHTS[sev]}" for sev in sorted(Severity)]
    linhas += [
        f"finding {fid} owasp={tag.owasp or ''} cwe={tag.cwe or ''} cwe_name={tag.cwe_name or ''}"
        for fid, tag in sorted(_TAGS.items())
    ]
    documento = "\n".join(linhas).encode("utf-8")
    return f"sha256:{hashlib.sha256(documento).hexdigest()}"


def serializar_com_selo(payload: dict[str, object]) -> str:
    """Serializa o laudo em JSON e o sela com ``artifact_sha256``.

    RECEITA DE VERIFICAÇÃO (quem recebe o arquivo reproduz assim, sem a ferramenta)::

        doc = json.load(open("laudo.json", encoding="utf-8"))
        selo = doc.pop("artifact_sha256")
        calc = hashlib.sha256(
            json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
        ).hexdigest()
        assert calc == selo

    O selo prova NÃO-ADULTERAÇÃO do arquivo, não autenticidade da origem: quem reescrever o
    laudo inteiro recalcula o hash junto. Autenticidade é assinatura, e é outro trabalho.
    """
    corpo = _dumps(payload)
    selo = hashlib.sha256(corpo.encode("utf-8")).hexdigest()
    return _dumps({**payload, "artifact_sha256": selo})


def _dumps(payload: dict[str, object]) -> str:
    """Serialização canônica — as MESMAS opções nas duas passadas, senão o selo não fecha."""
    return json.dumps(payload, ensure_ascii=False, indent=2)
