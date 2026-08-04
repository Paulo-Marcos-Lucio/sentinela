"""A imagem base tem de estar fixada por digest.

O repositório prega SHA-pinning — e a Esteira, ferramenta irmã da suíte, COBRA isso de
quem ela audita. O próprio Dockerfile usava `FROM python:3.12-slim`, uma tag móvel: dois
`docker build` do mesmo commit, em semanas diferentes, montavam imagens diferentes. Numa
ferramenta cujo entregável é um laudo, isso desfaz a proveniência inteira — o `commit` no
relatório aponta para um código, mas o intérprete e as bibliotecas do sistema debaixo dele
não são as mesmas duas vezes.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"

# `FROM <imagem>@sha256:<64 hex>` com `AS <estágio>` opcional. Tag antes do digest é
# permitida (documenta a intenção); o que não se admite é digest AUSENTE.
_FROM_FIXADO = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?$")


def _linhas_from() -> list[str]:
    texto = DOCKERFILE.read_text(encoding="utf-8")
    return [linha.strip() for linha in texto.splitlines() if linha.strip().startswith("FROM ")]


def test_toda_imagem_base_e_fixada_por_digest() -> None:
    linhas = _linhas_from()
    assert linhas, "Dockerfile sem nenhuma linha FROM — o teste está olhando para o arquivo errado"
    for linha in linhas:
        assert _FROM_FIXADO.match(linha), f"imagem base em tag móvel: {linha!r}"


def test_os_dois_estagios_usam_exatamente_a_mesma_imagem() -> None:
    # O estágio final COPIA `site-packages` do estágio de build. Se os dois flutuarem para
    # digests diferentes, a cópia cai sobre um Python de outra compilação — e o defeito
    # aparece só em tempo de execução, dentro do contêiner do cliente.
    digests = {linha.split("@", 1)[1].split()[0] for linha in _linhas_from()}
    assert len(digests) == 1, f"estágios com imagens base diferentes: {sorted(digests)}"
