# Imagem enxuta para rodar a Sentinela sem instalar Python localmente.
#
# A base é fixada por DIGEST, não por tag. Com `python:3.12-slim`, dois `docker build` do
# mesmo commit em semanas diferentes montavam imagens diferentes — e num produto cujo
# entregável é um laudo isso desfaz a proveniência: o campo `commit` do relatório aponta
# para um código, mas o intérprete e as bibliotecas de sistema debaixo dele não são os
# mesmos duas vezes. É a mesma exigência que a Esteira faz de quem ela audita.
#
# O digest é o do ÍNDICE multi-arquitetura (16 plataformas), não o de uma delas: fixar o
# manifesto de amd64 quebraria a construção em arm64.
#
# Para atualizar (revisar a cada atualização de segurança do Debian/Python):
#   docker buildx imagetools inspect python:3.12-slim   # digest do índice
#   docker manifest inspect -v python:3.12-slim         # alternativa, por plataforma
# Verificado em 2026-08-04: resolve para python 3.12.13-slim-trixie.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS build

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ----------------------------------------------------------------------------
# MESMO digest do estágio de build, e não por estética: o estágio final copia o
# `site-packages` de lá. Dois digests diferentes fariam a cópia cair sobre um Python de
# outra compilação, com o defeito aparecendo só dentro do contêiner do cliente.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# Usuário não-root: uma ferramenta de segurança não deve rodar como root.
RUN useradd --create-home --uid 10001 sentinela

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/sentinela /usr/local/bin/sentinela

USER sentinela
WORKDIR /home/sentinela

ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1
ENTRYPOINT ["sentinela"]
CMD ["--help"]
