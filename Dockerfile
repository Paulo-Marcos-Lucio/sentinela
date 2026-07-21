# Imagem enxuta para rodar a Sentinela sem instalar Python localmente.
FROM python:3.12-slim AS build

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ----------------------------------------------------------------------------
FROM python:3.12-slim

# Usuário não-root: uma ferramenta de segurança não deve rodar como root.
RUN useradd --create-home --uid 10001 sentinela

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/sentinela /usr/local/bin/sentinela

USER sentinela
WORKDIR /home/sentinela

ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1
ENTRYPOINT ["sentinela"]
CMD ["--help"]
