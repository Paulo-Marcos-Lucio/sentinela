# Contribuindo com a Sentinela

Obrigado pelo interesse! Contribuições — issues, correções, novas checagens — são
bem-vindas.

## Ambiente de desenvolvimento

```bash
git clone https://github.com/Paulo-Marcos-Lucio/sentinela.git
cd sentinela
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Portão de qualidade

Antes de abrir um Pull Request, garanta que tudo passa:

```bash
make check     # equivale a: ruff check . && mypy src && pytest
make format    # formata com ruff
```

O CI roda lint (ruff), formatação, tipos (mypy strict) e testes (pytest) em
Python 3.10–3.13. PRs precisam passar em todos. Além disso, um job de
autoauditoria roda a própria Sentinela contra um alvo local (dogfood), o
CodeQL analisa o código e a revisão de dependências barra pacote vulnerável no PR.

## Adicionando uma nova checagem

A arquitetura torna isso simples e isolado:

1. Crie um arquivo em `src/sentinela/checks/` com uma classe herdando de `Checker`.
2. Declare `id`, `name`, `category` e `intrusive`, e implemente `run(ctx)`.
3. **Nunca** levante exceção por falha de rede — trate o caso e não gere achado.
4. Se a checagem envia requisições além da leitura passiva, marque `intrusive = True`.
5. Registre a classe em `core/registry.py`.
6. Adicione a taxonomia (OWASP/CWE) do achado em `knowledge/mapping.py`.
7. Escreva testes offline em `tests/` (use os helpers de `conftest.py`).

## Convenção de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`.

## Princípios

- **Não-intrusivo por padrão.** Novas checagens ativas entram apenas sob `--autorizado`.
- **Sem falsos-positivos gratuitos.** Prefira uma assinatura de conteúdo a confiar num status 200.
- **Severidade honesta.** Header ausente raramente é "Alto"; não infle para impressionar.
