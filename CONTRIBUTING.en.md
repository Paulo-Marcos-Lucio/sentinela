<p align="center"><a href="CONTRIBUTING.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/sentinela/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Contributing to Sentinela

Thank you for your interest! Contributions — issues, fixes, new checks — are
welcome.

## Development Environment

```bash
git clone https://github.com/Paulo-Marcos-Lucio/sentinela.git
cd sentinela
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Quality Gate

Before opening a Pull Request, make sure everything passes:

```bash
make check     # equivalent to: ruff check . && mypy src && pytest
make format    # formats with ruff
```

CI runs lint (ruff), formatting, type checks (mypy strict), and tests (pytest) on
Python 3.10–3.13. PRs must pass all of them. In addition, a self-audit job
runs Sentinela itself against a local target (dogfooding), CodeQL analyzes
the code, and dependency review blocks vulnerable packages in the PR.

## Adding a New Check

The architecture makes this simple and isolated:

1. Create a file in `src/sentinela/checks/` with a class inheriting from `Checker`.
2. Declare `id`, `name`, `category`, and `intrusive`, and implement `run(ctx)`.
3. **Never** raise an exception on network failure — handle the case and do not generate a finding.
4. If the check sends requests beyond passive reading, mark `intrusive = True`.
5. Register the class in `core/registry.py`.
6. Add the finding's taxonomy (OWASP/CWE) in `knowledge/mapping.py`.
7. Write offline tests in `tests/` (use the helpers from `conftest.py`).

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`.

## Principles

- **Non-intrusive by default.** New active checks are gated behind `--autorizado`.
- **No gratuitous false positives.** Prefer a content signature over trusting a 200 status.
- **Honest severity.** A missing header is rarely "High"; don't inflate it to impress.
