.PHONY: help install lint format typecheck test check all docker

help:  ## Mostra esta ajuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Instala o pacote em modo editável com dependências de dev
	pip install -e ".[dev]"

lint:  ## Roda o linter (ruff)
	ruff check .

format:  ## Formata o código (ruff format)
	ruff format src tests

typecheck:  ## Verifica tipos (mypy)
	mypy src

test:  ## Roda os testes com cobertura
	pytest --cov=sentinela --cov-report=term-missing

check: lint typecheck test  ## Roda todo o portão de qualidade (lint + tipos + testes)

all: format check  ## Formata e roda o portão de qualidade

docker:  ## Constrói a imagem Docker
	docker build -t sentinela .
