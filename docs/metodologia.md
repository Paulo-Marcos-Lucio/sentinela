# Metodologia

Este documento explica **como** a Sentinela chega aos seus achados e, igualmente
importante, **onde ela para** — porque um bom diagnóstico é honesto sobre seus limites.

## 1. Princípio: não-intrusivo por padrão

A varredura padrão observa apenas o que o servidor **já entrega** a qualquer cliente:

- Cabeçalhos de resposta HTTP (uma requisição `GET`).
- O handshake TLS e o certificado apresentado (nenhum payload é enviado à aplicação).
- Consultas DNS públicas (SPF, DMARC, CAA, DNSSEC).
- Uma requisição `OPTIONS` para enumerar métodos e uma com `Origin` forjada para avaliar CORS.

Nenhuma dessas ações tenta explorar, alterar estado, adivinhar credenciais ou
extrair dados. É o equivalente digital de olhar a fachada de um prédio da calçada.

### Modo intrusivo (opt-in)

A sondagem de rotas sensíveis (`/.git`, `/.env`, etc.) envia requisições que vão
além da leitura passiva. Por isso ela **só roda com `--autorizado`** — uma trava
técnica que reflete uma exigência ética e legal (ver [SECURITY.md](../SECURITY.md)).

## 2. Severidade ancorada no CVSS

Cada achado recebe uma severidade qualitativa alinhada às faixas do CVSS
(idênticas em v3.1 e v4.0):

| Severidade | Faixa CVSS | Significado |
| --- | --- | --- |
| 🔴 Crítica | 9.0–10.0 | Ação imediata; risco direto e alto. |
| 🟠 Alta | 7.0–8.9 | Risco relevante; priorizar. |
| 🟡 Média | 4.0–6.9 | Endurecimento importante. |
| 🔵 Baixa | 0.1–3.9 | Defesa em profundidade / higiene. |
| ⚪ Informativa | 0.0 | Boa prática, sem impacto explorável direto. |

> **Calibragem honesta:** a ausência de um cabeçalho isolado raramente é "Alta". A
> Sentinela evita inflar severidade — o valor de um diagnóstico está na confiança
> que ele merece.

## 3. Mapeamento OWASP Top 10:2025 + CWE

Cada achado é classificado contra a edição **vigente** do OWASP Top 10 (2025, versão
final de janeiro de 2026) e recebe um **CWE** específico, mais estável entre versões
do Top 10. As checagens não-intrusivas concentram sinal em duas categorias:

- **A02:2025 Security Misconfiguration** — cabeçalhos, CORS, métodos, exposição de arquivos.
- **A04:2025 Cryptographic Failures** — TLS/certificado, HSTS, cookies sem `Secure`.

Sinais parciais tocam **A01** (CORS/CSRF), **A07** (autenticação/e-mail spoofing) e outras.

## 4. Nota de higiene (0–100)

A nota parte de 100 e subtrai um peso por achado, conforme a severidade
(Crítica −40, Alta −20, Média −8, Baixa −3, Informativa 0), com piso em 0. O
conceito segue: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 45, **F** < 45.

É um indicador **transparente e reprodutível** — qualquer cliente consegue
reconstruí-lo à mão. **Não** é um escore CVSS formal nem uma medida de risco
completa; serve para comunicar tendência.

## 5. Limites (o que a Sentinela NÃO faz)

Um diagnóstico de configuração **não substitui** um pentest manual. Ficam de fora
do modo não-intrusivo:

- Injeção (SQLi, XSS confirmado, template injection) — exige teste ativo.
- Falhas de lógica de negócio e de autorização (IDOR, escalonamento).
- Autenticação e gestão de sessão sob ataque.
- Vulnerabilidades específicas de versão sem sinal externo.

A ausência de achados **não** significa "sem vulnerabilidades" — significa "sem
problemas de configuração/higiene na superfície analisada".
