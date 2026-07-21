# Relatório de Diagnóstico de Segurança — paulo-marcos-lucio.github.io

> Gerado pela **Sentinela v0.1.0** · 21/07/2026 15:14 UTC

| Item | Valor |
| --- | --- |
| Alvo | `https://paulo-marcos-lucio.github.io/` |
| Modo | Não-intrusivo |
| Checagens executadas | 8 |
| Nota de higiene | **70/100 · Conceito C** |

## Sumário executivo

Sem achados críticos ou altos; há oportunidades de endurecimento (hardening) de severidade média/baixa.

| Severidade | Qtd. |
| --- | --- |
| 🔴 Crítica | 0 |
| 🟠 Alta | 0 |
| 🟡 Média | 3 |
| 🔵 Baixa | 2 |
| ⚪ Informativa | 4 |

## Achados

### Cabeçalhos de Segurança

#### 🟡 Content-Security-Policy ausente

**Severidade:** Média · **ID:** `CSP_AUSENTE` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-693** (Protection Mechanism Failure)

A resposta não define uma Content-Security-Policy.

- **Impacto:** A CSP é a defesa em profundidade mais eficaz contra XSS e injeção de conteúdo. Sem ela, qualquer falha de saída não escapada vira execução de script no navegador da vítima.
- **Recomendação:** Implante uma CSP restritiva (idealmente baseada em nonce/hash), começando por `default-src 'self'` e liberando origens sob demanda. Use o modo `Content-Security-Policy-Report-Only` para calibrar sem quebrar o site.
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy) · [ref](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

#### 🟡 Sem proteção contra clickjacking

**Severidade:** Média · **ID:** `CLICKJACKING_SEM_PROTECAO` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-1021** (Improper Restriction of Rendered UI Layers)

Não há `X-Frame-Options` nem a diretiva `frame-ancestors` na CSP.

- **Impacto:** A página pode ser embutida em um <iframe> de um site malicioso (clickjacking), induzindo o usuário a clicar em ações sem perceber.
- **Recomendação:** Defina `Content-Security-Policy: frame-ancestors 'none'` (ou `'self'`) — abordagem moderna — e/ou `X-Frame-Options: DENY`.
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options) · [ref](https://owasp.org/www-project-secure-headers/)

#### 🔵 Referrer-Policy ausente

**Severidade:** Baixa · **ID:** `REFERRER_POLICY_AUSENTE` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-200** (Exposure of Sensitive Information)

O cabeçalho `Referrer-Policy` não foi encontrado na resposta.

- **Impacto:** Sem política de referenciador, URLs internas (com tokens, IDs ou dados sensíveis no path/query) podem vazar para sites de terceiros no cabeçalho Referer.
- **Recomendação:** Defina `Referrer-Policy: strict-origin-when-cross-origin` (ou `no-referrer` para o máximo de privacidade).
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy) · [ref](https://owasp.org/www-project-secure-headers/)

#### 🔵 X-Content-Type-Options ausente

**Severidade:** Baixa · **ID:** `XCTO_AUSENTE` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-693** (Protection Mechanism Failure)

O cabeçalho `X-Content-Type-Options` não foi encontrado na resposta.

- **Impacto:** Sem 'nosniff', o navegador pode tentar adivinhar (MIME sniffing) o tipo de conteúdo e interpretar um arquivo como script, abrindo espaço para XSS a partir de uploads ou respostas mal tipadas.
- **Recomendação:** Envie o cabeçalho `X-Content-Type-Options: nosniff` em todas as respostas.
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options) · [ref](https://owasp.org/www-project-secure-headers/)

#### ⚪ Cross-Origin-Opener-Policy ausente

**Severidade:** Informativa · **ID:** `COOP_AUSENTE` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-693** (Protection Mechanism Failure)

O cabeçalho `Cross-Origin-Opener-Policy` não foi encontrado na resposta.

- **Impacto:** Sem COOP, a página compartilha o mesmo grupo de contexto de navegação com janelas de outras origens, facilitando ataques de canal lateral cross-origin (ex.: Spectre) e manipulação via window.opener.
- **Recomendação:** Defina `Cross-Origin-Opener-Policy: same-origin` em páginas sensíveis.
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy) · [ref](https://owasp.org/www-project-secure-headers/)

#### ⚪ HSTS sem includeSubDomains

**Severidade:** Informativa · **ID:** `HSTS_SEM_SUBDOMINIOS` · **OWASP:** A04:2025 Cryptographic Failures · **CWE-319** (Cleartext Transmission of Sensitive Information)

O HSTS não cobre os subdomínios.

- **Evidência:** `Strict-Transport-Security: max-age=31556952`
- **Impacto:** Subdomínios sem HSTS podem ser usados para ataques de rebaixamento e para plantar/ler cookies do domínio pai.
- **Recomendação:** Adicione a diretiva `includeSubDomains` após validar todos os subdomínios em HTTPS.
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security)

#### ⚪ Permissions-Policy ausente

**Severidade:** Informativa · **ID:** `PERMISSIONS_POLICY_AUSENTE` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-693** (Protection Mechanism Failure)

O cabeçalho `Permissions-Policy` não foi encontrado na resposta.

- **Impacto:** Sem essa política, a página não restringe explicitamente recursos poderosos do navegador (câmera, microfone, geolocalização, etc.), ampliando o impacto de um eventual XSS.
- **Recomendação:** Defina uma `Permissions-Policy` restritiva, desabilitando recursos não usados, ex.: `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
- **Referências:** [ref](https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy) · [ref](https://owasp.org/www-project-secure-headers/)

### DNS / E-mail

#### 🟡 Registro DMARC ausente

**Severidade:** Média · **ID:** `DMARC_AUSENTE` · **OWASP:** A07:2025 Authentication Failures · **CWE-290** (Authentication Bypass by Spoofing)

O domínio `github.io` não publica uma política DMARC.

- **Impacto:** Sem DMARC, mesmo com SPF/DKIM os provedores não sabem o que fazer com e-mails que falham na autenticação, deixando brecha para spoofing.
- **Recomendação:** Publique um registro em `_dmarc.<domínio>` começando por monitoramento (`v=DMARC1; p=none; rua=mailto:...`) e evolua para `p=quarantine` e `p=reject`.
- **Referências:** [ref](https://www.rfc-editor.org/rfc/rfc7489) · [ref](https://dmarc.org/overview/)

#### ⚪ DNSSEC não detectado

**Severidade:** Informativa · **ID:** `DNSSEC_AUSENTE` · **OWASP:** A02:2025 Security Misconfiguration · **CWE-345** (Insufficient Verification of Data Authenticity)

Não foram encontrados registros DNSKEY para `github.io` (zona provavelmente não assinada).

- **Impacto:** Sem DNSSEC, respostas DNS podem ser forjadas (cache poisoning), redirecionando usuários para servidores maliciosos.
- **Recomendação:** Avalie habilitar DNSSEC no provedor de DNS para assinar a zona.
- **Referências:** [ref](https://www.rfc-editor.org/rfc/rfc8659)

---

### Metodologia e limites

Este relatório resulta de checagens **não-intrusivas** (salvo modo intrusivo explicitamente autorizado) que observam o que o servidor expõe a um cliente comum. A nota de higiene é um indicador transparente, **não** um escore CVSS formal, e a ausência de achados não garante inexistência de vulnerabilidades — falhas de lógica, injeção e autorização exigem teste manual dedicado.

Conduzido sob autorização e dentro do escopo acordado, em conformidade com a Lei 12.737/2012, a Lei 14.155/2021, o Marco Civil da Internet (Lei 12.965/2014) e a LGPD (Lei 13.709/2018).
