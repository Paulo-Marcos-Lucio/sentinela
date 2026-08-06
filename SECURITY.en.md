<p align="center"><a href="SECURITY.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/sentinela/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Security Policy and Ethical Use

## Authorized Use

**Sentinela** is a **defensive assessment** tool, intended to analyze
systems that you **own** or for which you have **explicit, written
authorization** to test.

- The **default mode is non-intrusive**: it only observes what the server already exposes to
  any visitor (HTTP headers, TLS handshake, public DNS queries).
- **Intrusive mode** (`--autorizado`) is a deliberate decision made by the operator, who
  declares that they hold authorization. Without this flag, **fuzzing of sensitive routes/files,
  API probing, and verbose-error probing do not run** (these are the checks marked as
  intrusive). Passive checks always run, and the default posture is low-touch —
  subdomain discovery requires `--descobrir`, and the method inventory performs a
  single `OPTIONS`. In short: no fuzzing without `--autorizado`, but "passive" here
  means low impact, not zero packets.

### Legal Framework (Brazil)

Unauthorized access to a computer device is a crime in Brazil:

- **Law 12.737/2012** (the Carolina Dieckmann Law — Article 154-A of the Penal Code): criminalizes
  the invasion of a computer device.
- **Law 14.155/2021**: increased the penalties and removed from the statute the requirement of
  "improper breach of a security mechanism" — that is, access without **express or
  tacit authorization** can constitute a crime even without breaking any controls.
- **Law 12.965/2014** (Marco Civil da Internet) and **Law 13.709/2018**, the LGPD (Brazil's data-protection law, GDPR-equivalent),
  govern privacy and the handling of any personal data that may be encountered.

**Written authorization with a defined scope** (domains/IPs, time window,
permitted techniques) is the element that removes the unlawfulness. Document it before
running any test.

## Responsible Disclosure

Found a vulnerability **in this tool**? Please report it
privately:

- Email: **contatopml26@gmail.com** (subject: `[security] sentinela`)

I kindly ask that you **not** open a public issue before giving us time for a
fix. I acknowledge receipt and work on the fix as a priority, coordinating
disclosure with whoever reported it.

## Scope

This policy covers the code in this repository. It **does not** authorize using the
tool against third parties without consent.
