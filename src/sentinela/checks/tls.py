"""Inspeção de TLS e do certificado do servidor.

Faz um handshake TLS de baixo nível (sem baixar conteúdo) para avaliar:
versão de protocolo negociada, aceitação de protocolos legados, validade e
expiração do certificado, correspondência de hostname, chave fraca e algoritmo
de assinatura obsoleto. Tudo defensivo: qualquer erro inesperado resulta em
"não avaliado", nunca em exceção propagada.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from sentinela.checks._util import is_ip, truncate
from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Timeout por handshake. Servidor OK responde em <1s; o teto só é atingido em host
# lento/que descarta a conexão em silêncio — por isso as conexões rodam em PARALELO
# (o check inteiro fica limitado a UM handshake, não à soma de quatro).
_HANDSHAKE_TIMEOUT = 6.0

# Tolerância antes de desconfiar do relógio local. Uma hora cobre fuso mal configurado
# e a imprecisão normal do cabeçalho `Date`; acima disso, os achados de expiração de
# certificado deste relatório deixam de ser confiáveis.
_DERIVA_MAXIMA_SEGUNDOS = 3600.0


class TlsChecker(Checker):
    id = "tls"
    name = "TLS e certificado"
    category = Category.TLS
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        host = ctx.target.host
        port = ctx.target.port if ctx.target.is_https else 443

        # As conexões TLS são independentes → em paralelo, evitando um host lento
        # transformar 4×timeout em ~40s (o que travaria uma demo).
        alvo_e_ip = is_ip(host)
        # Honra o --timeout do operador (agilidade de demo) mantendo o teto de 6s por handshake.
        timeout = min(ctx.config.timeout, _HANDSHAKE_TIMEOUT)
        with ThreadPoolExecutor(max_workers=3) as pool:
            cert_future = pool.submit(_fetch_certificate, host, port, timeout)
            # Alvo IP puro: a validação de cadeia por hostname não se aplica (o navegador
            # casaria contra IP SAN); a checagem de hostname abaixo já cobre o IP SAN.
            trust_future = None if alvo_e_ip else pool.submit(_trust_error, host, port, timeout)
            legacy_future = pool.submit(_accepts_legacy_tls, host, port, timeout)
            der, tls_version, tls_cipher = cert_future.result()
            trust_error = trust_future.result() if trust_future is not None else None
            legados, legados_nao_avaliados = legacy_future.result()

        if der is None:
            return  # sem endpoint TLS acessível — não é papel desta checagem relatar
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            return

        yield from self._check_relogio(ctx)
        yield from self._check_expiry(cert)
        yield from self._check_hostname(cert, host)
        yield from self._check_key_and_signature(cert)
        if trust_error is not None:
            yield Finding(
                id="CERT_NAO_CONFIAVEL",
                title="Certificado não confiável",
                category=self.category,
                severity=Severity.HIGH,
                description="A validação padrão do certificado falhou (cadeia não confiável).",
                evidence=trust_error,
                impact=(
                    "Certificados autoassinados ou de cadeia incompleta fazem o "
                    "navegador alertar o usuário e comprometem a confiança na conexão."
                ),
                recommendation="Use um certificado emitido por uma CA reconhecida e envie a cadeia completa.",
                references=(ref.OWASP_TLS_CHEATSHEET, ref.MOZILLA_SSL_CONFIG),
            )
        yield from self._check_protocols(legados, legados_nao_avaliados)
        yield from self._check_tls_hardening(tls_version, tls_cipher)

    def _check_relogio(self, ctx: ScanContext) -> Iterable[Finding]:
        """Compara o relógio local com o do alvo, porque a validade do certificado é
        medida contra o relógio DESTA máquina.

        Um relógio adiantado transforma um certificado impecável em `CERT_EXPIRANDO`
        (média) ou `CERT_EXPIRADO` (alta, que teta a nota em F). Medido: o mesmo
        certificado sintético de 90 dias dá A com o relógio certo e F com ele 120 dias
        à frente. O `Date` da resposta HTTP é uma segunda fonte gratuita, e discordância
        grande entre as duas é motivo para desconfiar do laudo antes de entregá-lo.
        """
        remoto = _data_do_servidor(ctx.primary.header("Date"))
        if remoto is None:
            return
        # Uma resposta servida de CACHE carrega o `Date` de quando foi GERADA na origem, não
        # "agora" — e um `Date` antigo compensado por `Age` (CDN) NÃO é deriva de relógio. Sem
        # tratar isso, todo Hit de borda (Date de horas atrás, Age igual) virava um falso
        # RELOGIO_LOCAL_DIVERGENTE. Duas defesas para a MESMA classe:
        #   (1) RFC 7234: o relógio da origem ≈ Date + Age. Corrigimos antes de comparar.
        #   (2) se a resposta se declara um HIT de cache (X-Cache/CF-Cache-Status), o `Date`
        #       não é fonte confiável de relógio — abstemo-nos em vez de acusar.
        if _resposta_de_cache_hit(ctx.primary):
            return
        origem = remoto + timedelta(seconds=_idade_da_resposta(ctx.primary.header("Age")))
        deriva = abs((datetime.now(timezone.utc) - origem).total_seconds())
        if deriva < _DERIVA_MAXIMA_SEGUNDOS:
            return
        yield Finding(
            id="RELOGIO_LOCAL_DIVERGENTE",
            title="Relógio desta máquina diverge do relógio do alvo",
            category=self.category,
            severity=Severity.INFO,
            description=(
                f"O cabeçalho `Date` do alvo está {deriva / 3600:.1f} h distante do relógio local."
            ),
            evidence=f"Date do alvo: {remoto.isoformat()} · local: {datetime.now(timezone.utc).isoformat()}",
            impact=(
                "A validade do certificado é avaliada contra o relógio local. Com essa "
                "diferença, os achados de expiração deste relatório podem estar errados nos "
                "dois sentidos: acusar um certificado válido ou absolver um vencido."
            ),
            recommendation=(
                "Sincronize o relógio da máquina (NTP) e rode a varredura de novo antes de "
                "usar este relatório como evidência."
            ),
            references=(ref.MOZILLA_TLS,),
        )

    def _check_expiry(self, cert: x509.Certificate) -> Iterable[Finding]:
        not_after = _not_valid_after(cert)
        now = datetime.now(timezone.utc)
        dias = (not_after - now).days

        if not_after < now:
            yield Finding(
                id="CERT_EXPIRADO",
                title="Certificado TLS expirado",
                category=self.category,
                severity=Severity.HIGH,
                description="O certificado do servidor já venceu.",
                evidence=f"Expirou em {not_after.date().isoformat()}",
                impact=(
                    "Navegadores exibem tela de erro bloqueando o acesso, e o "
                    "certificado deixa de garantir a identidade do servidor."
                ),
                recommendation="Renove o certificado imediatamente e automatize a renovação (ex.: ACME/Let's Encrypt).",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )
        elif dias <= 15:
            yield Finding(
                id="CERT_EXPIRANDO",
                title="Certificado TLS próximo do vencimento",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O certificado vence em {dias} dia(s).",
                evidence=f"Expira em {not_after.date().isoformat()}",
                impact="Se não renovado a tempo, o site ficará inacessível para os usuários.",
                recommendation="Renove antecipadamente e configure renovação automática com alertas.",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )

    def _check_hostname(self, cert: x509.Certificate, host: str) -> Iterable[Finding]:
        if is_ip(host):
            ip_sans = _san_ip_names(cert)
            if ip_sans and host not in ip_sans:
                yield Finding(
                    id="CERT_HOSTNAME_INVALIDO",
                    title="Certificado não cobre o IP acessado",
                    category=self.category,
                    severity=Severity.HIGH,
                    description="O IP acessado não consta como IP SAN no certificado.",
                    evidence=f"host={host} · IP SANs={', '.join(ip_sans[:5])}",
                    impact=(
                        "Um certificado que não corresponde ao endereço quebra a garantia "
                        "de identidade e faz o navegador bloquear a conexão."
                    ),
                    recommendation="Acesse o serviço pelo hostname coberto pelo certificado, "
                    "ou emita um certificado com o IP no SAN.",
                    references=(ref.OWASP_TLS_CHEATSHEET,),
                )
            return  # não comparar IP contra SANs de DNS (geraria falso-positivo)
        names = _san_dns_names(cert)
        if names and not _hostname_matches(host, names):
            yield Finding(
                id="CERT_HOSTNAME_INVALIDO",
                title="Certificado não cobre o hostname",
                category=self.category,
                severity=Severity.HIGH,
                description="O hostname acessado não consta no certificado (SAN).",
                evidence=f"host={host} · SAN={', '.join(names[:5])}",
                impact=(
                    "Um certificado que não corresponde ao domínio quebra a garantia "
                    "de identidade e faz o navegador bloquear a conexão."
                ),
                recommendation="Emita um certificado cujo SAN inclua exatamente o domínio servido.",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )

    def _check_key_and_signature(self, cert: x509.Certificate) -> Iterable[Finding]:
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            yield Finding(
                id="CERT_CHAVE_FRACA",
                title="Chave RSA fraca no certificado",
                category=self.category,
                severity=Severity.HIGH,
                description=f"A chave pública RSA tem apenas {key.key_size} bits.",
                evidence=f"RSA {key.key_size} bits",
                impact="Chaves RSA abaixo de 2048 bits são consideradas fracas e passíveis de quebra.",
                recommendation="Reemita o certificado com RSA de no mínimo 2048 bits (ou uma chave ECDSA P-256).",
                references=(ref.MOZILLA_TLS,),
            )

        algo = cert.signature_hash_algorithm
        if algo is not None and algo.name.lower() in {"md5", "sha1"}:
            yield Finding(
                id="CERT_ASSINATURA_FRACA",
                title="Certificado assinado com algoritmo obsoleto",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O certificado usa assinatura {algo.name.upper()}.",
                evidence=f"Assinatura: {algo.name}",
                impact="MD5 e SHA-1 são vulneráveis a colisões e não oferecem garantia de integridade.",
                recommendation="Reemita o certificado com assinatura SHA-256 ou superior.",
                references=(ref.MOZILLA_TLS,),
            )

    def _check_tls_hardening(self, version: str | None, cipher: str | None) -> Iterable[Finding]:
        """Profundidade de TLS a partir de UM handshake padrão: se o cliente (que suporta
        TLS 1.3) negociou 1.2, o servidor não oferece 1.3; e a cifra 1.2 revela se há forward
        secrecy (PFS). Cifras de TLS 1.3 são sempre PFS — nada a sinalizar nesse caso."""
        if version != "TLSv1.2":
            return  # 1.3 negociado (ok) ou handshake indisponível (inconclusivo)

        # Só afirmamos "servidor sem TLS 1.3" se o PRÓPRIO cliente do scanner suporta 1.3;
        # caso contrário, negociar 1.2 é limitação do scanner (build sem 1.3 ou proxy no
        # caminho), não do servidor — evita um falso-positivo em toda a frota escaneada.
        if ssl.HAS_TLSv1_3:
            yield Finding(
                id="TLS_13_AUSENTE",
                title="TLS 1.3 não suportado",
                category=self.category,
                severity=Severity.INFO,
                description="O servidor não negociou TLS 1.3 (o melhor protocolo obtido foi TLS 1.2).",
                evidence=f"Versão negociada no caminho testado: {version}",
                impact=(
                    "TLS 1.3 é mais rápido e remove famílias inteiras de cifras e modos frágeis do "
                    "1.2. Sua ausência não é uma falha, mas é hardening recomendado."
                ),
                recommendation="Habilite TLS 1.3 no servidor/edge (mantendo 1.2 como piso de compatibilidade).",
                references=(ref.MOZILLA_TLS, ref.MOZILLA_SSL_CONFIG),
            )

        if cipher is None:
            return
        upper = cipher.upper()
        # PFS presente se houver troca efêmera: ECDHE ou DHE. Cuidado: "ECDHE" contém "DHE",
        # então a checagem cobre os dois corretamente (ECDHE cai no 1º termo; DHE puro no 2º).
        if "ECDHE" not in upper and "DHE" not in upper:
            yield Finding(
                id="TLS_SEM_PFS",
                title="Cifra TLS 1.2 sem forward secrecy",
                category=self.category,
                severity=Severity.LOW,
                description=f"A cifra negociada em TLS 1.2 não usa troca de chave efêmera: `{cipher}`.",
                evidence=f"Cifra negociada: {cipher}",
                impact=(
                    "Sem forward secrecy (PFS), se a chave privada do servidor vazar no futuro, "
                    "todo o tráfego capturado no passado pode ser decifrado retroativamente."
                ),
                recommendation=(
                    "Priorize cifras ECDHE (ou DHE) no servidor e desabilite a troca de chave RSA "
                    "estática, seguindo o perfil intermediário da Mozilla."
                ),
                references=(ref.MOZILLA_TLS, ref.MOZILLA_SSL_CONFIG),
            )

    def _check_protocols(
        self, legados: list[str], nao_avaliados: list[str] | None = None
    ) -> Iterable[Finding]:
        if legados:
            yield Finding(
                id="TLS_PROTOCOLO_LEGADO",
                title="Protocolos TLS legados aceitos",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O servidor aceita: {', '.join(legados)}.",
                evidence=", ".join(legados),
                impact=(
                    "TLS 1.0/1.1 têm fraquezas conhecidas (ex.: BEAST, cifras RC4) e "
                    "foram formalmente descontinuados. Mantê-los habilitados amplia a "
                    "superfície de ataque e reprova em conformidades como PCI-DSS."
                ),
                recommendation="Desabilite TLS 1.0 e 1.1; sirva apenas TLS 1.2 e 1.3.",
                references=(ref.MOZILLA_TLS, ref.MOZILLA_SSL_CONFIG),
            )
        if nao_avaliados:
            yield Finding(
                id="TLS_LEGADO_NAO_AVALIADO",
                title="Aceitação de TLS legado não pôde ser avaliada nesta máquina",
                category=self.category,
                severity=Severity.INFO,
                description=(
                    "Não foi possível testar "
                    + ", ".join(nao_avaliados)
                    + ": o OpenSSL desta máquina não permite oferecer essas versões."
                ),
                evidence=f"OpenSSL: {ssl.OPENSSL_VERSION}",
                impact=(
                    "Silêncio aqui NÃO significa que o servidor recusa TLS legado — significa "
                    "que este cliente não conseguiu perguntar. Distribuições com política de "
                    "criptografia endurecida (RHEL 9, Debian com SECLEVEL alto) removem essas "
                    "versões do cliente, e a mesma varredura noutra máquina pode acusar."
                ),
                recommendation=(
                    "Para fechar este ponto, rode a varredura de uma máquina cujo OpenSSL "
                    "ainda ofereça TLS 1.0/1.1, ou confirme a configuração direto no servidor."
                ),
                references=(ref.MOZILLA_TLS,),
            )


# --------------------------------------------------------------------------- #
# Funções auxiliares de baixo nível
# --------------------------------------------------------------------------- #
def _fetch_certificate(
    host: str, port: int, timeout: float = _HANDSHAKE_TIMEOUT
) -> tuple[bytes | None, str | None, str | None]:
    """Certificado, versão e cifra negociadas — tudo de UM handshake padrão.

    Devolve ``(der, versão, cifra)``, ex.: ``(b"...", "TLSv1.3", "TLS_AES_256_GCM_SHA384")``,
    ou ``(None, None, None)`` se o handshake falhar. O certificado é obtido mesmo que não
    seja confiável ou esteja expirado (a validação tem checagem dedicada).

    Antes eram DUAS conexões: uma lia `getpeercert()` e outra lia `version()`/`cipher()`
    do mesmo contexto SSL, byte a byte idêntico. Eram 5 handshakes por alvo; agora são 4
    — menos pegada no log de um cliente que contratou uma varredura não-intrusiva.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cipher = tls.cipher()
            return tls.getpeercert(binary_form=True), tls.version(), (cipher[0] if cipher else None)
    except (OSError, ssl.SSLError):
        return None, None, None


def _data_do_servidor(valor: str | None) -> datetime | None:
    """Converte o cabeçalho ``Date`` (RFC 7231, sempre em GMT) para datetime UTC."""
    if not valor:
        return None
    try:
        return parsedate_to_datetime(valor).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _idade_da_resposta(valor: str | None) -> float:
    """`Age` (RFC 7234) em segundos: quanto tempo a resposta ficou em cache. 0 se
    ausente/inválido/negativo — nunca move o `Date` para trás."""
    if not valor:
        return 0.0
    try:
        idade = int(valor.strip())
    except (TypeError, ValueError):
        return 0.0
    return float(idade) if idade > 0 else 0.0


def _resposta_de_cache_hit(probe: object) -> bool:
    """A resposta se declara servida de um cache de borda? Nesse caso o `Date` é o da
    geração na origem (possivelmente sem `Age` para corrigir), e não uma leitura do
    relógio da origem — não serve para acusar divergência de relógio."""
    header = getattr(probe, "header", None)
    if not callable(header):
        return False
    xcache = (header("X-Cache") or "").lower()
    cf = (header("CF-Cache-Status") or "").upper()
    return "hit" in xcache or cf == "HIT"


def _contexto_de_confianca() -> ssl.SSLContext:
    """Contexto TLS ancorado no MESMO conjunto de CAs que o cliente HTTP da ferramenta.

    Antes, esta checagem usava `ssl.create_default_context()` — a loja do sistema
    operacional — enquanto o `httpx` valida contra o bundle do `certifi`. Duas âncoras
    diferentes na MESMA varredura: o mesmo certificado podia ser aceito pela requisição
    e reprovado pela checagem. Reproduzido contra um endpoint público e válido da Amazon
    Trust Services, que saiu com `CERT_NAO_CONFIAVEL` (alta) e nota F.

    Ancorar no certifi também é o que torna o resultado reprodutível entre máquinas: o
    bundle vem com o pacote e é o mesmo em Windows, Linux e macOS, enquanto a loja do SO
    varia por distribuição, por atualização e por CA corporativa instalada.
    """
    try:
        import certifi  # dependência transitiva do httpx; presente em toda instalação

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001 - sem certifi, a loja do SO é melhor que nada
        return ssl.create_default_context()


def _trust_error(host: str, port: int, timeout: float = _HANDSHAKE_TIMEOUT) -> str | None:
    """``None`` se a cadeia é confiável (ou a falha já tem checagem dedicada); caso
    contrário, a mensagem curta da falha de CADEIA de confiança."""
    context = _contexto_de_confianca()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host),
        ):
            return None
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        msg = str(getattr(exc, "verify_message", "") or exc).lower()
        # Expiração e hostname divergente já têm checagens dedicadas — não duplicar.
        if code in (9, 10) or "expired" in msg or "hostname mismatch" in msg or "not valid for" in msg:
            return None
        return truncate(str(exc), 160)
    except (OSError, ssl.SSLError):
        return None


def _accepts_legacy_tls(
    host: str, port: int, timeout: float = _HANDSHAKE_TIMEOUT
) -> tuple[list[str], list[str]]:
    """Testa se TLS 1.0/1.1 são aceitos. Devolve ``(aceitos, nao_avaliados)``.

    A segunda lista existe porque esta checagem depende do OpenSSL **da máquina que
    roda a varredura**: num Windows ou num Ubuntu comum dá para oferecer TLS 1.0/1.1
    e perguntar ao servidor; num RHEL 9 com `crypto-policies` em DEFAULT, ou em
    qualquer build que remova essas versões, o cliente NÃO CONSEGUE nem oferecer.
    Antes, esse caso devolvia lista vazia — indistinguível de "o servidor recusou".
    O mesmo alvo saía com achado de severidade média numa máquina e limpo na outra.
    """

    def probe(versao: ssl.TLSVersion, rotulo: str) -> tuple[str | None, str | None]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = versao
            context.maximum_version = versao
        except (ValueError, OSError):
            # OpenSSL local não permite forçar essa versão: não avaliado, não "ausente".
            return None, rotulo
        # OpenSSL 3.x remove as cifras de TLS 1.0/1.1 no SECLEVEL padrão (2). Sem baixar o
        # nível, o handshake falharia por "no ciphers" no NOSSO cliente e a checagem viraria
        # código morto (falso-negativo). Baixamos o SECLEVEL do cliente para OFERECER as cifras
        # legadas — assim o resultado reflete a aceitação REAL do servidor (que, se bem
        # configurado, rejeita com alerta de versão de protocolo).
        # OpenSSL 3.x remove as cifras de TLS 1.0/1.1 no SECLEVEL padrão (2). Sem baixar o
        # nível, o handshake falharia por "no ciphers" no NOSSO cliente.
        cifras_legadas_disponiveis = True
        try:
            context.set_ciphers("DEFAULT@SECLEVEL=0")
        except (ssl.SSLError, OSError):
            cifras_legadas_disponiveis = False
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                context.wrap_socket(sock, server_hostname=host),
            ):
                return rotulo, None
        except (OSError, ssl.SSLError) as exc:
            # Sem cifras legadas no cliente, a recusa pode ter sido NOSSA. Só dá para
            # dizer "o servidor não aceita" quando nós conseguimos de fato oferecer.
            if not cifras_legadas_disponiveis and _falha_do_cliente(exc):
                return None, rotulo
            return None, None

    versoes = ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(lambda vr: probe(*vr), versoes))
    return (
        [aceito for aceito, _ in resultados if aceito is not None],
        [nao_av for _, nao_av in resultados if nao_av is not None],
    )


def _falha_do_cliente(exc: BaseException) -> bool:
    """Heurística: o handshake caiu por limitação do NOSSO cliente, não por recusa do alvo."""
    msg = str(exc).lower()
    return any(t in msg for t in ("no ciphers", "unsupported protocol", "wrong version", "no protocols"))


def _not_valid_after(cert: x509.Certificate) -> datetime:
    """Compatível com versões novas e antigas do `cryptography`."""
    value: datetime | None = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    naive: datetime = cert.not_valid_after  # deprecado, mas em UTC
    return naive.replace(tzinfo=timezone.utc)


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def _san_ip_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]


def _hostname_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".exemplo.com"
            # Curinga cobre exatamente um rótulo à esquerda.
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0 and host != suffix[1:]:
                return True
    return False
