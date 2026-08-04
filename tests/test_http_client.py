"""O `HttpClient` de verdade, contra servidores locais — sem tocar em rede externa.

O docstring de `core/http.py` vende duas garantias como "decisões de segurança da própria
ferramenta": a guarda anti-SSRF nos redirecionamentos e o teto de corpo por streaming.
Eram exatamente as duas únicas partes do módulo que NENHUM teste executava — apagar as
três linhas do `_host_is_blocked` e o `[:cap]` do `_read_capped` deixava a suíte inteira
verde. Todos os outros testes constroem `Probe` na mão ou trocam o cliente por um falso.

O critério de aceite aqui é OBSERVAR A REQUISIÇÃO: o servidor de destino registra cada
acerto. "Não apareceu na cadeia" não bastaria — sem a guarda, a requisição sai e falha,
e a cadeia fica vazia do mesmo jeito. O que separa os dois mundos é o servidor de destino
ter sido tocado ou não.
"""

from __future__ import annotations

import gzip
import threading
import tracemalloc
import zlib
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import sentinela.core.http as http_mod
from sentinela.core.http import _MAX_REDIRECTS, HttpClient, _host_is_blocked

_CORPO_GRANDE = b"A" * 1_000_000

# Bomba de descompressão: 64 MiB de zeros que cabem em ~64 KB na rede. Montada em blocos
# para que o PRÓPRIO teste nunca segure os 64 MiB — senão a medição de memória mediria o
# teste, não a ferramenta.
_BOMBA_EXPANDIDA = 64 * 1024 * 1024


def _monta_bomba(tamanho: int) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    bloco = b"\0" * (1024 * 1024)
    partes = [compressor.compress(bloco) for _ in range(tamanho // len(bloco))]
    partes.append(compressor.flush())
    return b"".join(partes)


_BOMBA = _monta_bomba(_BOMBA_EXPANDIDA)


class _Destino(BaseHTTPRequestHandler):
    """Servidor "interno": registra tudo que chegar nele."""

    acertos: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - assinatura da stdlib
        type(self).acertos.append(self.path)
        corpo = b"SEGREDO-DA-REDE-INTERNA"
        self.send_response(200)
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def log_message(self, *args: object) -> None:
        return


class _Alvo(BaseHTTPRequestHandler):
    """Servidor "alvo": redireciona para o destino interno e serve corpos grandes."""

    destino_url = ""

    def do_GET(self) -> None:  # noqa: N802 - assinatura da stdlib
        if self.path == "/redireciona":
            self._redireciona(f"{type(self).destino_url}/segredo")
        elif self.path.startswith("/cadeia/"):
            self._redireciona(f"/cadeia/{int(self.path.rsplit('/', 1)[1]) + 1}")
        elif self.path == "/gigante":
            self._responde(_CORPO_GRANDE)
        elif self.path == "/bomba":
            self._responde(_BOMBA, encoding="gzip")
        elif self.path == "/comprimido":
            self._responde(gzip.compress(b"<html>MARCA-DENTRO-DO-GZIP</html>"), encoding="gzip")
        else:
            self._responde(b"ok")

    def _redireciona(self, destino: str) -> None:
        self.send_response(302)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _responde(self, corpo: bytes, encoding: str | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def log_message(self, *args: object) -> None:
        return


def _sobe(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(scope="module")
def destino() -> Iterator[str]:
    yield from _sobe(_Destino)


@pytest.fixture(scope="module")
def alvo(destino: str) -> Iterator[str]:
    _Alvo.destino_url = destino
    yield from _sobe(_Alvo)


@pytest.fixture(autouse=True)
def _limpa_acertos() -> Iterator[None]:
    _Destino.acertos.clear()
    yield


def test_redirecionamento_para_host_interno_nunca_e_requisitado(alvo: str) -> None:
    with HttpClient(timeout=5.0) as client:
        probe = client.request("GET", f"{alvo}/redireciona")
    assert _Destino.acertos == [], "a guarda anti-SSRF não impediu a requisição ao host interno"
    assert "SEGREDO-DA-REDE-INTERNA" not in probe.body_snippet


def test_redirecionamento_permitido_e_de_fato_seguido(alvo: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Contraprova: com a POLÍTICA de faixas relaxada (mas o ponto de aplicação intacto),
    # o mesmo redirecionamento É seguido. Sem este caso, o teste acima passaria por
    # acidente mesmo com a guarda travando tudo.
    monkeypatch.setattr(http_mod, "_ip_blocked", lambda _ip: False)
    with HttpClient(timeout=5.0) as client:
        probe = client.request("GET", f"{alvo}/redireciona")
    assert _Destino.acertos == ["/segredo"]
    assert len(probe.redirect_chain) == 2
    assert "SEGREDO-DA-REDE-INTERNA" in probe.body_snippet


def test_o_alvo_inicial_escolhido_pelo_operador_nunca_e_bloqueado(alvo: str) -> None:
    # A guarda vale para DESTINO DE REDIRECIONAMENTO, não para o alvo: varrer um host
    # interno é uso legítimo e explícito. Este servidor é 127.0.0.1 e responde 200.
    with HttpClient(timeout=5.0) as client:
        probe = client.request("GET", f"{alvo}/ok")
    assert probe.ok and probe.status_code == 200


def test_cadeia_longa_para_no_maximo_de_saltos(alvo: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_mod, "_ip_blocked", lambda _ip: False)
    with HttpClient(timeout=5.0) as client:
        probe = client.request("GET", f"{alvo}/cadeia/0")
    assert len(probe.redirect_chain) == _MAX_REDIRECTS + 1


def test_sem_follow_redirects_a_cadeia_nao_avanca(alvo: str) -> None:
    with HttpClient(timeout=5.0) as client:
        probe = client.request("GET", f"{alvo}/cadeia/0", follow_redirects=False)
    assert probe.status_code == 302
    assert len(probe.redirect_chain) == 1


def test_corpo_gigante_e_cortado_no_teto(alvo: str) -> None:
    with HttpClient(timeout=10.0, max_body_bytes=4096) as client:
        probe = client.request("GET", f"{alvo}/gigante")
    assert len(probe.body_snippet) <= 4096
    assert len(_CORPO_GRANDE) > 4096  # o servidor tentou entregar 1 MB


def test_download_e_interrompido_no_teto_nao_apenas_truncado() -> None:
    """A promessa do docstring é "o download é interrompido", não "o texto é cortado".

    Só medir `len(body_snippet)` não distingue as duas: o `[:cap]` final mascara a
    remoção do `break`, e a ferramenta voltaria a BAIXAR o gigabyte inteiro antes de
    jogar fora — que é exatamente o recurso que um alvo hostil quer consumir. Aqui a
    fonte conta quantos pedaços foram efetivamente puxados.

    A costura é `iter_raw()` (bytes da rede), e não mais `iter_bytes()` (bytes já
    expandidos pelo httpx): a descompressão passou a ser nossa para poder ter teto.
    """
    puxados = 0

    class _RespostaFalsa:
        encoding = "utf-8"
        headers: dict[str, str] = {}

        def iter_raw(self) -> Iterator[bytes]:
            nonlocal puxados
            for _ in range(1000):  # 1 MB em pedaços de 1 KB
                puxados += 1
                yield b"A" * 1024

    with HttpClient(timeout=1.0) as client:
        corpo, _trunc, _lidos = client._read_capped(_RespostaFalsa(), 4096)  # type: ignore[arg-type]

    assert len(corpo) == 4096
    assert puxados <= 5, f"o download continuou depois do teto: {puxados} pedaços de 1 KB puxados"


def test_gzip_bomb_respeita_teto_de_memoria(alvo: str) -> None:
    """O teto de corpo tem de valer sobre os bytes DESCOMPRIMIDOS, durante o streaming.

    Aplicá-lo depois da descompressão protege o disco e o texto do relatório, mas não
    protege a memória — que é justamente o recurso que a bomba quer consumir. O corpo
    truncado saía do tamanho certo, e por isso nenhuma asserção sobre `body_snippet`
    denunciava o problema: só a medição de pico de alocação denuncia.
    """
    assert len(_BOMBA) < 200_000  # ~64 KB na rede…
    assert len(zlib.decompress(_BOMBA, zlib.MAX_WBITS | 16)) == _BOMBA_EXPANDIDA  # …64 MiB na RAM

    tracemalloc.start()
    try:
        with HttpClient(timeout=10.0, max_body_bytes=4096) as client:
            probe = client.request("GET", f"{alvo}/bomba")
        _atual, pico = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(probe.body_snippet) <= 4096
    assert probe.truncated is True, "corpo interrompido no teto tem de vir marcado como incompleto"
    # Folga generosa (2 000× o teto) para não depender do tamanho de bloco do zlib nem do
    # ruído do servidor de teste; ainda assim ~8× menor que a expansão da bomba.
    assert pico < 8 * 1024 * 1024, f"a descompressão materializou {pico / 1024 / 1024:.1f} MiB de RAM"


def test_corpo_comprimido_normal_continua_sendo_lido(alvo: str) -> None:
    """Contraprova indispensável do teto acima: um corpo VAZIO passaria naquele teste.

    Ao assumir a descompressão para poder limitá-la, a ferramenta passou a poder falhar
    de um jeito novo e silencioso — devolver corpo vazio para todo alvo que comprime, o
    que faria as checagens de conteúdo declararem ausência de tudo. Aqui o conteúdo tem
    de chegar decodificado e o corpo tem de vir marcado como ÍNTEGRO.
    """
    with HttpClient(timeout=10.0, max_body_bytes=4096) as client:
        probe = client.request("GET", f"{alvo}/comprimido")
    assert "MARCA-DENTRO-DO-GZIP" in probe.body_snippet
    assert probe.truncated is False
    assert probe.corpo_confiavel is True


def test_fluxo_que_expande_para_nada_nao_prende_a_leitura(alvo: str) -> None:
    """O teto de SAÍDA sozinho não fecha a porta: ele nunca dispara se não há saída.

    Blocos armazenados vazios (o marcador de `Z_SYNC_FLUSH`, 5 bytes cada) formam um
    fluxo gzip válido que descomprime para ZERO byte. Sem um teto sobre os bytes da rede,
    a ferramenta ficaria puxando esses 5 bytes de graça enquanto o alvo quisesse mandar.
    """
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    cabecalho = compressor.compress(b"") + compressor.flush(zlib.Z_SYNC_FLUSH)
    enchimento = b"\x00\x00\x00\xff\xff" * 13_107  # ~64 KB que viram 0 byte de corpo
    puxados = 0

    class _RespostaSemFim:
        encoding = "utf-8"
        headers = {"content-encoding": "gzip"}

        def iter_raw(self) -> Iterator[bytes]:
            nonlocal puxados
            yield cabecalho
            while True:  # o alvo hostil mandaria para sempre
                puxados += 1
                yield enchimento

    with HttpClient(timeout=1.0) as client:
        corpo, truncado, _lidos = client._read_capped(_RespostaSemFim(), 4096)  # type: ignore[arg-type]

    assert corpo == ""
    assert truncado is True
    assert puxados <= 40, f"a leitura seguiu além do teto de rede: {puxados} pedaços de 64 KB"


def test_encoding_que_nao_sabemos_desembrulhar_nao_vira_texto_falso(alvo: str) -> None:
    """Consequência direta de assumir a descompressão: não inventar corpo.

    Se o alvo responder num codec que não sabemos limitar, o corpo sai VAZIO e marcado
    como incompleto — nunca bytes comprimidos decodificados como se fossem texto, que
    fariam as checagens de conteúdo afirmarem ausências que não observaram.
    """

    class _RespostaExotica:
        encoding = "utf-8"
        headers = {"content-encoding": "br"}

        def iter_raw(self) -> Iterator[bytes]:  # pragma: no cover - não deve ser chamado
            yield _BOMBA

    with HttpClient(timeout=1.0) as client:
        corpo, truncado, lidos = client._read_capped(_RespostaExotica(), 4096)  # type: ignore[arg-type]

    assert corpo == ""
    assert truncado is True
    assert lidos == 0


def test_teto_por_requisicao_nao_afrouxa_o_teto_padrao(alvo: str) -> None:
    with HttpClient(timeout=10.0, max_body_bytes=4096) as client:
        maior = client.request("GET", f"{alvo}/gigante", max_body_bytes=64_000)
        padrao = client.request("GET", f"{alvo}/gigante")
    assert 4096 < len(maior.body_snippet) <= 64_000
    assert len(padrao.body_snippet) <= 4096


def test_erro_de_transporte_vira_probe_e_nao_excecao() -> None:
    with HttpClient(timeout=1.0) as client:
        probe = client.request("GET", "http://127.0.0.1:1/")  # porta fechada
    assert not probe.ok
    assert probe.error


def test_cgnat_e_bloqueado() -> None:
    """`100.64.0.0/10` (RFC 6598) não é "privado" para o módulo `ipaddress` — e passava.

    Não é faixa acadêmica: é o espaço de CGNAT das operadoras, e dentro dele mora
    `100.100.100.100`, o endpoint de metadados da Alibaba Cloud. Um alvo hostil que
    redirecionasse para lá fazia a varredura buscar credenciais de instância.
    """
    assert _host_is_blocked("100.64.0.1") is True
    assert _host_is_blocked("100.100.100.100") is True
    assert _host_is_blocked("100.127.255.255") is True
    # Contraprova de borda: os vizinhos IMEDIATOS da faixa continuam liberados — uma
    # denylist larga demais transforma alvo legítimo em "bloqueado" sem ninguém notar.
    assert _host_is_blocked("100.63.255.255") is False
    assert _host_is_blocked("100.128.0.0") is False


def test_ipv4_mapeado_em_ipv6_e_bloqueado() -> None:
    """`::ffff:100.64.0.1` é o MESMO host que `100.64.0.1`, escrito de outro jeito.

    Depender do `is_private` do stdlib aqui é frágil: a resposta dele para IPv4 mapeado
    mudou entre patch releases do próprio Python (CVE-2024-4032), e o projeto suporta
    3.10+. A normalização passa a ser nossa, e o veredito deixa de variar com o intérprete.
    """
    assert _host_is_blocked("::ffff:100.64.0.1") is True
    assert _host_is_blocked("::ffff:127.0.0.1") is True
    assert _host_is_blocked("::ffff:169.254.169.254") is True  # metadados AWS/GCP/Azure
    assert _host_is_blocked("::ffff:10.0.0.1") is True
    assert _host_is_blocked("::ffff:8.8.8.8") is False  # mapeado de IP público segue público


def test_faixas_especiais_de_teste_e_ietf_sao_bloqueadas() -> None:
    # `192.0.0.0/24` (IETF Protocol Assignments) e `198.18.0.0/15` (benchmarking) só entram
    # em `is_private` do stdlib a partir das versões corrigidas pelo CVE-2024-4032. Ficam
    # explícitas para que o bloqueio não dependa do micro-release do Python da máquina.
    assert _host_is_blocked("192.0.0.100") is True
    assert _host_is_blocked("198.18.0.1") is True
    assert _host_is_blocked("198.19.255.255") is True


def test_host_que_nao_resolve_falha_fechado(monkeypatch: pytest.MonkeyPatch) -> None:
    # Política DELIBERADA: se o DNS do destino de um redirecionamento não resolve, não há
    # como afirmar que ele é externo — e a ferramenta não segue. Falhar ABERTO aqui abria
    # uma janela de DNS rebinding entre a checagem da guarda e a resolução do httpx.
    def _falha(*_a: object, **_k: object) -> list[object]:
        raise OSError("nome não resolve")

    monkeypatch.setattr(http_mod.socket, "getaddrinfo", _falha)
    assert _host_is_blocked("qualquer-nome.example") is True
    assert _host_is_blocked("8.8.8.8") is False  # literal de IP não passa pelo DNS
