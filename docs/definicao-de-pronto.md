# Definição de pronto — a correção ataca a classe, não o exemplo

Este documento fixa um critério que vale para as cinco ferramentas da suíte
([Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela),
[Guardião](https://github.com/Paulo-Marcos-Lucio/guardiao),
[Chaveiro](https://github.com/Paulo-Marcos-Lucio/chaveiro),
[Esteira](https://github.com/Paulo-Marcos-Lucio/esteira) e o
[Laboratório OWASP](https://github.com/Paulo-Marcos-Lucio/laboratorio-owasp)):
o que precisa ser verdade para uma correção de defeito ser considerada pronta,
não só "fechada".

## A regra

> Corrigir o exemplo que apareceu no relatório e chamar de resolvido não fecha
> o item. O critério de pronto inclui um **invariante** que impeça a classe
> inteira de voltar.

Um defeito relatado é sempre uma instância — um IP específico que escapou da
guarda anti-SSRF, uma resposta específica que zerou a nota, um cookie
específico que gerou falso-positivo. É tentador (e mais rápido) escrever um
teste que fixa exatamente aquele valor e seguir em frente. O problema é que
esse teste prova apenas que *aquele* exemplo não volta — a causa-raiz, que
normalmente é uma classe inteira de entrada mal tratada, continua aberta para
qualquer outro membro da classe que ninguém tenha pensado em testar.

Duas exigências, nesta ordem:

1. **Um teste que falhava antes da correção.** Não um teste que já passaria
   sem a mudança — isso prova que o código funciona, não que o bug existia.
   O teste precisa reproduzir o defeito relatado contra o código anterior à
   correção (rodá-lo no commit-pai é a forma mais direta de confirmar) e virar
   verde só depois da correção.
2. **Um invariante que cubra a classe, property-based quando couber.** Quando
   o defeito é membro de uma família (qualquer endereço de uma faixa de rede,
   qualquer deriva de relógio, qualquer ordem de claims), o teste correto gera
   muitos membros dessa família — com [Hypothesis](https://hypothesis.readthedocs.io/)
   nos repositórios em Python — e afirma a propriedade que nenhum deles pode
   violar. Quando a classe é finita e pequena o bastante para enumerar por
   completo (ex.: os três estados de um enum), um teste parametrizado cobrindo
   todos os casos cumpre o mesmo papel sem precisar de geração aleatória.

Na dúvida sobre se um teste ataca a classe ou só o exemplo, a pergunta é: *se
eu trocar o valor concreto deste teste por outro membro plausível da mesma
família, ele continua provando alguma coisa?* Se a resposta é não — o teste
só repete o valor do relatório — ele não fecha o item sozinho.

## Exemplos reais deste repositório

### O bypass de normalização de IP (SSRF)

`tests/test_propriedades_ssrf.py` documenta a própria causa-raiz no
cabeçalho do arquivo: a guarda anti-SSRF comparava o endereço literal, e
`::ffff:100.64.0.1` — o mesmo host CGNAT que `100.64.0.1`, só que escrito na
forma IPv4-mapeado-em-IPv6 — passava batido. Um teste que fixasse
`::ffff:100.64.0.1` como entrada teria fechado só aquele bypass; a correção
real foi normalizar antes de decidir, e o teste que tranca isso gera até 400
endereços por rodada com Hypothesis e afirma duas invariantes:

```python
@settings(max_examples=400)
@given(ip=_host_em_faixa_perigosa())
def test_faixa_reservada_sempre_bloqueada(ip):
    """INVARIANTE 1: qualquer endereço de faixa interna/não-roteável é bloqueado."""
    assert _ip_blocked(ip) is True


@settings(max_examples=400)
@given(ip=st.ip_addresses(v=4))
def test_ipv4_mapeado_espelha_o_ipv4(ip):
    """INVARIANTE 2 (a classe do bypass): `::ffff:X` decide igual a `X`."""
    mapeado = ipaddress.ip_address(f"::ffff:{ip}")
    assert _ip_blocked(mapeado) == _ip_blocked(ip)
```

A segunda invariante é a que importa aqui: ela não menciona `100.64.0.1`,
menciona a *relação* entre a forma mapeada e a forma nativa, para qualquer
IPv4. Nenhuma variação futura dessa forma de escrever o mesmo endereço volta
a escapar sem que o teste detecte.

### A nota que ignorava resposta suprimida (H1)

`tests/test_cruzada_fp_fn_2026_08.py` — cujo próprio docstring declara "cada
teste ataca a CLASSE (a causa-raiz), não o exemplo isolado — é o padrão
`DEFINITION_OF_DONE`" — traz o caso H1: `RESPOSTA_DE_ERRO` valia INFO peso
zero no cálculo da nota, então um alvo que devolvia 500 ou 404 na raiz, com
**todas** as checagens suprimidas por não ter avaliado nada, saía com nota
100/A. O relatório original citou um alvo específico; o teste que fechou o
item não cita nenhum:

```python
def test_h1_resposta_primaria_nao_avaliada_teta_a_nota_em_f():
    # Classe: TODA resposta primária que suprime as checagens do alvo teta a nota em F.
    for fid in ("RESPOSTA_DE_ERRO", "ALVO_BLOQUEADO", "ALVO_INACESSIVEL"):
        s = compute_score([_finding_scoring(fid)])
        assert s.grade == "F", fid
        assert s.value <= 44, fid
```

Note o segundo teste ao lado dele, `test_h1_alvo_avaliado_com_so_info_segue_a`:
a contraprova de que a correção não supercorrigiu — um alvo genuinamente
avaliado, com achados só informativos, continua saindo A. Um invariante sem a
contraprova barra falso-negativo à custa de introduzir falso-positivo em
outra classe; as duas pontas fazem parte de fechar o item.

## Quando não há classe (e tudo bem)

Nem todo item da fila é correção de defeito. Documentação, publicação de
conteúdo já escrito, dado de série temporal — a política (`POLITICA.md`) já
distingue isso: esses itens carregam informação nova por si, sem precisar de
invariante nenhum. A exigência de teste-que-falhava-antes e invariante
property-based vale especificamente para **correção de defeito**: é aí que a
tentação de fechar o exemplo isolado e seguir em frente é maior, e é aí que o
"1 dia sem commit é melhor que um commit ruim" da política se aplica com mais
força — um invariante mal desenhado passa no CI e ainda assim não tranca
nada.
