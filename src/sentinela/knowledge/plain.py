"""Camada didática: explica cada achado em linguagem de leigo, com analogias.

Metáfora unificada (mantida em todo o relatório): o site é uma **loja física**.
Fachada = o que o visitante vê · cadeado da porta = HTTPS · crachá de identidade =
certificado TLS · regras de segurança afixadas = cabeçalhos · pulseira do cliente =
cookies · caixa de correio da marca = DNS/e-mail. O objetivo é o cliente leigo
entender enquanto o consultor explica.
"""

from __future__ import annotations

# Introdução do relatório — a metáfora-âncora.
INTRO_LEIGO: str = (
    "Pense no seu site como uma **loja física**. Ele tem a fachada (o que o visitante vê), "
    "o cadeado da porta (a conexão segura HTTPS), o crachá de identidade da loja (o certificado), "
    "regras de segurança afixadas na parede (os cabeçalhos), a pulseira que identifica cada cliente "
    "(os cookies) e a caixa de correio da sua marca (o e-mail/DNS). Este diagnóstico olha, de fora — "
    "como um cliente comum faria, sem forçar nenhuma porta — se cada uma dessas coisas está bem "
    "trancada. A nota vai de A (bem protegido) a F, e o Plano de Ação diz por onde começar."
)

# finding.id -> explicação em termos simples, com analogia. 1–2 frases.
_PLAIN: dict[str, str] = {
    # --- Cabeçalhos de segurança (as regras de segurança afixadas na parede) ---
    "CSP_AUSENTE": (
        "Falta a lista de 'fornecedores autorizados' de conteúdo. Sem ela, o navegador aceita "
        "rodar qualquer script na sua página — inclusive um malicioso que um atacante injete. "
        "A CSP diz quem pode entregar mercadoria na sua loja."
    ),
    "CSP_DIRETIVA_INSEGURA": (
        "A lista de fornecedores existe, mas tem uma brecha que na prática deixa entrar 'qualquer "
        "um' — o que anula boa parte da proteção contra scripts maliciosos."
    ),
    "CLICKJACKING_SEM_PROTECAO": (
        "Sem esta trava, um golpista pode colocar o seu site dentro de uma moldura invisível e "
        "enganar o visitante a clicar em coisas que ele não vê — como sobrepor um vidro falso sobre "
        "o teclado de um caixa eletrônico."
    ),
    "XCTO_AUSENTE": (
        "Sem este aviso, o navegador pode 'adivinhar' que um arquivo é de um tipo diferente do "
        "declarado — e um atacante usa isso pra fazer um arquivo inofensivo virar código executável."
    ),
    "REFERRER_POLICY_AUSENTE": (
        "Sem esta política, o seu site pode entregar a outros sites o endereço exato de onde o "
        "visitante veio — como contar pra loja vizinha tudo o que o cliente fazia antes de chegar."
    ),
    "PERMISSIONS_POLICY_AUSENTE": (
        "Você não está limitando quais recursos sensíveis (câmera, microfone, localização) as "
        "páginas podem pedir — é deixar as portas dos fundos destrancadas 'por via das dúvidas'."
    ),
    "COOP_AUSENTE": (
        "Falta um isolamento entre a aba do seu site e outras janelas — como não ter paredes entre "
        "as salas. Um 'vizinho' malicioso numa aba pode tentar bisbilhotar a sua."
    ),
    "XXSS_PROTECTION_LEGADO": (
        "Você usa uma trava antiga que os navegadores modernos já aposentaram (e que às vezes cria "
        "novos problemas) — como um alarme obsoleto que dispara sozinho. O certo é removê-la e "
        "confiar na CSP."
    ),
    # --- HSTS / transporte (o cadeado da porta) ---
    "HSTS_AUSENTE": (
        "Seu site tem o cadeado (HTTPS), mas não OBRIGA o navegador a usá-lo sempre. É ter a porta "
        "blindada e deixar a de vidro do lado destrancada: num Wi-Fi público, um atacante empurra o "
        "visitante pra versão sem cadeado e lê tudo."
    ),
    "HSTS_FRACO": (
        "A regra 'sempre use o cadeado' existe, mas vale por pouco tempo — como um contrato de "
        "segurança que expira em dias. Basta estender o prazo."
    ),
    "HSTS_SEM_SUBDOMINIOS": (
        "A regra do cadeado protege o site principal, mas não os subdomínios (loja., blog.) — "
        "deixando essas portas laterais desprotegidas."
    ),
    "SEM_REDIRECT_HTTPS": (
        "Quem digita o endereço sem 'https' continua numa conexão sem cadeado, em texto aberto — "
        "como enviar uma carta sem envelope, que qualquer um no caminho lê. O certo é levar todo "
        "visitante automaticamente pra versão segura."
    ),
    # --- Cookies (a pulseira que identifica o cliente) ---
    "COOKIE_SEM_HTTPONLY": (
        "A 'pulseira' que identifica o usuário logado pode ser lida por scripts da página. Se um "
        "script malicioso entrar, ele copia a pulseira e se passa pelo usuário — um clone do crachá."
    ),
    "COOKIE_SEM_HTTPONLY_FUNCIONAL": (
        "Alguns cookies (de analytics/preferências) podem ser lidos por scripts — o que é normal se "
        "não carregam login. Só vale confirmar que nenhum deles é de sessão."
    ),
    "COOKIE_SEM_SECURE": (
        "A 'pulseira' do usuário pode trafegar por uma conexão sem cadeado, onde alguém na mesma "
        "rede consegue capturá-la. Basta marcá-la pra só viajar por HTTPS."
    ),
    "COOKIE_SEM_SAMESITE": (
        "Sem esta marca, a 'pulseira' acompanha o usuário até quando ele clica num link de outro "
        "site — o que abre porta pra golpes (CSRF) em que um site malicioso age em nome do usuário "
        "sem ele perceber."
    ),
    # --- CORS (quem pode pegar emprestada a chave da loja) ---
    "CORS_REFLEXAO_COM_CREDENCIAIS": (
        "Seu site está dizendo 'qualquer site pode acessar os dados do usuário logado aqui' — como "
        "dar cópia da chave da sua casa pra quem quer que peça, inclusive golpistas."
    ),
    "CORS_CURINGA_COM_CREDENCIAIS": (
        "Seu site libera os dados do usuário logado pra qualquer origem — confiança total em "
        "estranhos. É o portão da casa sempre aberto."
    ),
    "CORS_REFLEXAO_ORIGEM": (
        "Seu site responde automaticamente 'sim, confio em você' pra qualquer site que pergunta, "
        "sem checar quem é. Confiança cega."
    ),
    # --- Métodos HTTP ---
    "HTTP_TRACE_HABILITADO": (
        "Uma porta de diagnóstico antiga (o método TRACE) está aberta ao público e pode ser abusada "
        "pra roubar dados do usuário. É a porta de manutenção que ficou destrancada."
    ),
    "HTTP_METODOS_PERIGOSOS": (
        "O servidor anuncia que aceita comandos de alteração/remoção (PUT/DELETE) de quem chega de "
        "fora — como uma loja que deixa qualquer um remarcar os preços na prateleira."
    ),
    # --- Exposição de informação ---
    "VERSAO_STACK_EXPOSTA": (
        "O servidor conta em voz alta a marca e a VERSÃO exata do software que usa. Um atacante "
        "consulta a lista pública de falhas daquela versão — como um ladrão que já sabe o modelo "
        "exato da sua fechadura."
    ),
    "LISTAGEM_DIRETORIO": (
        "Uma pasta do site mostra a lista de todos os arquivos que tem dentro, como uma gaveta "
        "aberta — o visitante vê e baixa coisas que não deveriam estar à mostra."
    ),
    # --- Arquivos/rotas sensíveis (os mais graves) ---
    "GIT_EXPOSTO": (
        "A 'planta baixa' completa do site (o histórico de código no .git) está acessível na web. "
        "Qualquer um baixa o código-fonte inteiro — inclusive senhas antigas que ficaram no "
        "histórico. É deixar os projetos e as chaves da obra na calçada."
    ),
    "DOTENV_EXPOSTO": (
        "O arquivo de configuração (.env) — que costuma guardar SENHAS de banco, chaves de API e "
        "segredos — está acessível pela web. É o cofre da loja com a porta escancarada pra rua."
    ),
    "SVN_EXPOSTO": (
        "Metadados de controle de versão (.svn) expostos revelam a estrutura e trechos do seu "
        "código — como deixar rascunhos da planta baixa acessíveis a qualquer um."
    ),
    "APACHE_STATUS_EXPOSTO": (
        "Um painel interno do servidor está público, mostrando em tempo real o que está sendo "
        "acessado — como uma janela aberta pros bastidores da loja."
    ),
    "PHPINFO_EXPOSTO": (
        "Uma página de diagnóstico (phpinfo) revela toda a configuração interna do servidor — um "
        "mapa completo entregue de bandeja pro atacante."
    ),
    # --- TLS / certificado (o crachá de identidade da loja) ---
    "CERT_EXPIRADO": (
        "O 'documento de identidade' do site (o certificado) venceu, e o navegador bloqueia o "
        "acesso com uma tela vermelha de erro — como um crachá vencido que a portaria não aceita."
    ),
    "CERT_EXPIRANDO": (
        "O documento de identidade do site vence em poucos dias. Renove antes, senão o site fica "
        "inacessível de uma hora pra outra."
    ),
    "CERT_HOSTNAME_INVALIDO": (
        "O documento de identidade é de OUTRO nome, não bate com o endereço acessado — como um "
        "crachá com a foto errada. O navegador desconfia e bloqueia."
    ),
    "CERT_NAO_CONFIAVEL": (
        "O documento de identidade não foi emitido por um órgão reconhecido (ou veio incompleto) — "
        "como um RG feito em casa. O navegador não confia e alerta o usuário."
    ),
    "CERT_CHAVE_FRACA": (
        "A 'fechadura' criptográfica do certificado é curta demais e pode ser arrombada com poder "
        "de computação suficiente. Troque por uma mais forte."
    ),
    "CERT_ASSINATURA_FRACA": (
        "O certificado foi assinado com um método antigo e quebrável (MD5/SHA-1) — como uma "
        "assinatura fácil de falsificar. Reemita com um método moderno."
    ),
    "TLS_PROTOCOLO_LEGADO": (
        "O site ainda aceita versões antigas e furadas do 'idioma seguro' (TLS 1.0/1.1), já "
        "aposentadas — como aceitar uma senha que todo mundo sabe que é insegura. Deixe só as "
        "versões modernas."
    ),
    # --- DNS / e-mail (a caixa de correio da sua marca) ---
    "SPF_AUSENTE": (
        "Não existe uma lista de 'quem pode mandar e-mail em nome do seu domínio'. Sem ela, qualquer "
        "golpista envia e-mail se passando pela sua empresa (phishing) — como não registrar quem "
        "pode usar o seu papel timbrado."
    ),
    "SPF_PERMISSIVO": (
        "A lista de remetentes existe, mas termina com 'na dúvida, aceite todo mundo' — o que anula "
        "a proteção. Basta fechá-la com '-all'."
    ),
    "DMARC_AUSENTE": (
        "Falta a política que diz aos provedores o que fazer com e-mails falsos enviados em seu "
        "nome. Sem ela, os falsos ainda chegam à caixa de entrada dos seus clientes."
    ),
    "DMARC_SEM_ENFORCEMENT": (
        "A política existe, mas está só 'observando' — vê os e-mails falsos passarem e não bloqueia. "
        "Evolua a política pra efetivamente barrá-los."
    ),
    "CAA_AUSENTE": (
        "Não há uma regra dizendo QUAIS autoridades podem emitir certificado pro seu domínio — hoje "
        "qualquer uma pode, o que amplia o risco de um certificado indevido. É um reforço extra."
    ),
    "DNSSEC_AUSENTE": (
        "As respostas de DNS do seu domínio não são assinadas, então podem ser forjadas pra "
        "redirecionar visitantes a um site falso — como adulterar a placa de endereço na esquina."
    ),
    "DNS_HOSPEDAGEM_GERENCIADA": (
        "Seu site está numa hospedagem gerenciada (tipo GitHub Pages): o DNS e o e-mail são do "
        "provedor, não seus, e não são a sua responsabilidade. Pra avaliar e-mail/DNS, rode o "
        "diagnóstico contra o seu domínio próprio."
    ),
    # --- Higiene / processo ---
    "SECURITY_TXT_AUSENTE": (
        "Falta um canal-padrão de contato de segurança (o security.txt) — o lugar onde um "
        "pesquisador ético avisaria se encontrasse uma falha. Sem ele, o aviso pode nunca chegar."
    ),
}


def plain_for(finding_id: str) -> str | None:
    """Explicação em termos simples (com analogia) de um achado, ou ``None``."""
    return _PLAIN.get(finding_id)
