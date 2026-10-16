# Segurança — riscos aceitos e controles da API

Riscos residuais conhecidos, as decisões que os aceitam, o modelo de ameaças e a matriz
requisito → controle (RNF-15b, no fim). Operação (backup, restauração, segredos):
[`operacao.md`](operacao.md). LGPD: [`ropa.md`](ropa.md) e [`incidente.md`](incidente.md).

## Modelo de ameaças (resumo de ARQUITETURA-ALVO §7)

| Ameaça | Controle | Residual aceito |
|---|---|---|
| Vazamento do banco ou de um backup | Zero-knowledge; authHash re-hasheado com Argon2id + pepper (`COFRE_SEGREDO`, fora do banco); backup cifrado com `age` (só a chave pública no host) | Senha-mestra fraca permite ataque offline (KDF caro, mínimo de 12 caracteres no cliente) |
| Operador/servidor passivo | Servidor só vê blobs, ids, tamanhos, horários | Metadados de uso visíveis (quem revelou o quê e quando) |
| **Servidor ativo malicioso: o servidor serve o JS** | CSP estrita, sem CDN, Trusted Types, bibliotecas vendorizadas com hash | **Não mitigado.** Quem controla o servidor (ou o domínio/proxy) entrega um JS que lê a senha-mestra quando ela é digitada e o cofre aberto. Zero-knowledge protege contra vazamento do banco, não contra quem troca o código servido. Mitigação real (app/extensão assinados, verificação fora de banda) fica no backlog |
| Servidor troca a chave pública de um membro | Fingerprint conferido fora de banda na confirmação; o cliente reconfere antes de envelopar | Admin que pula a conferência anula a proteção |
| Servidor faz rollback de item | AAD com `versao`/`chave_ver`; o cliente compara as versões do sync com as da rotação | Rollback para blob antigo legítimo do mesmo contexto (manifesto assinado no backlog) |
| Ex-membro com a chave antiga | Rotação da collectionKey + "senhas a trocar" | O que ele já viu continua conhecido |
| Membro com acesso forja item | Servidor barra gravação por permissão | Quem tem a collectionKey cifra blob válido (RF-O05, abaixo) |
| Força bruta / enumeração | Limites por IP e conta, respostas iguais, Argon2 falso | DoS dirigido de 15 min aceito |
| Roubo de sessão / CSRF / XSS | Cookie HttpOnly/Secure/SameSite=Strict, `X-Cofre`, origem única, zero `innerHTML` | XSS anularia tudo (por isso CSP + Trusted Types) |
| Supressão de auditoria | Evento na mesma transação; append-only por grant + trigger | O dono do banco pode desligar o trigger (hash-chain no backlog) |
| Malware no cliente | Fora de escopo | — |

## Autenticação e limites (RNF-01)

- **Lockout por conta (10 falhas em 15 min → bloqueio de 15 min).** A contagem é por
  `sha256(e-mail)` na tabela `limites`, numa instrução atômica, antes da verificação. Ela é
  compartilhada por: login (senha ou segundo fator errados), `recuperar/iniciar` (kit ou segundo
  fator errados), `POST /eu/senha` (senha atual errada), `POST /eu/mfa/confirmar` e
  `DELETE /eu/mfa` (código errado). Sucesso em qualquer um zera a contagem.
- **DoS dirigido aceito.** Quem conhece o e-mail de alguém consegue bloquear o login dessa conta
  por 15 min, repetidamente, sem saber a senha. É o preço de não permitir força bruta e de
  responder igual para e-mail existente e inexistente. Mitigação: o bloqueio não se estende
  durante a vigência (tentativas bloqueadas não somam), o limite por IP (20/min) freia um
  atacante só, e o evento `auth.bloqueio` fica na auditoria. Sem desbloqueio manual no MVP.
- **Respostas públicas sem enumeração.** `prelogin`, `login` e `recuperar/iniciar` devolvem os
  mesmos bytes para e-mail inexistente e para credencial errada (testado comparando o corpo
  cru). `401 mfa_requerido` só sai depois de senha (ou kit) válidos — revela que o primeiro
  fator acertou, por natureza; essa tentativa também conta no lockout.
- **Limite de concorrência do Argon2.** Cada hash/verificação Argon2 do servidor usa 64 MiB.
  No máximo `COFRE_ARGON2_CONCORRENCIA` (padrão 2) rodam juntos; as demais esperam até 10 s e
  então recebem `503 {"erro":"ocupado"}` (o front mostra "Servidor ocupado, tente em instantes").
  Tudo que chama Argon2 o faz fora de transação aberta, para a espera não segurar conexão.
- **Degradação sob flood distribuído (aceita).** Um atacante com muitos IPs, cada um abaixo de
  20 req/min, mantém as duas vagas do Argon2 ocupadas e usuários legítimos passam a receber
  `503 ocupado` enquanto durar o ataque. Não há perda de dados nem de memória (o teto protege o
  container). Mitigação adicional fica no proxy (Fase 9).
- **`X-Forwarded-For` forjado sem proxy.** A API roda com `--proxy-headers
  --forwarded-allow-ips '*'` e o limite por IP usa o IP que o uvicorn extrai do XFF. Isso só é
  seguro com o Caddy na frente sobrescrevendo o XFF. Se a porta 8098 ficar alcançável sem o
  proxy, um cliente troca o XFF a cada requisição e contorna o limite por IP (o limite por conta
  continua valendo). Hoje a porta só escuta em `127.0.0.1`; a Fase 9 fecha o ponto (configuração
  do Caddy confirmada e `--forwarded-allow-ips` restrito ao proxy).
- **Purga de `limites`.** Sem job externo: as linhas sem bloqueio vigente e com janela iniciada
  há mais de 15 min são apagadas a cada credencial válida e também quando a janela de um IP/rota
  abre (1ª requisição do minuto em `contar_ip`). Elas seriam recriadas do zero na próxima
  tentativa, então apagar não muda nenhuma regra; e a tabela fica limitada ao que está dentro
  das janelas mesmo sob ataque sem nenhum login válido.

- **Limite de corpo (Fases 7 e 8).** Antes de qualquer parse, um middleware ASGI confere o
  `Content-Length` e conta os bytes do stream (inclusive `Transfer-Encoding: chunked`): 256 KiB
  por padrão; 20 MiB só em `rotacionar`, promoção e reativação de owner, e só para sessão
  **válida com a permissão da rota** (uma consulta antes de ler o corpo: sessão viva, usuário
  `ativo`, sem MFA pendente e `gerenciar` na coleção para `rotacionar` / papel owner para
  `papel` e `reativar`, as únicas que mandam envelopes de todas as coleções). Um member com
  `editar` ou um admin com sessão válida não pega a vaga grande nem passa de 256 KiB. Toda recusa
  (408/413/503) vai ao log `corpo_recusado` com `usuario_id` quando a sessão foi consultada, e
  408/503 de usuário autenticado também viram o evento `requisicao.recusada`. Cookie inventado, revogado ou expirado fica nos 256 KiB. Corpo grande tem
  prazo de leitura (`COFRE_PRAZO_CORPO_S`, padrão 60 s): estourou → `408 corpo_lento` e a vaga
  é liberada, então um envio lento autenticado atrasa as outras rotações no máximo esse prazo,
  e com sessão identificada. Acima → `413 {"erro":"corpo_grande"}`. Corpo acima de 256 KiB é um por vez (o
  segundo recebe `503 ocupado` + `Retry-After: 5`), porque o parse JSON de 20 MiB ocupa várias
  vezes isso em memória. Antes, três POSTs de 150 MB sem cookie (até no `/prelogin`) derrubavam
  a API por OOM. Carga reproduzível: `scripts/carga_corpo.py` (6 POSTs de 150 MB em paralelo,
  metade chunked, sem cookie → 6 × 413, `RestartCount` 0, pico 63 MiB).
- **Memória de uma rotação grande (medida).** Rotação real de 18,9 MiB (158 itens com blobs de
  ~63 KiB): pico de 79 MiB no container. Pior caso patológico, 18,9 MiB em 105 mil entradas
  minúsculas: 219 MiB (o processo não devolve essa memória ao sistema). Somado às duas vagas do
  Argon2 (2 × 64 MiB) fica abaixo do `mem_limit` de 384 MiB, com pouca folga: a rotação limita
  `itens` a 20 000 e `versoes` a 100 000 por requisição e, na Fase 9, vale considerar 512 MiB.

## MFA (RF-I03, RF-I04)

- TOTP RFC 6238 (SHA-1, 6 dígitos, 30 s, janela ±1) com `hmac` da stdlib; vetores do Apêndice B
  nos testes. Um passo vale uma vez (anti-replay atômico em `totp_ultimo_passo`).
- O segredo TOTP fica cifrado (envelope `v1`, AES-256-GCM, AAD com o id do usuário) com a
  subchave `totp` de `COFRE_SEGREDO`. Quem tem banco **e** `COFRE_SEGREDO` tem os segredos TOTP:
  o segundo fator protege contra senha vazada, não contra comprometimento do servidor.
- Os 10 códigos de recuperação (40 bits cada, `secrets`) ficam só como
  `HMAC-SHA256(pepper, código)`, aparecem uma vez e valem uma vez.
- Política `mfa_obrigatorio` (padrão **desligada** desde a Fase 7, por decisão do usuário; a org liga em `PUT /org/politica`): sessão de usuário sem MFA só alcança `/eu`,
  `/eu/mfa/*` e `/logout`. A condição é recalculada a cada requisição, então ligar a política
  vale na hora para sessões já abertas.

## Recuperação por kit (RF-U06)

- `recuperar/iniciar` exige o `recup_auth` derivado da Recovery Key **e** o segundo fator (se o
  MFA estiver ativo) antes de entregar a userKey envelopada pelo kit. O token de conclusão vale
  5 min, uma vez. A conclusão troca senha e kit e revoga todas as sessões.
- Qualquer troca de credencial (conclusão de recuperação, `POST /eu/senha`, ativar ou desativar
  o MFA) invalida **todos** os tokens de recuperação pendentes do usuário na mesma transação:
  um token "estacionado" antes não desfaz a remediação do dono. A conclusão reconfere o estado
  da conta (suspensa/removida → 401 `token_invalido`, nada muda).
- Desativar o MFA revoga as outras sessões do usuário (como a troca de senha).
- Segredo TOTP adulterado ou trocado entre usuários (AAD com o id) falha fechado: 401
  `mfa_invalido` e evento `auth.mfa` falha (`meta.metodo = totp_segredo_invalido`).
- Sem senha-mestra e sem kit, o acesso pessoal é perdido (D18).

## Coleções e itens (Fase 6)

- **Zero-knowledge.** Nome de coleção, meta e segredo de item chegam como envelopes `v1`
  cifrados no navegador com a collectionKey; a collectionKey chega como envelope `x1` por
  membro. O servidor confere formato (regex de §3.1/§3.2), tamanho (64 KiB por blob, `422
  blob_grande`), permissão e versões, e nunca decifra nada. O AAD amarra cada blob a org,
  coleção, item, `chave_ver` e `versao`: blob movido de item ou de versão não decifra.
- **Autorização.** Sem envelope na coleção = `404 nao_encontrado` em toda rota dela, com os
  mesmos bytes de um id inexistente (inclusive para item de outra coleção ou de outra org).
  Com envelope e nível abaixo do mínimo: `403 sem_permissao`. Toda rota relê o estado do
  usuário (`FOR SHARE`) e o envelope (`FOR SHARE`) na transação que grava/entrega: uma
  suspensão em andamento faz a requisição esperar e terminar em `401`, sem efeito.
- **Revelar é auditado (RF-A02/A03).** `segredo_cif` só sai por `GET /itens/{id}/segredo` e
  `GET /itens/{id}/versoes/{v}`, com o evento gravado na mesma transação: se o evento falhar,
  nada é entregue (500). `sync` e lixeira nunca trazem `segredo_cif`.
- **Copiar é melhor esforço.** `POST /itens/{id}/copiado` é o cliente avisando; quem já
  revelou o segredo pode copiá-lo sem avisar. A limpeza do clipboard em 30 s também é melhor
  esforço (o navegador pode negar a leitura; outro app pode ter guardado o conteúdo).
- **Histórico.** As 10 versões anteriores mais recentes ficam em `item_versoes` (autor e data
  de cada uma). `PUT` exige `If-Match` com a versão atual (`428`/`409 conflito_versao`).
- **Lixeira.** 30 dias. A purga é preguiçosa: acontece no `sync` de quem tem envelope na
  coleção (evento `item.purgado`, `meta.modo = automatico`); apagar definitivo grava o mesmo
  tipo com `meta.modo = manual`. Item vencido de coleção que ninguém sincroniza fica no banco
  até alguém sincronizar.

### Limitações aceitas (RF-O05)

- **`ver_sem_revelar` não protege contra quem usa a credencial.** A permissão impede que o
  servidor entregue o segredo à pessoa, mas o item continua sendo usado por ela (ex.: login
  preenchido por outra ferramenta, pessoa que vê a tela de quem revelou). É controle de
  exposição contra servidor honesto, não sigilo contra o membro: quem tem `ver_sem_revelar`
  tem a collectionKey e decifra o `segredo_cif` que obtiver por outro caminho (backup vazado,
  servidor desonesto).
- **Quem tem a collectionKey pode forjar blob.** Qualquer membro (mesmo `ver_sem_revelar`)
  recebe a collectionKey para ler os metadados; com ela consegue cifrar um item válido. O
  servidor só barra a **gravação** por permissão; sem assinatura (D9), um servidor malicioso
  ou um membro com a chave e acesso ao banco forja conteúdo que decifra normalmente.
- **Rollback para blob antigo legítimo não é detectado** (o AAD impede trocar de contexto, não
  voltar a uma versão anterior do mesmo contexto). Manifesto assinado fica no backlog.
- **`sync` sem paginação**: dimensionado para alguns milhares de itens por usuário.

## Compartilhamento, revogação e offboarding (Fase 7)

- **Dados para a rotação.** `GET /colecoes/{id}/rotacao` (`gerenciar`) entrega membros, todos os
  itens com `segredo_cif` (inclusive lixeira) e todas as versões numa resposta, com um evento
  `colecao.rotacao_iniciada` (contagens). Quem rotaciona vê todos os segredos (precisa, para
  recifrar); o evento registra isso de forma distinguível de uma revelação humana.
- **Rotação atômica (RF-U04).** `POST /colecoes/{id}/rotacionar` numa transação: coleção
  `FOR UPDATE`, itens `FOR UPDATE`, todas as validações (membros atuais, todos os itens inclusive
  lixeira na versão atual, todas as versões) antes da primeira escrita. Duas rotações
  simultâneas: uma 200, a outra 409 `chave_ver_desatualizada`. Edição durante a rotação: 409 e o
  cliente refaz. Rotas de item travam a coleção antes do item (mesma ordem da rotação), senão as
  duas se travariam em ordem inversa (deadlock, testado por mutação).
- **O que a rotação resolve e o que não.** Ex-membro com a collectionKey antiga não decifra nada
  gravado depois da rotação (testado no E2E do front com os módulos reais). O que ele viu antes
  continua conhecido: por isso cada item fica `rotacao_senha_pendente` até alguém editar com
  `senha_trocada=true` (troca no sistema de origem).
- **Remoção (RF-U03).** `DELETE /membros/{id}` apaga os envelopes, marca as coleções e os itens e
  devolve o relatório (ids); desde a Fase 8 o mesmo relatório fica no `meta` do evento
  `membro.removido` (ids não são segredo), consultável depois em `GET /auditoria`.
- **Membro suspenso continua recebendo a chave nova nas rotações.** A rotação envelopa a chave
  nova para todos os membros da coleção, inclusive suspensos. Suspensão é reversível e não tira
  o acesso às coleções (só corta sessões): se a rotação o deixasse de fora, ao ser reativado ele
  teria envelope de uma `chave_ver` antiga e perderia a coleção até alguém compartilhar de novo.
  Isso não vaza nada: suspenso não tem sessão, e o envelope só abre com a chave privada dele.
  Para tirar a pessoa de verdade, remove-se o membro (coleção) ou a pessoa (org), o que marca
  rotação. Pela mesma razão a reativação de owner recusa envelope que substituiria o que ele já
  tem (409 `envelope_existente`): o guardado pode ser o de uma rotação feita durante a suspensão.
- **Corrida rotação × membros.** Se alguém entra ou sai da coleção entre o `GET /rotacao` e o
  `POST /rotacionar`, o conjunto de envelopes deixa de bater com os membros: 409
  `membros_alterados`, nada muda e o cliente refaz com os membros atuais.
- **Degradação da vaga de corpo grande (aceita).** Há uma vaga para corpo acima de 256 KiB por
  processo. Um usuário com permissão legítima (gerente de alguma coleção, ou owner) que envia
  corpos grandes devagar segura a vaga até o prazo de leitura (60 s) e repete: as rotações e
  promoções dos outros recebem `503 ocupado` enquanto durar. O efeito é só disponibilidade dessas
  três rotas; o atacante precisa de credencial válida com a permissão; cada recusa fica no log
  com o `usuario_id` e vira evento `requisicao.recusada`; suspender a conta encerra o abuso.
- **D13 (owners).** Promoção a owner e reativação de owner exigem envelopes `gerenciar` das
  coleções (todas / as que faltam); coleção nova exige envelope de todo owner ativo; owner não
  perde `gerenciar` nem sai de coleção (409 `owner_gerencia`). Testado depois de toda operação.
- **Integridade do tipo.** O AAD de meta e segredo inclui o `tipo` do item: o servidor não troca
  o tipo exibido sem quebrar a decifragem; o cliente ainda confere as chaves do JSON contra o tipo.

## Backup e restauração (RNF-05/06, Fase 8)

- `scripts/backup.sh` só conhece a chave **pública** `age` (`BACKUP_AGE_RECIPIENT`) e recusa uma
  chave privada nessa variável sem imprimi-la. A privada fica fora do host e só é usada pelo
  `restaurar.sh` (`AGE_IDENTITY`) numa verificação ou restauração.
- O dump é cifrado no pipe (`pg_dump | age`): o texto do dump nunca vai ao disco do host. O
  `.age` não contém sentinela em claro (DoD 5), e o dump decifrado também não, porque o banco só
  guarda blobs cifrados no navegador.
- A cópia externa no R2 é só `rclone copyto` de arquivo novo; o script nunca apaga nada lá (a
  validade é a do ciclo de vida do bucket) e não envia quando o uso projetado passaria de 9 GB
  (90% do plano grátis). Detalhes e cálculo de operações: `operacao.md`.

## Matriz requisito → controle (RNF-15b)

| Requisito | Controle | Verificação |
|---|---|---|
| RNF-C01 zero-knowledge | Cifragem só no navegador; servidor confere formato e permissão | E2E do front (`pg_dump` e logs sem sentinela); DoD 5 da Fase 8 (dump restaurado sem `SENT-`) |
| RF-A01 eventos de §5.6 | `app/auditoria.py` na transação da ação | `tests/test_eventos_completos.py` (todo tipo, uma vez, com org/ator/ip/user_agent) |
| RF-A02/A03 revelar auditado | Evento na mesma transação; `segredo_cif` só em rotas auditadas | `tests/test_cofre.py` (trigger que falha → 500 sem segredo) |
| RF-A04 append-only | Grant + trigger em `eventos` | `tests/test_eventos_append_only.py` |
| RF-A06 consulta de auditoria | `GET /auditoria` owner/admin, SQL fixo com bind, cursor por id | `tests/test_auditoria.py` |
| RF-O02/O03/O04 autorização | Dependências de papel + envelope por coleção (404 sem envelope) | `tests/test_matriz_autorizacao.py` (46 rotas × 9 atores, com completude) |
| RF-O05 limitações | Este documento + aviso na UI ao escolher a permissão | Revisão manual |
| RNF-01 força bruta | `limites` por IP e conta | `tests/test_limites.py`, `tests/test_login.py` |
| RNF-05 backup cifrado | `scripts/backup.sh` (age, retenção 7+4+3, R2 com guarda de cota) | `tests/test_backup.py`; job `backup` do CI |
| RNF-06 restauração testada | `scripts/restaurar.sh --verifica` | Job `backup` do CI; DoD 5 (arquivo truncado → falha) |
| RNF-07 logs sem segredo | Formatter JSON sem corpo/query; tokens só no corpo | `tests/test_sentinela_logs.py` (todas as rotas), `tests/test_logs.py` |
| RNF-15a ROPA | `docs/ropa.md` | Revisão manual |
| RNF-15d anonimização | Remoção troca nome/e-mail; eventos mantêm `ator_id` | `tests/test_membros.py` |
| RNF-15e incidente | `docs/incidente.md` | Revisão manual |
| D13 owners | Envelopes `gerenciar` validados em criação/promoção/reativação | `tests/test_compartilhar.py` (invariante após cada teste) |
| Limite de corpo | Middleware `LimiteCorpo` | `tests/test_limite_corpo.py` |
