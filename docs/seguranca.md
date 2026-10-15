# Segurança — riscos aceitos e controles da API

Documento vivo. A Fase 8 completa a matriz requisito → controle (RNF-15b). Aqui ficam os
riscos residuais conhecidos e as decisões que os aceitam.

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

- **Limite de corpo (Fase 7).** Antes de qualquer parse, um middleware ASGI confere o
  `Content-Length` e conta os bytes do stream (inclusive `Transfer-Encoding: chunked`): 256 KiB
  por padrão; 20 MiB só em `rotacionar`, promoção e reativação de owner, e só com cookie de
  sessão. Acima → `413 {"erro":"corpo_grande"}`. Corpo acima de 256 KiB é um por vez (o
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
  devolve o relatório (ids); o evento `membro.removido` guarda só contagens.
- **D13 (owners).** Promoção a owner e reativação de owner exigem envelopes `gerenciar` das
  coleções (todas / as que faltam); coleção nova exige envelope de todo owner ativo; owner não
  perde `gerenciar` nem sai de coleção (409 `owner_gerencia`). Testado depois de toda operação.
- **Integridade do tipo.** O AAD de meta e segredo inclui o `tipo` do item: o servidor não troca
  o tipo exibido sem quebrar a decifragem; o cliente ainda confere as chaves do JSON contra o tipo.
