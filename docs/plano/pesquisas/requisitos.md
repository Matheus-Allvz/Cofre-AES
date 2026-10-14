# Cofre de Senhas Empresarial — Pesquisa de Requisitos

Escopo: requisitos funcionais (RF), não funcionais (RNF), fluxos e decisão de banco para uma empresa de 10–200 usuários. A arquitetura criptográfica (zero-knowledge, hierarquia de chaves) é tratada por outro pesquisador; aqui só aparecem as dependências dela (marcadas **[CRIPTO]**).

Prioridades: **MVP** = necessário para chamar o sistema de "empresarial"; **Desej.** = segunda onda; **Fora** = não vale o custo para este projeto.

## 1. Estado atual (lido no código)

- Modelo: `cofres` (UUID + verificador da senha-mestra) e `segredos` (título, usuário, url em claro; senha em AES-GCM). `README.md`, `app/main.py`, `sql/esquema.sql`.
- Autenticação: header `X-Senha-Mestra` em toda chamada. A senha-mestra única compartilhada é a "identidade". Não existe usuário, papel, sessão, auditoria, MFA, rate limit nem lixeira.
- `PUT` sobrescreve a senha sem guardar a anterior. `DELETE` é físico.
- RLS com política `laboratorio` (`anon` com `using (true)`): quem tiver a chave anon lê e escreve as tabelas direto no Supabase, sem passar pela API. Isso é bloqueador para qualquer uso real.
- Frontend (`app.js`): não persiste a senha em storage (comentário no topo), copia para o clipboard via `navigator.clipboard`, sem temporizador de limpeza nem de bloqueio.
- Observabilidade já especificada na VPS: OTel Collector, VictoriaMetrics, Loki, Tempo, Grafana, Uptime Kuma, formatter JSON com TraceContext, backup de SQLite de 14 dias (`OBSERVABILITY_PLATFORM_SPEC.md` §2, §4). Dá para reaproveitar tudo sem montar infraestrutura nova.

## 2. O que os produtos de referência entregam

| Capacidade | Bitwarden Teams/Ent. | 1Password Business | Passbolt | Keeper | Vaultwarden |
|---|---|---|---|---|---|
| Papéis | Owner, Admin, User, Custom (Ent.) [B1] | Owners, Administrators, Team Members, Security, Provision Managers [P1] | Admin / User + grupos [PB1] | Owner/admin/user + roles (não verificado) | Owner, admin, manager, user [V1] |
| Permissão por coleção | View, View sem senha, Edit, Edit sem senha, Manage [B2] | Permissões por vault | Read / Update / Owner por recurso | Não verificado | Igual ao Bitwarden [V1] |
| Eventos / auditoria | 60+ tipos, retenção indefinida, export CSV e API; eventos de cliente sofrem atraso e podem ser suprimidos [B3] | Activity log (grupo Security) | Audit log no admin guide [PB1] | Não verificado | Event logs [V1] |
| Políticas da org | Master password, 2FA obrigatório, session timeout, remover export, entre outras [B4] | Via política de conta | Políticas de admin | Não verificado | Policies [V1] |
| MFA | TOTP, WebAuthn, e-mail, Duo | TOTP + Secret Key | TOTP, Duo, YubiKey (não verificado) | Não verificado | TOTP, WebAuthn |
| SSO | SAML/OIDC (Ent.) | SSO via IdP | SSO (Pro/Ent.) | SAML | OIDC parcial; sem SCIM [V1] |
| Recuperação de conta | Admin account recovery (Ent.) | Owners/Admins recuperam contas [P1] | Account recovery com chave de organização | Não verificado | Admin password reset [V1] |

Lições que importam para o desenho:
1. A senha-mestra é o ponto central de todos os produtos. Mesmo com SSO, o Vaultwarden mantém a senha-mestra porque ela deriva a chave do cofre [V1]. SSO não elimina a senha-mestra e fica fora do MVP.
2. "Ver sem revelar a senha" é um nível de permissão, mas o Bitwarden avisa que é só limitação de UI: quem pode usar a credencial acaba tendo acesso a ela [B2]. O requisito precisa documentar essa limitação.
3. Log gerado no cliente é fraco como evidência [B3]. Aqui o servidor da API grava o evento antes de devolver o segredo, porque o servidor é quem decide. Isso depende da arquitetura criptográfica escolhida; ver **[CRIPTO]** em RF-A03.

## 3. Requisitos Funcionais

Convenção do critério de aceite: teste automatizado (pytest/httpx) salvo indicação contrária.

### 3.1 Identidade e acesso

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RF-I01 | Cadastro **somente por convite**: admin gera convite com e-mail, papel e validade. `POST /usuarios` aberto não existe. | MVP | Chamada de cadastro sem token de convite válido retorna 403. Convite expirado ou já usado retorna 410. Convite é de uso único. |
| RF-I02 | Login com e-mail + senha-mestra. A senha-mestra **nunca** é header em toda requisição; o login emite token de sessão de curta duração. | MVP | Nenhuma rota de dados aceita `X-Senha-Mestra`. Requisição sem token retorna 401. |
| RF-I03 | MFA TOTP (RFC 6238) com 10 códigos de recuperação de uso único; segredo TOTP guardado cifrado. | MVP | Login com senha correta e sem TOTP não emite sessão completa. Código reutilizado na mesma janela é recusado. |
| RF-I04 | Política "MFA obrigatório" (ver RF-P): usuário sem MFA só acessa o fluxo de configuração. | MVP | Com a política ativa, qualquer rota de dados retorna 403 `mfa_required` até o MFA ser configurado. |
| RF-I05 | WebAuthn/passkey como segundo fator. | Desej. | Registro e login com chave FIDO2 em teste manual documentado. |
| RF-I06 | SSO OIDC (Google/Entra) como autenticação do login. A senha-mestra continua existindo [V1]. | Fora | Não implementar; registrar a decisão. |
| RF-I07 | SAML, SCIM, sincronização de diretório (LDAP/AD). | Fora | — |
| RF-I08 | Sessão: token com expiração absoluta (ex.: 12 h) e ociosa (ex.: 15 min), revogável no logout. Lista de sessões ativas com "encerrar". | MVP | Token expirado retorna 401. Após logout o mesmo token retorna 401. |
| RF-I09 | Bloqueio automático do cofre no cliente por inatividade (chave em memória descartada) e ao fechar a aba. | MVP | Teste manual: após o tempo configurado a tela volta ao desbloqueio e nada é lido de storage. |
| RF-I10 | Troca de senha-mestra (exige a senha atual e MFA) que invalida as outras sessões. **[CRIPTO]**: reembrulhar chaves, sem recifrar todos os itens. | MVP | Após a troca, a senha antiga falha e as sessões anteriores retornam 401. Os itens continuam legíveis. |

### 3.2 Organização, coleções e papéis

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RF-O01 | Entidade **Organização** (uma por instalação no MVP; modelo já com `org_id`). | MVP | Toda tabela de negócio tem `org_id`; consulta sem filtro de org retorna zero linhas em teste. |
| RF-O02 | Papéis: **owner** (≥1; único que gerencia a org e transfere posse), **admin** (usuários, políticas, auditoria, todas as coleções), **manager** (gerencia as coleções que lhe forem atribuídas), **member** (usa coleções atribuídas). | MVP | Matriz de autorização testada: cada rota × papel retorna o código esperado (tabela em teste parametrizado). |
| RF-O03 | Papel **read-only** como nível de permissão por coleção (e não como papel global). | MVP | Usuário com `ver` não consegue `POST/PUT/DELETE` nessa coleção (403). |
| RF-O04 | **Coleções** (pastas compartilhadas) com permissões por usuário ou grupo: `ver`, `ver sem revelar senha`, `editar`, `gerenciar`. Permissão do usuário prevalece sobre a do grupo [B2]. | MVP | Para cada nível, teste confirma o que a API permite e nega. Em `ver sem revelar`, `GET .../senha` retorna 403 mas a listagem funciona. |
| RF-O05 | Limitação documentada: "ver sem revelar senha" não protege quem pode usar/copiar a credencial [B2]. | MVP | Parágrafo presente na documentação e no tooltip da UI. |
| RF-O06 | Grupos de usuários (ex.: "Financeiro") como destino de permissão. | Desej. | Atribuir coleção a um grupo dá acesso a todos os membros; remover o membro revoga o acesso. |
| RF-O07 | Cofre pessoal por usuário, além das coleções da org. | Desej. | Item pessoal não aparece nem na auditoria de itens de outros, e admin não o lê. |
| RF-O08 | Papéis customizados. | Fora | — |

### 3.3 Ciclo de vida do usuário

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RF-U01 | Convite → aceite → confirmação por admin **[CRIPTO]** (o admin libera o acesso às chaves da coleção depois que o usuário cria a sua). Estados: `convidado`, `aceito`, `ativo`, `suspenso`, `removido`. | MVP | Máquina de estados testada; transições inválidas retornam 409. |
| RF-U02 | **Suspensão**: bloqueia login e revoga sessões imediatamente, sem apagar o usuário. | MVP | Após suspender, token existente retorna 401 em ≤ 1 requisição e novo login é recusado. |
| RF-U03 | **Offboarding**: remover usuário revoga acesso a todas as coleções, lista as coleções que ele alcançava e marca as senhas dessas coleções para rotação. | MVP | O relatório "credenciais a rotacionar" lista todos os itens de que o usuário tinha acesso. A API impede remover o último owner. |
| RF-U04 | Rotação: item marcado como "rotação pendente" aparece em painel até alguém editar a senha. **[CRIPTO]**: se houver chave de coleção, rotacioná-la para revogar de fato. | MVP | Item pendente some do painel apenas após `PUT` com nova senha. |
| RF-U05 | Transferência de posse: owner passa o papel a outro usuário (exige MFA); itens e coleções de quem sai são reatribuídos a um admin. | MVP | Org sem owner é impossível. Itens de usuário removido ficam acessíveis ao admin. |
| RF-U06 | **Recuperação de conta**: ver decisão abaixo. | MVP (opção A) | Ver fluxo 5.7. |
| RF-U07 | Desprovisionamento automático via SCIM. | Fora | — |

Decisão sobre recuperação (RF-U06). O modelo zero-knowledge não permite o servidor repor a senha-mestra. Opções:
- **A (recomendada para MVP):** *recovery key* gerada no cadastro (formato 1Password "Secret Key"), baixada/impressa pelo usuário. Perder senha e chave resulta em perda dos itens pessoais; itens de coleção continuam acessíveis aos demais membros. Menor complexidade.
- **B (Desej.):** *admin account recovery* (Bitwarden/1Password/Passbolt [B4][P1]). Exige que o usuário aceite um "reset de senha" que concede ao admin uma capacidade criptográfica. Maior superfície de ataque.

### 3.4 Itens

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RF-T01 | Tipos de item: **login** (título, usuário, senha, URLs, notas), **nota segura**, **chave de API/segredo** (nome, valor, validade opcional). | MVP | Cada tipo faz CRUD completo e valida os campos obrigatórios. |
| RF-T02 | Cartão de pagamento. Escopo PCI desaconselha guardar; Bitwarden tem política para *remover* o tipo [B4]. | Fora | — |
| RF-T03 | Campos customizados (texto/oculto). | Desej. | Campo oculto não aparece em listagens. |
| RF-T04 | TOTP por item (guardar semente e exibir código de 6 dígitos). | Desej. | Código gerado bate com o de um app de referência para a mesma semente. |
| RF-T05 | **Anexos**: arquivos cifrados, limite 5–10 MB, no disco/volume da VPS. | Desej. | Upload acima do limite retorna 413; arquivo baixado é idêntico ao enviado; não fica em claro em disco. |
| RF-T06 | **Histórico de versões** da senha (últimas N, padrão 10), com restauração e quem alterou. O `PUT` atual perde a senha anterior. | MVP | Após 3 edições há 3 versões; restaurar a v1 recria a senha e gera nova versão. |
| RF-T07 | **Lixeira**: `DELETE` vira exclusão lógica por 30 dias; restaurar por quem tiver `editar`; exclusão definitiva por admin/manager ou após o prazo. | MVP | Item excluído some da listagem, aparece na lixeira e é restaurável. Após 30 dias um job o remove (teste com relógio simulado). |
| RF-T08 | Gerador de senhas (tamanho, classes de caracteres, passphrase) com CSPRNG (`secrets`). Pode ser 100% no cliente (`crypto.getRandomValues`). | MVP | Senha gerada respeita os parâmetros; teste estatístico simples de distribuição. |
| RF-T09 | Verificação de senha vazada via **HIBP Pwned Passwords** com k-anonymity: envia só os 5 primeiros caracteres do SHA-1, use `Add-Padding: true`; a API é gratuita e sem limite de taxa documentado [H1]. Chamada feita pelo cliente ou por proxy do backend, **nunca** enviando a senha completa. Opcional e desligável por política (privacidade/saída de rede). | Desej. | Em teste, a requisição capturada contém só 5 caracteres de hash; senha conhecida ("password") retorna contagem > 0. |
| RF-T10 | Copiar para clipboard com limpeza automática após 30 s e senha mascarada por padrão com botão "revelar". | MVP | Teste manual: após 30 s o clipboard é esvaziado (se não foi alterado). |
| RF-T11 | Busca por título/usuário/URL só entre itens acessíveis ao usuário. | MVP | Resultado nunca contém item de coleção não atribuída. |
| RF-T12 | Importação (CSV Bitwarden/Chrome) e exportação cifrada. Exportação sujeita à política RF-P04. | Desej. | Export em claro exige re-autenticação com MFA e gera evento. |

### 3.5 Auditoria

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RF-A01 | Eventos obrigatórios (todos com `quando`, `ator`, `org`, `ip`, `user-agent`, `alvo`, `resultado`): login ok/falha, logout, MFA ok/falha, bloqueio de conta, **revelar senha**, **copiar senha**, criar/editar/excluir/restaurar item, compartilhar, mudar permissão, convidar/aceitar/suspender/remover usuário, mudar política, **export**, troca de senha-mestra, criação/uso de código de recuperação. | MVP | Teste: cada ação gera exatamente um evento com os campos acima. |
| RF-A02 | O evento é gravado **no servidor, na mesma transação** da ação sensível. Se a gravação falhar, a ação falha (revelar senha sem log é proibido). Motivo: eventos gerados no cliente podem ser suprimidos [B3]. | MVP | Teste que força erro na tabela de auditoria e verifica que o `GET` da senha retorna 500, sem a senha. |
| RF-A03 | "Copiar" é ação do cliente: registrar via `POST /auditoria/copia` logo antes de entregar o clipboard, e documentar que a cópia local é de melhor esforço. Como a revelação (`GET` da senha) é sempre mediada pelo servidor, o evento autoritativo é "revelar". **[CRIPTO]**: se o desenho for zero-knowledge puro (o servidor nunca vê a senha), a revelação também é só do cliente; nesse caso, exigir *token de acesso a item* emitido pelo servidor (que registra) antes de entregar o blob cifrado. | MVP | Sem chamar o endpoint do token não há blob; cada chamada gera evento. |
| RF-A04 | **Append-only**: o usuário da aplicação tem só `INSERT`/`SELECT` na tabela de eventos (`REVOKE UPDATE, DELETE`), e há trigger que bloqueia `UPDATE/DELETE`. Opcional: cadeia de hash (`hash = H(prev_hash ‖ evento)`) para detectar adulteração. | MVP (grants + trigger) / Desej. (hash) | Tentativa de `UPDATE`/`DELETE` com o usuário da app falha com erro de permissão. Com hash: script de verificação detecta linha alterada. |
| RF-A05 | Retenção: 12 meses online, depois arquivado (export cifrado) por mais 12–24 meses, conforme a política da empresa. A janela deve ser configurável e documentada. | MVP | Job de arquivamento testado; configuração visível no painel admin. |
| RF-A06 | Consulta pelo admin: filtros por data, usuário, ação, alvo; paginação. Usuário comum vê só o próprio histórico de login. | MVP | Member não acessa `/auditoria` (403); admin filtra e pagina. |
| RF-A07 | Exportação do log (CSV/JSON), ela mesma auditada. Eventos replicados também para Loki (JSON estruturado), **sem** valores de segredo. | Desej. | Export gera evento `audit.export`; busca no Loki de uma senha de teste retorna zero resultados. |
| RF-A08 | Alertas: N falhas de login seguidas, login de IP novo, export, mudança de política. Via Grafana/Alertmanager. | Desej. | Alerta de teste dispara com 5 falhas em 5 min. |

### 3.6 Políticas da organização

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RF-P01 | **Força mínima da senha-mestra** (tamanho ≥ 12, opcional zxcvbn ≥ 3) aplicada no cadastro e na troca. | MVP | Senha abaixo do mínimo retorna 422 com a regra violada. |
| RF-P02 | **MFA obrigatório** (RF-I04). | MVP | Ver RF-I04. |
| RF-P03 | **Timeout** de sessão e de bloqueio do cofre configuráveis pela org (limites mín./máx.). | MVP | O cliente respeita o valor da org; valor fora do limite é rejeitado. |
| RF-P04 | **Bloquear export** de dados por membros (somente owner exporta) [B4]. | MVP | Com a política ligada, `POST /export` de member retorna 403. |
| RF-P05 | Restringir criação de coleção a admin/manager. | Desej. | Member recebe 403 ao criar coleção. |
| RF-P06 | Bloquear tipo de item (ex.: cartão) e restringir HIBP. | Desej. | Criar item do tipo bloqueado retorna 403. |
| RF-P07 | Toda alteração de política é auditada e só owner/admin pode alterar. | MVP | Evento `policy.changed` com valor antigo e novo. |

## 4. Requisitos Não Funcionais

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RNF-01 | **Rate limit** por IP e por conta nas rotas de login/MFA/convite/recuperação (ex.: 5 tentativas/min por conta, 20/min por IP), com backoff e **lockout** temporário (15 min) após 10 falhas; resposta uniforme (sem enumeração de e-mail). Implementar no reverse proxy e na aplicação. Referência: ASVS V6 (anti-automação, bloqueio) [A1]. | MVP | Teste: 11ª tentativa retorna 429 e a conta bloqueada recusa até a senha correta; tempo de resposta de e-mail inexistente ≈ existente. |
| RNF-02 | TLS 1.2+ no reverse proxy, HSTS, cookies `Secure; HttpOnly; SameSite`, CSP restritiva e CORS fechado ao domínio do frontend. | MVP | `testssl.sh`/securityheaders sem falha crítica; CORS recusa outras origens. |
| RNF-03 | Hash de autenticação no servidor com parâmetros atuais (Argon2id ≥ 19 MiB, t=2, p=1, ou PBKDF2-SHA256 600 000 iterações) [O1]. O projeto hoje usa PBKDF2 com ≥ 210 000. **[CRIPTO]**: decidir junto ao outro pesquisador. | MVP | Parâmetros em configuração; teste confere o mínimo. |
| RNF-04 | **Disponibilidade** alvo 99,5% (≈ 3,6 h de indisponibilidade/mês), single node na VPS; RTO 4 h, RPO 24 h no MVP (RPO 15 min com WAL se for Desej.). | MVP | Uptime Kuma monitora `/saude`; relatório mensal confere a meta. |
| RNF-05 | **Backup**: `pg_dump` cifrado (age/gpg) diário + cópia **fora da VPS** (S3/Backblaze/outra máquina), retenção 7 diários + 4 semanais + 3 mensais. Chave de cifra do backup guardada separadamente. WAL archiving/PITR (pgBackRest ou wal-g) como Desej. | MVP | Job registra sucesso/tamanho; alerta se o último backup tiver > 26 h. |
| RNF-06 | **Restauração testada**: procedimento escrito e executado em ambiente limpo ao menos a cada trimestre, medindo RTO/RPO; o teste restaura e abre um item de verificação. | MVP | Runbook + registro datado da última restauração; script `restaurar.sh` automatiza o teste e retorna 0 se o item de verificação decifra. |
| RNF-07 | **Logs estruturados** JSON com `trace_id`, sem segredos: filtro que remove campos `senha`, `authorization`, `x-senha-mestra`, tokens, corpo de requisição de rotas sensíveis. Reaproveitar o formatter da spec de observabilidade. | MVP | Teste injeta senha sentinela, exercita todas as rotas e verifica que ela não aparece em log, traço nem métrica. |
| RNF-08 | **Métricas** (OTel → VictoriaMetrics): taxa de login ok/falha, latência p95 por rota, 429, contagem de reveals, erros 5xx, idade do último backup. Dashboard Grafana e alertas. | Desej. | Painel exibe as séries; alerta de teste dispara. |
| RNF-09 | **Health check**: `/saude` (liveness) e `/pronto` (readiness, inclui banco). Docker `HEALTHCHECK` e Uptime Kuma. | MVP | `/pronto` retorna 503 com o Postgres parado. |
| RNF-10 | **Testes e CI**: pytest com cobertura ≥ 80% nas áreas de autorização/cripto/auditoria; Postgres real em container (não mock); lint (ruff), análise estática (bandit), auditoria de dependências (pip-audit) e build de imagem a cada push. | MVP | Pipeline falha com teste, lint ou vulnerabilidade alta quebrada. |
| RNF-11 | **Versionamento de API**: prefixo `/v1`; mudança incompatível vira `/v2`; OpenAPI publicado. Migrações de banco versionadas (Alembic) e reversíveis. | MVP | Contrato OpenAPI do `/v1` está em teste de snapshot; `alembic upgrade/downgrade` roda no CI. |
| RNF-12 | **Segredos de infraestrutura** (DB, chave de backup, JWT) fora do repositório (variáveis de ambiente/Docker secrets), rotacionáveis. | MVP | `gitleaks` limpo no CI. |
| RNF-13 | **Desempenho**: p95 < 300 ms para listar/revelar com 200 usuários e 50 000 itens; derivação de chave limitada para não permitir DoS (fila/limite de concorrência). | Desej. | Teste de carga (k6/locust) com o perfil acima. |
| RNF-14 | **Endurecimento do host**: Postgres só em rede interna Docker, firewall, SSH por chave, atualizações automáticas, usuário não-root no container. | MVP | Varredura externa (nmap) mostra só 80/443/SSH. |
| RNF-15 | **LGPD** (ver §4.1). | MVP | Ver abaixo. |

### 4.1 LGPD — requisitos derivados

O sistema trata dados pessoais dos próprios usuários (nome, e-mail, IP, logs) e, indiretamente, credenciais que podem estar ligadas a pessoas. A empresa é a controladora e a VPS/provedor é operador.

| ID | Requisito | Prior. | Critério de aceite |
|---|---|---|---|
| RNF-15a | **Registro das operações** de tratamento (art. 37): documento com finalidade, base legal, categorias de dados, retenção, operadores e medidas de segurança. A auditoria técnica (RF-A) ajuda, mas não substitui o registro formal [L1]. | MVP | Documento `docs/ropa.md` existe e é referenciado no README. |
| RNF-15b | **Medidas de segurança** técnicas e administrativas (art. 46) documentadas: cifragem, controle de acesso, MFA, backup, auditoria [L1]. | MVP | Matriz requisito → controle presente na documentação. |
| RNF-15c | **Minimização**: coletar só e-mail, nome e papel; o log de IP tem retenção própria; título/URL de itens são dados da empresa, e o usuário é avisado de que não devem conter dados pessoais de terceiros desnecessários. | MVP | Revisão do esquema confirma ausência de campos não justificados. |
| RNF-15d | **Direito de exclusão/anonimização** do titular (art. 18): ao remover usuário, dados pessoais (nome, e-mail) são anonimizados, mas **eventos de auditoria permanecem** com identificador pseudonimizado para cumprir obrigação de segurança/legal. Decisão a registrar com o encarregado (DPO). | MVP | Após exclusão, `GET /usuarios/{id}` não retorna PII; os eventos mantêm `ator_id` sem nome/e-mail. |
| RNF-15e | **Incidente**: procedimento de resposta com comunicação à ANPD e aos titulares em caso de risco ou dano relevante (art. 48). O prazo hoje aplicável deve ser **confirmado no texto oficial da Resolução CD/ANPD nº 15/2024** (as fontes consultadas divergem) [L1]. | MVP | Runbook de incidente com responsáveis, modelo de comunicação e prazo conferido na fonte oficial. |
| RNF-15f | Backups e logs seguem a retenção definida; exclusão de dado pessoal "propaga" ao backup pela expiração natural, documentada. | Desej. | Política de retenção documentada. |

## 5. Fluxos de usuário

### 5.1 Admin cria a organização
1. Na instalação, um comando (CLI do servidor) cria a organização e o primeiro **owner** com um token de bootstrap de uso único; não existe endpoint público de criação.
2. O owner abre o link, define e-mail e senha-mestra (RF-P01 valida a força).
3. **[CRIPTO]** O cliente gera as chaves do usuário e a *recovery key*; o owner a baixa e confirma que a guardou.
4. O sistema obriga a configurar o TOTP: mostra o QR, pede um código, mostra os códigos de recuperação.
5. O owner define as políticas iniciais (MFA obrigatório, timeout, bloqueio de export) e cria a primeira coleção.
6. Auditoria registra `org.created`, `user.activated`, `mfa.enabled`, `policy.changed`.

### 5.2 Admin convida um membro
1. Admin informa e-mail, papel e coleções (com permissão por coleção).
2. O sistema cria o convite (token aleatório, hash armazenado, validade 72 h) e envia o link por e-mail.
3. Estado do usuário: `convidado`. O evento `user.invited` é registrado.
4. O convite pode ser reenviado ou revogado até ser aceito.

### 5.3 Membro aceita e configura MFA
1. O membro abre o link; o servidor valida token, validade e uso único.
2. Define a senha-mestra (política RF-P01); **[CRIPTO]** o cliente gera as chaves e a recovery key.
3. Baixa/confirma a recovery key.
4. Configura o TOTP (obrigatório se a política exigir) e guarda os códigos de recuperação.
5. Estado: `aceito`. O admin vê o pedido pendente e **confirma** (RF-U01); só então o membro recebe acesso às coleções.
6. Eventos: `invite.accepted`, `mfa.enabled`, `user.confirmed`.

### 5.4 Criar item em coleção compartilhada
1. O membro desbloqueia o cofre (senha-mestra + TOTP) e abre a coleção em que tem permissão `editar`.
2. Clica em "Novo item", escolhe o tipo (login/nota/chave de API), preenche; pode usar o gerador (RF-T08) e a checagem HIBP (RF-T09, se habilitada).
3. O cliente cifra o conteúdo; a API valida a permissão `editar` da coleção e grava.
4. Resposta 201; evento `item.created` (coleção, item, ator). Os demais membros passam a ver o item conforme a permissão deles.

### 5.5 Revelar/copiar senha com auditoria
1. O membro abre o item; a senha aparece mascarada.
2. Clica em "revelar" ou "copiar": o cliente chama a API (RF-A03).
3. O servidor checa sessão válida, MFA satisfeito e permissão que **não** seja "ver sem revelar".
4. **Na mesma transação**, grava `item.revealed` ou `item.copied` (quem, qual item, IP). Se falhar, nega (RF-A02).
5. Entrega a senha (ou o blob cifrado); o cliente exibe por 30 s e limpa o clipboard (RF-T10).
6. O admin vê o evento em RF-A06.

### 5.6 Offboarding
1. O admin abre o usuário e escolhe "suspender" (imediato) ou "remover".
2. O sistema invalida todas as sessões e tokens do usuário (RF-U02).
3. Mostra o relatório "credenciais acessíveis por este usuário" (coleções → itens).
4. O admin confirma; o usuário é removido das coleções; itens pessoais dele são transferidos a um admin (RF-U05).
5. Todos os itens do relatório viram "rotação pendente" (RF-U04); **[CRIPTO]** a chave das coleções é rotacionada.
6. Responsáveis alteram as senhas nos sistemas de origem e atualizam os itens; o painel zera.
7. Se o usuário era dono de dados pessoais, aplica-se RNF-15d (anonimização). Eventos: `user.suspended`/`user.removed`, `item.rotation_pending`.

### 5.7 Recuperação de conta
Opção A (MVP, recovery key):
1. Usuário esqueceu a senha-mestra; na tela de login escolhe "recuperar com chave".
2. Informa e-mail, recovery key e um código TOTP (ou código de recuperação do MFA).
3. Define nova senha-mestra; as chaves pessoais são reembrulhadas com ela.
4. O sistema encerra todas as sessões e gera **nova** recovery key.
5. Eventos `recovery.used`, `password.changed`; o admin é notificado.
6. Sem a chave nem a senha: o admin remove o usuário e o convida de novo; o acesso às coleções é recriado, e os itens pessoais são perdidos (aviso explícito no cadastro).

Opção B (Desej., admin recovery): admin dispara "redefinir", o usuário aceita, e o admin só concede a capacidade de recriar chaves, sem ver a senha antiga. Exige a política de recovery ativa [B4].

### 5.8 Restauração de backup
1. Incidente (perda de dados/corrupção). O responsável declara o incidente e congela a escrita (modo manutenção no proxy).
2. Escolhe o ponto de restauração (último dump bom ou PITR) e o baixa da cópia externa.
3. Decifra o backup com a chave guardada separadamente.
4. Restaura num Postgres novo (`pg_restore`/`wal-g`), não por cima do atual.
5. Roda `restaurar.sh --verifica`: confere contagem de tabelas, migração (`alembic current`) e decifragem de um item sentinela.
6. Aponta a aplicação para o banco restaurado; sai do modo manutenção.
7. Registra RTO/RPO medidos, o evento `ops.restore` e abre pós-incidente. Se houve perda de dados pessoais, avalia comunicação conforme RNF-15e.
O mesmo roteiro, em ambiente limpo, é o teste trimestral do RNF-06.

## 6. Decisão: Supabase ou PostgreSQL na VPS

**Recomendação: migrar para PostgreSQL 16 na VPS** (container, rede interna), mantendo SQL puro/Alembic e abandonando `supabase-py`/RLS anônima.

Motivos:
1. **Superfície de ataque**: hoje o frontend e qualquer portador da chave anon alcançam as tabelas via PostgREST com política `using (true)`. Com Postgres interno, só a API acessa o banco; autorização fica numa camada só (ou RLS por `org_id` com `SET LOCAL`, aplicado na transação).
2. **Auditoria append-only de verdade** (RF-A04): `REVOKE`, triggers e papéis separados são triviais no Postgres próprio; no Supabase gerenciado exige disciplina para não passar pelas chaves `service_role`.
3. **Backup e restauração sob controle**: `pg_dump`/WAL/pgBackRest com cópia externa cifrada e teste de restauração em casa. No Supabase, o plano gratuito pausa projetos por inatividade (7 dias) [S1] e as fontes divergem sobre backups no plano gratuito; PITR é complemento pago (~US$ 100/mês por 7 dias) em plano que começa em US$ 25/mês [S1]. Confirmar preços atuais antes de decidir por custo.
4. **Soberania e LGPD**: dados e logs numa infraestrutura sob o controle da empresa, sem transferência a terceiro operador (menos um operador no registro do art. 37).
5. **Integração** com a stack de observabilidade já existente (Postgres exporter → VictoriaMetrics, logs → Loki).
6. **Custo previsível**: a VPS já existe; 8 GB sobram para Postgres + API (+ a stack de observabilidade, que deve ter limites de memória, conforme o runbook).

Contrapartidas assumidas: o time vira responsável por atualizações do Postgres, disco, monitoramento e disponibilidade (RNF-04). Isso é mitigado por RNF-05/06/09 e pelo host endurecido (RNF-14). O Supabase continuaria válido se o objetivo fosse só o trabalho acadêmico, com GoTrue para login e sem requisitos de auditoria/backup. Para o escopo empresarial acima, não é adequado.

Migração: (1) criar o esquema via Alembic; (2) `pg_dump` dos dados atuais do Supabase (só dados de teste); (3) trocar `app/banco.py` por psycopg/SQLAlchemy; (4) remover políticas `laboratorio`; (5) rotacionar as chaves anon/service do projeto antigo e encerrá-lo.

## 7. Resumo de priorização

- **MVP (núcleo empresarial)**: convite (I01), login+sessão (I02, I08), MFA TOTP e política (I03, I04), troca de senha-mestra (I10), org/papéis/coleções/permissões (O01–O05), ciclo de vida completo (U01–U06), itens login/nota/API (T01), histórico, lixeira, gerador, clipboard, busca (T06–T08, T10, T11), auditoria server-side append-only com consulta (A01, A02, A04–A06), políticas P01–P04/P07, rate limit/lockout, TLS, backup externo + restauração testada, logs sem segredo, health, CI, versionamento, LGPD, endurecimento.
- **Desejável**: WebAuthn, grupos, cofre pessoal, campos customizados, TOTP por item, anexos, HIBP, import/export, hash-chain, alertas, métricas, PITR, admin recovery, teste de carga.
- **Fora**: SSO/SAML/SCIM/LDAP, papéis customizados, cartão de pagamento, extensão de navegador/autofill, apps móveis, multi-organização com billing.

## 8. Referências

- [B1] Bitwarden, tipos de usuário e papéis: https://bitwarden.com/help/user-types-access-control/
- [B2] Bitwarden, permissões de coleção: https://bitwarden.com/help/collection-permissions/
- [B3] Bitwarden, event logs (tipos, retenção, limitação de eventos de cliente): https://bitwarden.com/help/event-logs/
- [B4] Bitwarden, políticas de organização: https://bitwarden.com/help/policies/
- [P1] 1Password, grupos, permissões e recuperação: https://support.1password.com/groups/
- [PB1] Passbolt, documentação (Admin Guide: autenticação, provisionamento, RBAC, audit log; detalhes não confirmados na página de índice): https://www.passbolt.com/docs/admin/
- [V1] Comparativos do Vaultwarden (papéis, coleções, eventos, OIDC parcial, sem SCIM; fontes secundárias): https://selfhost.dev/blog/vaultwarden-vs-bitwarden/ e https://www.ssdnodes.com/learn/vaultwarden-vs-bitwarden-self-hosted
- [H1] HIBP Pwned Passwords API (k-anonymity, prefixo de 5 caracteres, `Add-Padding`, sem rate limit): https://haveibeenpwned.com/API/v3#PwnedPasswords
- [O1] OWASP Password Storage Cheat Sheet (Argon2id 19 MiB/t=2/p=1; PBKDF2-SHA256 600 000): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- [A1] OWASP ASVS (mapa V6 Autenticação, V7 Sessão; IDs de requisitos da 5.0 não confirmados no texto oficial): https://cheatsheetseries.owasp.org/IndexASVS.html e https://github.com/OWASP/ASVS
- [S1] Supabase, pausa de projetos, backups e preços: https://supabase.com/docs/guides/platform/free-project-pausing , https://supabase.com/docs/guides/platform/backups , https://supabase.com/pricing
- [L1] LGPD arts. 37, 46, 48 (resumos): https://confidata.com.br/blog/lgpd-comentada-20-controlador-operador-registros , https://confidata.com.br/blog/lgpd-comentada-23-seguranca-incidentes ; texto da lei: https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm ; Resolução CD/ANPD nº 15/2024: https://www.gov.br/anpd

Normas (ISO 27001:2022 A.5.15–5.18 controle de acesso/identidade/credenciais, A.8.5 autenticação segura, A.8.15 registro de logs; CIS Controls v8 controles 5, 6, 8, 11) foram usadas por conhecimento geral, sem fetch do texto (as normas são pagas/paywalled); os requisitos RF-I/O/U/A e RNF-01/05/07 mapeiam para esses controles. Itens marcados "não verificado" (Keeper, detalhes do Passbolt) devem ser conferidos antes de citar em trabalho formal.
