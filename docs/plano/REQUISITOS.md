# Requisitos finais — Cofre AES Empresarial

IDs herdados de `pesquisa-requisitos.md` para rastreio; `RNF-C*` são novos (cripto). Fase = fase de `FASES.md` que entrega. "T" = teste automatizado (pytest no backend, `node --test` no front); "M" = verificação manual roteirizada pelo validador.
Alvo: 1 organização por instalação, 10–200 usuários. Começo limpo: sem migração dos cofres acadêmicos.

## 1. MVP — Funcionais

### Identidade e sessão

| ID | Requisito | Critério de aceite verificável | Fase |
|---|---|---|---|
| RF-I01 | Cadastro só por convite (token de uso único, 72 h, hash no banco). Primeiro owner por CLI `python -m app.cli criar-org`. | T: aceitar com token inexistente → 404; expirado/usado/revogado → 410; segundo uso → 410; não existe rota de cadastro aberto (`POST /api/v1/usuarios` → 404/405). CLI recusa segunda org (exit ≠ 0). | 3 |
| RF-I02 | Login e-mail + authHash; sessão por cookie opaco; nenhuma rota aceita `X-Senha-Mestra`. | T: rota de dados sem cookie → 401; `grep -ri "senha-mestra\|x-senha" app/` sem ocorrência em código de rota. | 3 |
| RF-I03 | MFA TOTP (RFC 6238) + 10 códigos de recuperação de uso único; segredo TOTP cifrado. | T: vetor do RFC 6238 (SHA-1) bate; login sem TOTP de usuário com MFA → 401 `mfa_requerido`; código do mesmo passo reutilizado → 401; código de recuperação reutilizado → 401; coluna `totp_segredo_cif` não contém o base32 em claro. | 4 |
| RF-I04 | MFA obrigatório por política (padrão **desligado** desde a Fase 7, decisão do usuário; a org liga em `PUT /org/politica`): sessão `mfa_pendente` só acessa configuração de MFA. | T: com política ativa e usuário sem MFA, `GET /api/v1/sync` → 403 `mfa_configuracao_requerida`; após confirmar MFA → 200. | 4 |
| RF-I08 | Sessão: ociosa = `inatividade_min`, absoluta 12 h, revogável; listar/encerrar sessões próprias. | T: relógio simulado após ociosidade → 401; após 12 h → 401; após logout o mesmo cookie → 401; `DELETE /eu/sessoes/{id}` derruba a outra sessão. | 3 (listar/encerrar: 4) |
| RF-I09 | Bloqueio automático no cliente por inatividade (= logout + descarte das chaves) e ao fechar a aba. | M: com `inatividade_min=5`, após 5 min sem interação a tela volta ao login; `localStorage`/`sessionStorage`/IndexedDB vazios (DevTools). T (Node): função de temporizador chama `bloquear()` após o prazo com relógio falso. | 4 |
| RF-I10 | Troca de senha-mestra re-envelopa só a userKey e revoga as outras sessões; exige TOTP quando MFA ativo. | T (E2E Node): após troca, login com senha antiga → 401, outra sessão → 401, itens continuam decifráveis com a nova. | 3 (exigência de TOTP: 4) |

### Organização, papéis e coleções

| ID | Requisito | Critério de aceite verificável | Fase |
|---|---|---|---|
| RF-O01 | Entidade organização; toda tabela de negócio ligada a `org_id`. | T: teste de esquema lista tabelas de negócio e confirma `org_id` direto ou FK `NOT NULL` para tabela com `org_id`. | 1 / 3 / 6 |
| RF-O02 | Papéis `owner`, `admin`, `member` (sem `manager`; gestão de coleção é permissão). ≥1 owner sempre. | T: teste parametrizado rota × papel com o código esperado para todas as rotas de §5.3/5.5 da arquitetura. | 5 (matriz completa: 8) |
| RF-O03/O04 | Permissão por coleção: `ver_sem_revelar`, `ver`, `editar`, `gerenciar`. | T: para cada nível, tabela de operações permitidas/negadas (criar, editar, revelar, lixeira, membros, rotacionar). | 6 / 7 |
| RF-O05 | Limitações documentadas: `ver_sem_revelar` não protege contra quem usa a credencial; quem tem a collectionKey pode forjar blob. | M: texto em `docs/seguranca.md` e tooltip da UI ao escolher a permissão. | 6 |

### Ciclo de vida

| ID | Requisito | Critério de aceite verificável | Fase |
|---|---|---|---|
| RF-U01 | Estados `convidado → aceito → ativo ↔ suspenso → removido`; `aceito→ativo` exige fingerprint conferido pelo admin. | T: cada transição inválida → 409; fingerprint errado → 422; usuário `aceito` não recebe envelope (422 `destinatario_invalido`). | 3 / 5 |
| RF-U02 | Suspender bloqueia login e revoga sessões na hora. | T: cookie do suspenso → 401 na próxima requisição; login com credencial correta → 403 `conta_suspensa`. | 5 |
| RF-U03 | Remover usuário: revoga acesso, gera relatório de coleções/itens que ele alcançava, marca rotação. Último owner não pode sair. | T: relatório lista exatamente os itens das coleções dele; coleções ficam `rotacao_pendente`; remover último owner → 409. | 7 |
| RF-U04 | Rotação: coleção `rotacao_pendente` até rotacionar a chave; item `rotacao_senha_pendente` até `PUT` com `senha_trocada=true`. | T: rotação incompleta → 422 e nada muda (transação); após rotação, ex-membro sem envelope; item sai do painel só após `senha_trocada`. E2E: ex-membro com a chave antiga não decifra item recifrado. | 7 |
| RF-U05 | Transferência de posse: promover owner exige envelopes de todas as coleções; depois o antigo pode ser rebaixado. | T: promoção sem todos os envelopes → 422; org sem owner impossível (409). | 7 |
| RF-U06 | Recuperação por kit (Recovery Key) + MFA; gera kit novo; revoga sessões. | T (E2E Node): recuperar com kit → login com nova senha ok, kit antigo → 401, sessões antigas → 401. | 4 |

### Itens

| ID | Requisito | Critério de aceite verificável | Fase |
|---|---|---|---|
| RF-T01 | Tipos `login`, `nota`, `chave_api` com CRUD. | T: criar/editar/excluir cada tipo; tipo inválido → 422. | 6 |
| RF-T06 | Histórico (últimas 10 versões), restauração vira nova versão, registra quem editou. | T: 3 edições → 3 linhas em `item_versoes`; 12 edições → 10; E2E restaura v1 e lê a senha original. | 6 |
| RF-T07 | Lixeira 30 dias: soft delete, restaurar (`editar`), apagar definitivo (`gerenciar`), purga após 30 dias. | T: excluído some do `sync`, aparece na lixeira, restaura; com `excluido_em` 31 dias atrás, `sync` purga e grava `item.purgado`. | 6 |
| RF-T08 | Gerador de senha/passphrase no cliente com `crypto.getRandomValues` (rejeição de viés). | T (Node): tamanho e classes respeitados; 10 000 gerações sem caractere fora do alfabeto; teste qui-quadrado simples dentro do limite. | 6 |
| RF-T10 | Senha mascarada por padrão; copiar limpa o clipboard após 30 s se o conteúdo não mudou. | M: roteiro no PR (copiar, aguardar 30 s, colar → vazio). | 6 |
| RF-T11 | Busca local por título/usuário/URL só nos itens decifrados do usuário. | T (Node): função de busca sobre lista decifrada; servidor nunca recebe termo de busca (não existe rota). | 6 |

### Auditoria e políticas

| ID | Requisito | Critério de aceite verificável | Fase |
|---|---|---|---|
| RF-A01 | Eventos de §5.6 da arquitetura com `org, ator, ip, user_agent, alvo, resultado`. | T: cada ação gera exatamente um evento do tipo esperado (teste parametrizado, completado na Fase 8). | 3–8 |
| RF-A02 | Evento gravado na mesma transação da ação; falha na gravação → ação falha. | T: trigger temporário que faz `RAISE` em `INSERT` de `eventos`; `GET /itens/{id}/segredo` → 500 sem `segredo_cif` no corpo e sem evento. | 6 |
| RF-A03 | `segredo_cif` só sai por rota auditada; cópia registrada em melhor esforço. | T: `sync` e listagens não contêm a chave `segredo_cif`; cada revelação = 1 evento. | 6 |
| RF-A04 | `eventos` append-only (grant + trigger). | T: como `cofre_app`, `UPDATE`/`DELETE` em `eventos` → `InsufficientPrivilege`; como dono → erro do trigger. | 1 |
| RF-A06 | Consulta de auditoria por owner/admin com filtros e cursor; usuário vê os próprios eventos de login. | T: member → 403; filtros por tipo/ator/data retornam só o esperado; cursor não repete nem pula. | 8 |
| RF-P01 | Senha-mestra ≥ 12 caracteres (sem regra de composição), aplicada **no cliente** (o servidor não vê a senha). | T (Node): validador recusa 11, aceita 12 e 64+ (com Unicode). Documentado que o servidor não consegue impor. | 3 |
| RF-P02 | = RF-I04. | — | 4 |
| RF-P03 | `inatividade_min` (5–60, padrão 15) aplicado na sessão do servidor e no bloqueio do cliente. | T: valor 4 ou 61 → 422; servidor expira sessão ociosa conforme valor. | 4 |
| RF-P07 | Alteração de política só por owner/admin, auditada com antes/depois. | T: member → 403; evento `politica.alterada` com `meta.antes` e `meta.depois`. | 4 |

## 2. MVP — Não funcionais

| ID | Requisito | Critério de aceite verificável | Fase |
|---|---|---|---|
| RNF-01 | Rate limit: IP 20 req/min nas rotas públicas de auth; conta: 10 falhas → bloqueio 15 min; mesma resposta p/ e-mail inexistente; verificação Argon2 falsa para inexistente. | T: 11ª tentativa da conta → 429 com `Retry-After`; conta inexistente se comporta igual; spy confirma 1 chamada de verificação Argon2 para e-mail inexistente; 21ª requisição/min do mesmo IP → 429. | 3 |
| RNF-02 | Headers de segurança e CSP (§6 da arquitetura); TLS/HSTS no Caddy. | T (front): teste lê `nginx.conf` e confere cada header. M (F9): `curl -sI https://<dominio>/` mostra os headers; Firefox/Chromium sem violação de CSP/TT no console. | 2 / 9 |
| RNF-03 | Hash de autenticação Argon2id (argon2-cffi padrão) + pepper; KDF cliente Argon2id m=64 MiB t=3 p=1. | T: `auth_hash` no banco começa com `$argon2id$`; vetor cruzado Python×JS do KDF passa. | 2 / 3 |
| RNF-05 | Backup diário `pg_dump -Fc` cifrado com `age` (chave pública na VPS, privada fora), retenção 7d/4s/3m, cópia fora da VPS. | T/M: `scripts/backup.sh` gera arquivo `.age` que não contém string sentinela em claro; rotação de retenção testada com datas falsas; cron instalado (F9). | 8 / 9 |
| RNF-06 | Restauração testada: `scripts/restaurar.sh --verifica` restaura num Postgres novo e confere migração + contagem de linhas. | T (CI ou local): backup → restaurar → `--verifica` retorna 0; adulterar arquivo → ≠ 0. | 8 |
| RNF-07 | Logs JSON sem segredos. | T: teste com valor sentinela em authHash, blobs, token de convite e TOTP exercita todas as rotas; sentinela ausente de `caplog` e stdout capturado. | 1 (formatter) / 8 (sentinela completo) |
| RNF-09 | `/api/saude` e `/api/pronto`; `HEALTHCHECK` no Dockerfile. | T: `/api/pronto` → 503 com pool apontando para banco parado. | 1 |
| RNF-10 | CI em PR para `empresarial`: ruff, pytest (cobertura ≥ 80% em `app/`), pip-audit, gitleaks; front: `node --test`. | Pipeline vermelho se qualquer passo falhar (validador confere um run com falha induzida na Fase 1). | 1 / 2 |
| RNF-11 | Rotas sob `/api/v1`; migrations versionadas forward-only com checksum. | T: migration aplicada e depois alterada → runner falha com `checksum_divergente`; rodar runner 2× é idempotente. | 1 |
| RNF-12 | Segredos fora do repo. | gitleaks limpo no CI; `.env` no `.gitignore` e `.dockerignore`. | 1 |
| RNF-14 | Banco sem porta publicada; containers não-root; só 127.0.0.1 nas portas publicadas; limites de memória. | T: teste lê `docker-compose.yml` e confere; M (F9): `docker compose ps` e `ss -tlnp`. | 1 / 9 |
| RNF-15a/b/e | LGPD: `docs/ropa.md`, matriz requisito→controle em `docs/seguranca.md`, runbook de incidente com prazo **[CONFIRMAR na Resolução CD/ANPD nº 15/2024]**. | M: arquivos existem e são referenciados no README. | 8 |
| RNF-15c | Minimização: coletar só e-mail, nome, papel. | M: revisão do esquema no PR da Fase 3. | 3 |
| RNF-15d | Remoção anonimiza nome/e-mail; eventos mantêm `ator_id`. | T: após remover, `GET /membros` não traz o e-mail; eventos antigos com o `ator_id` permanecem. | 5 |
| RNF-C01 | Zero-knowledge: servidor nunca recebe senha-mestra, masterKey, kek, userKey, chave privada ou conteúdo em claro. | T (E2E Node): com senha e conteúdo sentinela, `pg_dump` do banco de teste e logs da API não contêm nenhum sentinela (nem em base64). | 6 (reforço na 8) |
| RNF-C02 | Navegador sem X25519/WebCrypto → tela "navegador não suportado", sem prosseguir. | T (Node): `detectarSuporte()` com `subtle` falso retorna falso; M: mensagem aparece. | 2 |
| RNF-C03 | Cripto do cliente confere com implementação independente. | T (Node): vetores gerados por Python (`argon2-cffi`, `cryptography`) para Argon2id, HKDF, AES-GCM (`v1`), X25519 (`x1`) passam; adulterar 1 bit do ct/AAD → rejeita. | 2 |
| RNF-C04 | Sem `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`eval`/`new Function`/handlers inline; sem script inline; libs vendorizadas com SHA-256 registrado. | T (Node): varredura dos `.js`/`.html` servidos; hash do vendorizado confere com `vendor/README.md`. | 2 |

## 3. Backlog pós-MVP

| ID | Item | Motivo de ficar fora |
|---|---|---|
| RF-I05 | WebAuthn/passkey | Desejável; TOTP cobre o MVP |
| RF-O06 / O07 | Grupos; cofre pessoal | Desejável |
| RF-T03 / T04 / T05 | Campos customizados; TOTP por item; anexos | Desejável / fora por decisão |
| RF-T09 | HIBP k-anonymity | Saída de rede + privacidade; desejável |
| RF-T12 / RF-P04 | Import/export (e política de bloqueio de export) | Sem export não há o que bloquear |
| RF-A04b | Hash-chain da auditoria | Desejável |
| RF-A05 | Arquivamento/retenção automática | Só faz efeito após 12 meses (D23) |
| RF-A07 / A08 / RNF-08 | Export de log, Loki, alertas, métricas OTel | Depende do stack de observabilidade (não verificado na VPS) |
| RF-P05 / P06 | Restringir criação de coleção; bloquear tipos | Desejável |
| RF-U06-B | Recuperação por admin (escrow) | Superfície de ataque; opt-in futuro |
| RNF-04 | SLO 99,5% com relatório | Monitor no Uptime Kuma entra na F9 se o Kuma existir; relatório fica fora |
| RNF-13 | Teste de carga | Desejável |
| — | OPAQUE; Ed25519 (autoria/manifesto anti-rollback); Web Worker do KDF; QR do TOTP; envio de e-mail; RLS por `org_id`; PITR/WAL; `--require-hashes`/bandit; snapshot do OpenAPI | Ver decisões D5, D7, D9, D17, D22 |
| Fora | SSO/SAML/SCIM/LDAP, papéis custom, cartões, extensão/autofill, mobile, multi-org com billing | Decisão do orquestrador |
