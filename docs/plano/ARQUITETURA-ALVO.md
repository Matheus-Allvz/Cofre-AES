# Arquitetura-alvo — Cofre AES Empresarial

Repos: `Matheus-Allvz/Cofre-AES` (API) e `Matheus-Allvz/Cofre-AES-Frontend` (web), branch `empresarial`. A `main` (trabalho acadêmico) não é tocada.
**Começo limpo:** não há migração dos cofres acadêmicos (Supabase). As rotas `/cofres*`, `X-Senha-Mestra`, `supabase-py` e `sql/esquema.sql` são removidos da branch `empresarial` na Fase 1. A versão acadêmica continua no ar, intocada.

Marcação: **[CONFIRMAR]** = o construtor confirma antes de fixar (fonte oficial ou teste) e registra a evidência no PR.

---

## 1. Decisões

| # | Tema | Decisão | Alternativa rejeitada | Motivo |
|---|---|---|---|---|
| D1 | Modelo | Zero-knowledge: toda cifragem/decifragem no browser. Servidor guarda blobs, chaves públicas, chaves envelopadas e hash de autenticação. | Cifragem no servidor (modelo acadêmico) | Vazamento do banco ou operador passivo não expõe nada. |
| D2 | Banco | PostgreSQL 16 próprio (`postgres:16-alpine`) no compose do projeto, sem porta publicada. | Supabase | RLS anon aberta, sem controle de grants/backup, pausa por inatividade. Igual à pesquisa. |
| D3 | Acesso ao banco | `psycopg` 3 + `psycopg_pool`, SQL puro, sem ORM. | SQLAlchemy | Esquema pequeno, SQL explícito é auditável; menos dependência. |
| D4 | Migrations | Arquivos `migracoes/NNNN_nome.sql` + runner próprio `app/migrar.py` (~50 linhas: tabela `schema_migracoes`, `pg_advisory_lock`, uma transação por arquivo, checksum SHA-256 dos já aplicados). Só "para frente"; reversão = restaurar backup. | Alembic | Esquema escrito em SQL de qualquer jeito; zero dependência e zero autogeração mágica. Downgrade em cofre cifrado raramente é seguro; o caminho real de volta é o backup (RNF-06). |
| D5 | Autenticação | Estilo Bitwarden: `authHash` derivado da masterKey vai ao servidor; servidor guarda `Argon2id(HMAC(pepper, authHash))`. | OPAQUE | Sem biblioteca madura nas duas pontas; ganho pequeno porque o servidor serve o JS. Backlog. |
| D6 | KDF cliente | **Só Argon2id** (`hash-wasm`, vendorizado), m=65536 KiB, t=3, p=1, 32 B. Parâmetros gravados por usuário. | Fallback PBKDF2 600k | WASM é universal nos browsers-alvo; dois caminhos = dobro de teste e um elo fraco. Coluna `kdf` jsonb permite trocar no futuro. |
| D7 | KDF em Worker | **Não** no MVP: roda na thread principal após um `await` de 50 ms para pintar o "Derivando chave…". | Web Worker | Worker sob Trusted Types exige policy para `new Worker`/`importScripts`; custo ~1 s, uma vez por login. Backlog. |
| D8 | Assimétrico | **X25519** (WebCrypto) + HKDF-SHA256 + AES-256-GCM (estilo HPKE base). Navegador sem X25519 → tela "navegador não suportado". | RSA-OAEP-3072 | Um algoritmo só; Chrome ≥133, Firefox ≥130, Safari ≥17 (confirmado no MDN browser-compat-data, Fase 2). Node ≥22 suporta para testes. |
| D9 | Assinaturas | Sem Ed25519 no MVP. Autenticidade de chave pública por fingerprint verificado fora de banda. | Ed25519 por item/manifesto | Complexidade alta; limitação documentada (quem tem a collectionKey pode forjar blob). Backlog. |
| D10 | Chave por item | **Sem itemKey.** Itens cifrados direto com a collectionKey. Rotação recifra itens e versões no cliente. | itemKey por item | Escala alvo (≤ alguns milhares de itens/coleção) torna a recifragem barata; menos um nível de envelope. |
| D11 | Item dividido | Cada item tem `meta_cif` (título, usuário, URLs) e `segredo_cif` (senha/notas/valor). Listagem só entrega `meta_cif`; `segredo_cif` só sai por rota auditada. | Blob único | Torna "revelar" auditável no servidor (RF-A02/A03) mesmo em zero-knowledge e viabiliza a permissão `ver_sem_revelar` contra servidor honesto. |
| D12 | Papéis | `owner`, `admin`, `member`. Gestão de coleção é **permissão por coleção** (`gerenciar`), não papel global. | Papel `manager` | `manager` = member com `gerenciar` em algumas coleções; um conceito a menos. |
| D13 | Acesso de owners | Todo owner ativo recebe envelope `gerenciar` de toda coleção (validado no servidor na criação/rotação/promoção). Admins **não** leem conteúdo por padrão. | Admin vê tudo | Garante que nenhuma coleção fica órfã sem dar escrow amplo a admins. |
| D14 | Origem única | Front e API no mesmo domínio: Caddy envia `/api/*` à API e o resto ao nginx do front. Sem CORS. | Subdomínios + CORS com credenciais | Cookie same-origin, `connect-src 'self'`, sem CORS para errar. |
| D15 | Sessão | Token opaco 256 bits em cookie `sessao` (`HttpOnly; Secure; SameSite=Strict; Path=/api`), SHA-256 no banco; ociosa = política (padrão 15 min), absoluta 12 h. Métodos não-GET exigem header `X-Cofre: 1`. | JWT + refresh | Revogação imediata trivial; nada de token em storage. |
| D16 | Bloqueio do cofre | Bloquear = descartar chaves da memória + `POST /logout`. Desbloquear = login. | Sessão viva com cofre travado | Um mecanismo só; cobre RF-I09 e RF-P03 com uma política (`inatividade_min`). |
| D17 | MFA | TOTP RFC 6238 implementado com `hmac` da stdlib (SHA-1, 6 dígitos, 30 s, janela ±1, anti-replay por passo). Segredo cifrado com AES-GCM chave do servidor. Sem QR no MVP (mostra segredo base32 e URI `otpauth://`). | `pyotp`, lib de QR | ~20 linhas; QR exige lib vendorizada a mais (backlog). |
| D18 | Recuperação | Kit de emergência (Recovery Key 256 bits) obrigatório para todos. | Recuperação por admin (escrow) | Escrow amplia superfície; backlog opt-in. |
| D19 | Segredo do servidor | Uma variável `COFRE_SEGREDO` (32 B base64) → subchaves `HMAC-SHA256(segredo, rótulo)`: `pepper`, `prelogin`, `totp`. | Uma env por finalidade | Menos segredo para gerir; rótulos separam domínios. |
| D20 | Rate limit | Tabela `limites` no Postgres (por conta e por IP). Mesma regra para e-mail existente ou não. | Memória do processo / só no proxy | Persiste entre restarts; resposta uniforme sem enumeração. |
| D21 | Papéis no banco | `cofre_dono` (migrations, dono das tabelas) e `cofre_app` (aplicação). `cofre_app` só tem `INSERT, SELECT` em `eventos`; trigger bloqueia `UPDATE/DELETE` para todos. Serviço `migrar` separado no compose (só ele recebe a credencial de dono). | App com superusuário | Append-only real (RF-A04). |
| D22 | E-mail | **Sem envio de e-mail no MVP.** Convite gera link exibido uma vez ao admin, que o entrega por canal próprio. | SMTP | Infra/segredo a mais; o canal fora de banda já é exigido pelo fingerprint. Backlog. |
| D23 | Retenção de auditoria | Sem job de arquivamento no MVP; política documentada (12 meses). Purga é operação manual com papel dono. | Job automático | Nenhum dado terá 12 meses antes de muito depois do go-live. Backlog. |
| D24 | Testes | pytest + httpx contra Postgres 16 real; JS com `node --test` (Node ≥22, sem deps npm); vetores cruzados gerados por Python (`argon2-cffi`, `cryptography`); E2E em Node usando os mesmos módulos de cripto do front contra a API real. | Mocks / browser headless | Testa a cripto real contra implementação independente sem dependência de browser no CI. |

---

## 2. Hierarquia de chaves

```
senha-mestra ──NFKC──> Argon2id(sal 16B, m=65536, t=3, p=1) ──> masterKey (32 B, só memória)
  masterKey ──HKDF-SHA256(salt=vazio, info="cofre-emp/v1/auth")──> authHash (32 B) ──> servidor
  masterKey ──HKDF-SHA256(salt=vazio, info="cofre-emp/v1/kek")───> kek (AES-256, só memória)

kek ──AES-GCM──> userKey (32 B aleatória)                      [usuarios.chave_usuario_cif]
recoveryKey (32 B aleatória, kit impresso)
  ──HKDF-SHA256(salt=vazio, info="cofre-emp/v1/recup-kek")──> recupKek ──AES-GCM──> userKey [usuarios.chave_usuario_recup_cif]
  ──HKDF-SHA256(salt=vazio, info="cofre-emp/v1/recup-auth")─> recupAuth ──> servidor guarda HMAC(pepper, recupAuth)
userKey ──AES-GCM──> chave privada X25519 (PKCS8)              [usuarios.chave_privada_cif]
chave pública X25519 (raw 32 B)                                [usuarios.chave_publica, em claro]

collectionKey (32 B aleatória por coleção, versionada chave_ver)
  ──envelope x1 para a chave pública de cada membro──>         [colecao_membros.chave_colecao_cif]
  ──AES-GCM──> nome da coleção, meta e segredo de cada item e de cada versão
```

Regras:
- Todo HKDF desta hierarquia (auth, kek, recup-kek, recup-auth) usa `salt` **vazio** (0 bytes; no WebCrypto, `new Uint8Array(0)`). O único HKDF com salt é o do envelope x1 (§3.2).
- Toda chave AES importada com `extractable: false`, exceto a userKey e a collectionKey quando precisam ser re-envelopadas (troca de senha, compartilhamento, rotação). Nada vai a `localStorage`/`sessionStorage`/IndexedDB/cookie.
- IV sempre de `crypto.getRandomValues` (12 B). AAD sempre reconstruído pelo cliente a partir de ids que ele já conhece; nunca lido do servidor como string pronta.
- Troca de senha-mestra re-envelopa só a userKey. Recuperação re-envelopa a userKey e gera **novo** kit.
- Rotação de coleção: nova collectionKey (`chave_ver+1`), recifra nome, todos os itens (inclusive lixeira) e todas as versões; envelopes novos para os membros restantes; tudo numa requisição atômica.

---

## 3. Formatos exatos

Encoding: **base64url sem padding** (RFC 4648 §5) em todo campo binário de JSON e dentro dos envelopes. Texto UTF-8. JSON cifrado é `JSON.stringify` do objeto (ordem não importa, o JSON nunca é comparado em claro no servidor).

### 3.1 Envelope simétrico `v1`
```
v1.<iv:12B>.<ct||tag:16B>
```
Regex de validação no servidor: `^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$`. Tamanho máximo por campo: 64 KiB (422 `blob_grande` acima).

### 3.2 Envelope assimétrico `x1` (collectionKey para um membro)
```
x1.<eph_pub:32B>.<iv:12B>.<ct||tag>
shared = X25519(eph_priv, pub_destino)
k      = HKDF-SHA256(ikm=shared, salt=eph_pub||pub_destino, info="cofre-emp/v1/env-colecao", 32 B)
ct     = AES-256-GCM(k, iv, collectionKey, AAD)
```
Regex: `^x1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$`.

### 3.3 AAD (strings UTF-8, campos separados por `|`, ids UUID minúsculos)

| Objeto | AAD |
|---|---|
| userKey sob kek | `cofre-emp/v1|userkey|<usuario_id>` |
| userKey sob recupKek | `cofre-emp/v1|userkey-recup|<usuario_id>` |
| chave privada sob userKey | `cofre-emp/v1|privkey|<usuario_id>` |
| envelope x1 de coleção | `cofre-emp/v1|env-colecao|<org_id>|<colecao_id>|<usuario_dest_id>|<chave_ver>` |
| nome da coleção | `cofre-emp/v1|colecao-nome|<org_id>|<colecao_id>|<chave_ver>` |
| meta do item | `cofre-emp/v1|item-meta|<org_id>|<colecao_id>|<item_id>|<tipo>|<chave_ver>|<versao>` |
| segredo do item | `cofre-emp/v1|item-segredo|<org_id>|<colecao_id>|<item_id>|<tipo>|<chave_ver>|<versao>` |

`tipo` (Fase 7) é o tipo do item (`login`/`nota`/`chave_api`, §3.4): o servidor não consegue trocar o tipo exibido sem quebrar a decifragem; além disso o cliente confere que as chaves do JSON decifrado pertencem ao tipo (§3.4) e trata divergência como "item adulterado". Sem migração de dados: não havia dados em produção quando o `tipo` entrou no AAD.
`versao` no AAD é a versão que o item **terá** após a gravação (criação = 1; `PUT` com `If-Match: n` cifra com `n+1`). Rotação mantém `versao` e muda `chave_ver`. Restaurar versão antiga = cliente decifra a antiga e recifra como nova versão.

### 3.4 Conteúdo dos itens (antes de cifrar)

| tipo | meta | segredo |
|---|---|---|
| `login` | `{titulo, usuario, urls: [..]}` | `{senha, notas}` |
| `nota` | `{titulo}` | `{conteudo}` |
| `chave_api` | `{titulo, validade?}` | `{valor, notas}` |

### 3.5 Outros formatos
- `authHash`, `recup_auth`: base64url de 32 B (43 chars).
- `sal`: base64url de 16 B. `kdf`: `{"tipo":"argon2id","m":65536,"t":3,"p":1}`.
- Recovery Key exibida: base32 RFC 4648 sem padding, maiúsculas, grupos de 4 separados por `-` (52 chars → 13 grupos). Entrada aceita com/sem hífens e minúsculas.
- Fingerprint: primeiros 16 B de `SHA-256(chave_publica raw)` em hex maiúsculo, grupos de 4 separados por espaço (8 grupos).
- Hash no servidor: `argon2-cffi` `PasswordHasher()` padrão (t=3, m=65536, p=4) sobre `HMAC-SHA256(pepper, authHash_bytes)`. Valores de alta entropia (token de sessão, convite, recup_auth, códigos de recuperação de MFA): `SHA-256` (tokens) ou `HMAC-SHA256(pepper, ·)` (recup_auth, códigos MFA).
- prelogin para e-mail inexistente: `sal = HMAC-SHA256(prelogin, email_normalizado)[:16]`, `kdf` = padrão. E-mail normalizado = `strip().lower()`.

---

## 4. Esquema de dados alvo (Postgres 16)

Extensões: `citext`. `*_cif` = envelope texto (`v1`/`x1`). Todas as tabelas de negócio têm `org_id` (direto ou via FK obrigatória), exceto `eventos`, cujo `org_id` é **nullable** (evento sem organização identificável, ex.: login falho de e-mail inexistente). `limites` é infraestrutura de rate limit, sem `org_id`.

| Tabela | Colunas (resumo) | Fase |
|---|---|---|
| `schema_migracoes` | `versao text pk, sha256 text, aplicada_em` | 1 |
| `organizacoes` | `id uuid pk, nome text, criada_em` | 1 |
| `eventos` | `id bigserial pk, em timestamptz, org_id null, ator_id uuid null, tipo text, alvo_tipo text, alvo_id text, resultado text ('ok'/'falha'), ip inet, user_agent text, meta jsonb` — trigger `BEFORE UPDATE OR DELETE` → `RAISE`; `cofre_app` só `INSERT, SELECT` | 1 |
| `limites` | `chave text pk ('conta:<sha256 email>' / 'ip:<ip>:<rota>'), falhas int, janela_inicio, bloqueado_ate` | 3 |
| `usuarios` | `id uuid pk, org_id, email citext unique, nome text, papel text check(owner/admin/member), estado text check(convidado/aceito/ativo/suspenso/removido), kdf jsonb, kdf_sal bytea, auth_hash text, chave_usuario_cif, chave_usuario_recup_cif, recup_auth_hmac bytea, chave_publica bytea, chave_privada_cif, fingerprint_confirmado text, confirmado_por uuid, totp_segredo_cif text, totp_ultimo_passo bigint, criado_em, atualizado_em` | 3 (TOTP em 4) |
| `convites` | `id uuid pk, org_id, usuario_id uuid fk, token_hash bytea unique, papel, criado_por, expira_em, usado_em, revogado_em` | 3 |
| `sessoes` | `id uuid pk, usuario_id, token_hash bytea unique, criada_em, ultimo_uso, expira_em, ip, user_agent, mfa_pendente bool, revogada_em` — `mfa_pendente` **sem uso desde a Fase 4** (calculado por requisição: `politicas.mfa_obrigatorio AND totp_ultimo_passo IS NULL`); não confiar na coluna | 3 |
| `recuperacoes` | `token_hash bytea pk, usuario_id, expira_em (5 min), usado_em` | 4 |
| `codigos_mfa` | `usuario_id, codigo_hmac bytea, usado_em` (pk usuario_id+codigo_hmac) | 4 |
| `politicas` | `org_id pk, mfa_obrigatorio bool default false (Fase 7, migração 0005: MFA opcional por padrão), inatividade_min int check 5..60 default 15, atualizado_em` | 4 |
| `colecoes` | `id uuid pk, org_id, nome_cif, chave_ver int, rotacao_pendente bool, criada_por, criada_em` | 6 |
| `colecao_membros` | `colecao_id, usuario_id, permissao check(ver_sem_revelar/ver/editar/gerenciar), chave_ver, chave_colecao_cif` — pk `(colecao_id, usuario_id)`; só o envelope da `chave_ver` atual | 6 |
| `itens` | `id uuid pk (gerado no cliente), colecao_id, tipo check(login/nota/chave_api), versao int, chave_ver int, meta_cif, segredo_cif, rotacao_senha_pendente bool, criado_por, criado_em, atualizado_por, atualizado_em, excluido_em null` | 6 |
| `item_versoes` | `item_id, versao, chave_ver, meta_cif, segredo_cif, editado_por, em` — pk `(item_id, versao)`; máx. 10 por item (as mais antigas apagadas na gravação) | 6 |

Sem RLS (só a API acessa o banco, que não publica porta). Defesa em profundidade com RLS por `org_id` → backlog.

---

## 5. Contrato de API v1

Base: `/api`. Dados em `/api/v1`. JSON. Erros: corpo `{"erro": "<codigo>"}` (handler único); 422 de validação do FastAPI mantém o formato padrão.
Autenticação: cookie `sessao`. Em `POST/PUT/PATCH/DELETE` autenticados, header `X-Cofre: 1` obrigatório (403 `csrf` sem ele). Respostas da API com `Cache-Control: no-store`.
Limite de corpo (Fase 7), conferido antes de qualquer parse no `Content-Length` e contando os bytes do stream (`Transfer-Encoding: chunked`): 256 KiB; 20 MiB só em `POST /colecoes/{id}/rotacionar`, `PUT /membros/{id}/papel` e `POST /membros/{id}/reativar` e só para **sessão válida com a permissão da rota** (consultadas no banco numa consulta antes de ler o corpo: não revogada, dentro dos prazos, usuário `ativo`, sem MFA pendente e — Fase 8 — `gerenciar` na coleção para `rotacionar`, papel owner para `papel`/`reativar`, as únicas que mandam envelopes de todas as coleções; qualquer outro cookie fica no limite pequeno), um corpo acima de 256 KiB por vez nessas rotas (o seguinte recebe 503 `ocupado` + `Retry-After`) e com prazo de leitura (`COFRE_PRAZO_CORPO_S`, padrão 60 s; estourou → 408 `corpo_lento` e a vaga é liberada). Acima → 413 `corpo_grande`. Toda recusa do limite (408/413/503) vai ao log estruturado (`corpo_recusado`, com `usuario_id` quando a sessão foi consultada); 408/503 de usuário autenticado também viram evento `requisicao.recusada` (Fase 8).
Sessão com `mfa_pendente=true` só acessa `/eu`, `/eu/mfa/*` e `/logout` (403 `mfa_configuracao_requerida` no resto).

### 5.1 Públicas (rate limit por IP; login/recuperação também por conta)

| Rota | Entrada | Sucesso | Erros |
|---|---|---|---|
| `GET /api/saude` | — | 200 `{"status":"ok"}` | — |
| `GET /api/pronto` | — | 200 | 503 sem banco |
| `POST /api/v1/prelogin` | `{email}` | 200 `{kdf, sal}` (falso determinístico se não existe) | 429 |
| `POST /api/v1/convites/consultar` | `{token}` | 200 `{usuario_id, org_id, org_nome, email, papel}` | 404 `convite_invalido`, 410 `convite_expirado` |
| `POST /api/v1/convites/aceitar` | `{token, nome, kdf, sal, auth_hash, chave_usuario_cif, chave_usuario_recup_cif, recup_auth, chave_publica, chave_privada_cif}` | 201; usuário `convidado→aceito` (bootstrap owner: `→ativo`) | 404, 410, 422 |
| `POST /api/v1/login` | `{email, auth_hash, totp?, codigo_recuperacao?}` | 200 + `Set-Cookie`; corpo `{usuario:{id,org_id,email,nome,papel,estado}, kdf, sal, chave_usuario_cif, chave_privada_cif, chave_publica, politica, mfa_pendente}` | 401 `credenciais_invalidas` (mesmo corpo p/ inexistente), 401 `mfa_requerido`, 401 `mfa_invalido`, 403 `conta_suspensa` (só após credencial válida), 429 `bloqueado` + `Retry-After` |
| `POST /api/v1/recuperar/iniciar` | `{email, recup_auth, totp? / codigo_recuperacao?}` | 200 `{token, usuario_id, chave_usuario_recup_cif}` (token 5 min) | 401 `credenciais_invalidas`, 401 `mfa_requerido`, 429 |
| `POST /api/v1/recuperar/concluir` | `{token, kdf, sal, auth_hash, chave_usuario_cif, chave_usuario_recup_cif, recup_auth}` | 204; revoga todas as sessões | 401 `token_invalido` |

### 5.2 Conta (autenticado)

| Rota | Quem | Efeito / erros |
|---|---|---|
| `POST /api/v1/logout` | qualquer | 204, revoga a sessão atual |
| `GET /api/v1/eu` | qualquer | perfil + chaves cifradas + `politica` |
| `GET /api/v1/eu/sessoes` / `DELETE /api/v1/eu/sessoes/{id}` | qualquer | lista (id, criada, último uso, ip, UA, atual?) / revoga (404 se não é dele) |
| `GET /api/v1/eu/eventos` | qualquer | próprios eventos `auth.*` paginados |
| `POST /api/v1/eu/senha` | qualquer | `{auth_hash_atual, totp?, kdf, sal, auth_hash, chave_usuario_cif}` → 204; revoga as **outras** sessões. 401 `credenciais_invalidas`, 401 `mfa_requerido` |
| `POST /api/v1/eu/mfa/iniciar` | qualquer | 200 `{segredo_base32, otpauth_uri}`; 409 `mfa_ja_ativo` |
| `POST /api/v1/eu/mfa/confirmar` | qualquer | `{codigo}` → 200 `{codigos_recuperacao:[10]}` (exibidos uma vez); limpa `mfa_pendente` |
| `DELETE /api/v1/eu/mfa` | qualquer | `{auth_hash, codigo}` → 204; 403 `politica_mfa` se política exige |

### 5.3 Organização e membros

| Rota | Quem | Efeito / erros |
|---|---|---|
| `GET /api/v1/org` | ativo | `{id, nome, politica}` |
| `PUT /api/v1/org/politica` | owner, admin | `{mfa_obrigatorio, inatividade_min}`; evento com antes/depois; 422 fora de faixa |
| `GET /api/v1/membros` | ativo | `[{id, email, nome, papel, estado, chave_publica, fingerprint_confirmado}]` (sem removidos) |
| `POST /api/v1/convites` | owner, admin | `{email, papel: admin/member}` → 201 `{convite_id, usuario_id, link}` (token só nesta resposta); 409 `email_em_uso` |
| `DELETE /api/v1/convites/{id}` | owner, admin | revoga; 409 se usado |
| `POST /api/v1/membros/{id}/confirmar` | owner, admin | `{fingerprint}` → `aceito→ativo`; 422 `fingerprint_divergente` se ≠ calculado da chave guardada; 409 estado inválido |
| `POST /api/v1/membros/{id}/suspender` / `reativar` | owner, admin | `ativo↔suspenso`; suspender revoga sessões; 409 `ultimo_owner`; 409 `auto_acao` (sobre si mesmo, vale também para papel e remoção). Reativar **owner** (Fase 7, D13): corpo `{envelopes:[{colecao_id, chave_ver, chave_colecao_cif}]}` com envelope `gerenciar` de toda coleção em que ele não tem `gerenciar` (as criadas enquanto estava suspenso) — 422 `envelopes_incompletos`; quem reativa owner é owner e tem as collectionKeys. Envelope para coleção em que ele **já** tem envelope → 409 `envelope_existente` (Fase 8: não sobrescreve; o guardado pode ser de uma rotação feita durante a suspensão) |
| `PUT /api/v1/membros/{id}/papel` | owner (para/de owner); owner, admin (admin↔member) | promover a owner exige alvo `ativo` (409 `estado_invalido`) e envelopes `gerenciar` de todas as coleções (`{papel:"owner", envelopes:[{colecao_id, chave_ver, chave_colecao_cif}]}`) — 422 `envelopes_incompletos` (falta ou coleção desconhecida), 422 `envelopes_duplicados`, 409 `chave_ver_desatualizada`; envelopes fora da promoção → 422; 409 `ultimo_owner` |
| `DELETE /api/v1/membros/{id}` | owner, admin | remove: revoga sessões, apaga envelopes, marca coleções `rotacao_pendente` e itens `rotacao_senha_pendente`, anonimiza nome/e-mail (`removido-<id>@invalido`), devolve `{relatorio:[{colecao_id, itens:[ids]}]}` e grava o mesmo relatório no `meta` do evento `membro.removido` (Fase 8; ids não são segredo), consultável em `GET /auditoria`; 409 `ultimo_owner` |

### 5.4 Coleções e itens

Permissões: `ver_sem_revelar` < `ver` < `editar` < `gerenciar`. Sem envelope = sem acesso (404 `nao_encontrado` para não vazar existência).

| Rota | Mínimo | Efeito / erros |
|---|---|---|
| `GET /api/v1/sync` | ativo | `{colecoes:[{id, nome_cif, chave_ver, permissao, chave_colecao_cif, rotacao_pendente}], itens:[{id, colecao_id, tipo, versao, chave_ver, meta_cif, rotacao_senha_pendente, atualizado_em, atualizado_por}]}` — só coleções com envelope; sem lixeira; sem `segredo_cif`. Purga itens da lixeira > 30 dias das coleções do usuário (evento `item.purgado`). |
| `POST /api/v1/colecoes` | ativo | `{id, nome_cif, envelopes:[{usuario_id, permissao, chave_colecao_cif}]}` (chave_ver=1) → 201. 422 `envelopes_incompletos` se faltar o criador (`gerenciar`) ou algum owner ativo (`gerenciar`); 422 `destinatario_invalido` se não ativo |
| `PUT /api/v1/colecoes/{id}` | gerenciar | `{chave_ver, nome_cif}`; 409 `chave_ver_desatualizada` |
| `DELETE /api/v1/colecoes/{id}` | gerenciar | só vazia (inclui lixeira); 409 `colecao_nao_vazia` |
| `GET /api/v1/colecoes/{id}/membros` | gerenciar | `[{usuario_id, permissao, chave_ver}]` |
| `POST /api/v1/colecoes/{id}/membros` | gerenciar | `{usuario_id, permissao, chave_ver, chave_colecao_cif}` → 201; 409 `chave_ver_desatualizada`, 422 `destinatario_invalido` (não ativo), 409 `ja_membro` |
| `PUT /api/v1/colecoes/{id}/membros/{uid}` | gerenciar | `{permissao}` → 200; owner não pode cair abaixo de `gerenciar` (409 `owner_gerencia`); 409 `ultimo_gerente` |
| `DELETE /api/v1/colecoes/{id}/membros/{uid}` | gerenciar | 204; apaga envelope, `rotacao_pendente=true`, itens `rotacao_senha_pendente=true`; 409 `owner_gerencia`, 409 `ultimo_gerente` |
| `GET /api/v1/colecoes/{id}/rotacao` | gerenciar | `{chave_ver, membros:[{usuario_id}], itens:[{id, tipo, versao, chave_ver, meta_cif, segredo_cif, excluido_em}], versoes:[{item_id, versao, chave_ver, meta_cif, segredo_cif}]}` (inclui lixeira): o que o cliente precisa para rotacionar, auditado como **um** evento `colecao.rotacao_iniciada` (contagens) em vez de um `item.revelado` por item/versão. O tipo do evento é fixo no servidor (nenhum rótulo vem do cliente) |
| `POST /api/v1/colecoes/{id}/rotacionar` | gerenciar | `{chave_ver_atual, nome_cif, envelopes:[{usuario_id, chave_colecao_cif}], itens:[{id, versao, meta_cif, segredo_cif}], versoes:[{item_id, versao, meta_cif, segredo_cif}]}` → 200 `{chave_ver}`, `rotacao_pendente=false`. Atômico. 409 `chave_ver_desatualizada`; 409 `membros_alterados` (Fase 8: conjunto de envelopes ≠ membros atuais — alguém entrou/saiu desde o `GET /rotacao`; o cliente re-sincroniza e refaz); 422 `rotacao_incompleta` (falta item — inclusive na lixeira — ou versão, ou sobra/repete algum); 409 `conflito_versao` (conferido antes do conjunto de versões); 413 `corpo_grande` acima de 20 MiB; 503 `ocupado` se outro corpo grande está em processamento |
| `POST /api/v1/colecoes/{id}/itens` | editar | `{id, tipo, chave_ver, meta_cif, segredo_cif}` → 201 `{versao:1}`; 409 `id_em_uso`, 409 `chave_ver_desatualizada` |
| `PUT /api/v1/itens/{id}` | editar | header `If-Match: <versao>`; `{chave_ver, meta_cif, segredo_cif, senha_trocada: bool}` → 200 `{versao}`; versão anterior vai para `item_versoes`; `senha_trocada` limpa `rotacao_senha_pendente`. 428 sem If-Match, 409 `conflito_versao` |
| `GET /api/v1/itens/{id}/segredo` | ver | evento `item.revelado` **na mesma transação**; `{segredo_cif, versao, chave_ver}` (`chave_ver` do **item**). 403 `sem_permissao` para `ver_sem_revelar`; item na lixeira exige `editar` (vale também para `versoes/{v}`) |
| `POST /api/v1/itens/{id}/copiado` | ver | 204, evento `item.copiado` (melhor esforço; documentado) |
| `GET /api/v1/itens/{id}/versoes` | ver | `[{versao, chave_ver, editado_por, em}]` |
| `GET /api/v1/itens/{id}/versoes/{v}` | ver | evento `item.versao_revelada`; `{meta_cif, segredo_cif, chave_ver}` |
| `DELETE /api/v1/itens/{id}` | editar | soft delete (`excluido_em`) |
| `GET /api/v1/colecoes/{id}/lixeira` | editar | itens excluídos (`meta_cif`, `excluido_em`) |
| `POST /api/v1/itens/{id}/restaurar` | editar | 409 se não está na lixeira |
| `DELETE /api/v1/itens/{id}/definitivo` | gerenciar | apaga item e versões; só se já na lixeira |

### 5.5 Auditoria

| Rota | Quem | Efeito |
|---|---|---|
| `GET /api/v1/auditoria?de&ate&ator_id&tipo&alvo_id&antes_de_id&limite(≤200)` | owner, admin | eventos em ordem decrescente de id, paginação por cursor `antes_de_id` |

### 5.6 Tipos de evento (todos com `org_id, ator_id, ip, user_agent, alvo, resultado`)
`auth.login` (ok/falha), `auth.logout`, `auth.bloqueio`, `auth.mfa` (ok/falha), `auth.senha_trocada`, `auth.recuperacao`, `auth.sessao_revogada`, `mfa.ativado`, `mfa.desativado`, `mfa.codigo_recuperacao_usado`, `convite.criado`, `convite.revogado`, `convite.aceito`, `membro.confirmado`, `membro.suspenso`, `membro.reativado`, `membro.removido`, `membro.papel_alterado`, `politica.alterada` (meta antes/depois), `colecao.criada`, `colecao.renomeada`, `colecao.excluida`, `colecao.membro_adicionado`, `colecao.permissao_alterada`, `colecao.membro_removido`, `colecao.rotacao_iniciada`, `colecao.rotacionada`, `item.criado`, `item.editado`, `item.revelado`, `item.versao_revelada`, `item.copiado`, `item.excluido`, `item.restaurado`, `item.purgado`, `org.criada`, `requisicao.recusada` (Fase 8: 408/503 do limite de corpo para usuário autenticado; `resultado=falha`, alvo `rota` = `"<MÉTODO> <caminho>"`, meta `{status, codigo}`).
`meta` nunca contém envelope, authHash, token, código TOTP ou e-mail digitado em login falho (usa `sha256(email)[:8]`).

---

## 6. Componentes e infraestrutura

```
Browser ──HTTPS── Caddy (host) ── /api/* ──> 127.0.0.1:8098  api (uvicorn, 1 worker, usuário não-root)
                               └─ resto ──> 127.0.0.1:8097  front (nginx: estáticos + headers)
api ──rede interna do compose──> db (postgres:16-alpine, sem porta publicada, volume)
migrar (one-shot, mesma imagem da api, credencial de dono) roda antes da api
```

Produção (decisões do usuário, Fase 9): domínio `secrets.matheus-alves.dev` atrás do **proxy da Cloudflare**. Cadeia real: `Cliente ──HTTPS── Cloudflare ──> VPS <IP_DA_VPS>:443 (sslh) ──> Caddy :4443 ──> 127.0.0.1:8097/8098`. Como o sslh repassa a conexão localmente, **o Caddy vê todo cliente como 127.0.0.1** e o `X-Forwarded-For` que ele monta não identifica o cliente.

- IP do cliente (rate limit por IP, eventos): vem de `CF-Connecting-IP` **só** quando a requisição chega do proxy local confiável (127.0.0.1); em qualquer outro caso o header é ignorado e vale o IP da conexão. A API não aceita mais `--forwarded-allow-ips '*'` em produção. Recomendado ativar **Authenticated Origin Pulls** (mTLS Cloudflare → origem) para que só a Cloudflare chegue ao Caddy, já que o IP público da VPS continua alcançável.
- Backup externo: **Cloudflare R2**, bucket `secrets-backup`, via `rclone` com remoto `r2` (`--s3-no-check-bucket`, porque a credencial do bucket não lista/cria buckets). Prefixos `diario/` (8 dias), `semanal/` (35 dias) e `mensal/` (100 dias), expirados por **regras de ciclo de vida do R2**: o script **nunca apaga** nada no R2. Guarda de cota: o script calcula o uso projetado (uso atual do bucket + arquivo novo) e **falha** se passar de 9 GB (90% do plano grátis de 10 GB).
- MFA opcional por padrão (configurável pela política da org).
- Pré-requisitos no host ainda pendentes: `rclone` e `age` não estão instalados; o reload do Caddy exige `sudo` do usuário (não é feito pelo deploy automático).
- Backend `docker-compose.yml`: serviços `db`, `migrar`, `api`. `api` `depends_on: migrar: condition: service_completed_successfully`. Hoje (até a Fase 9) `uvicorn --proxy-headers --forwarded-allow-ips '*'`, aceitável só porque a porta escuta em 127.0.0.1; a Fase 9 troca pela regra do `CF-Connecting-IP` acima.
- Variáveis (`.env`, fora do git): `POSTGRES_PASSWORD` (dono), `APP_DB_PASSWORD`, `COFRE_SEGREDO`, `COOKIE_SECURE` (padrão `true`).
- Front `nginx.conf` (versionado): estáticos + headers; `location /api/` faz proxy para `${API_UPSTREAM}` (padrão `http://host.docker.internal:8098`) **só para desenvolvimento local**; em produção o Caddy roteia `/api/*` antes.
- Headers do front:
  `Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`
  `Strict-Transport-Security: max-age=31536000`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), clipboard-read=()`, `Cross-Origin-Opener-Policy: same-origin`.
- Logs: JSON em stdout (`logging` stdlib + formatter próprio), sem corpo de requisição; tokens (convite, recuperação) só trafegam no corpo, nunca em path/query; o link de convite usa fragmento (`https://<dominio>/#/convite/<token>`), que o browser não envia ao servidor. OTel → backlog.

---

## 7. Modelo de ameaças (resumo)

| Ameaça | Mitigação no MVP | Residual |
|---|---|---|
| Vazamento do banco/backup | Zero-knowledge; authHash re-hasheado com Argon2id + pepper fora do banco; backup cifrado com `age` | Senha-mestra fraca permite ataque offline (KDF caro + mínimo 12 chars no cliente) |
| Operador/servidor passivo | Servidor só vê blobs, ids, tamanhos, horários | Metadados de uso visíveis |
| Servidor ativo malicioso (troca JS) | CSP estrita, sem CDN, libs vendorizadas com hash | **Não mitigado**: quem controla o servidor entrega JS malicioso. Documentado. |
| Servidor troca chave pública de membro | Fingerprint conferido fora de banda pelo admin na confirmação | Admin que pula a conferência anula a proteção |
| Servidor faz rollback de item | AAD com `versao`/`chave_ver` impede trocar contexto | Rollback para blob antigo legítimo não detectado (backlog: manifesto assinado) |
| Ex-membro com chave antiga | Rotação de collectionKey + painel de senhas a rotacionar | O que ele já viu continua conhecido; troca real é no sistema de origem |
| Membro com `ver` forja item | — | Quem tem a collectionKey cifra blob válido; servidor barra gravação por permissão (limitação documentada) |
| Força bruta / enumeração | Rate limit por IP e conta, lockout 15 min, prelogin falso determinístico, verificação Argon2 falsa para e-mail inexistente | — |
| Roubo de sessão / CSRF | Cookie HttpOnly/Secure/SameSite=Strict, `X-Cofre`, origem única, expiração ociosa/absoluta | XSS anula tudo → CSP + Trusted Types + zero `innerHTML` |
| Supressão de auditoria | Evento gravado na mesma transação; append-only por grant + trigger | Dono do banco pode desabilitar o trigger (hash-chain no backlog) |
| Perda da senha-mestra | Kit de recuperação | Sem senha e sem kit = perda do acesso pessoal; coleções seguem acessíveis a outros membros |
| Malware no cliente | Fora de escopo | — |
