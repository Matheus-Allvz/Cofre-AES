# Arquitetura criptográfica para o Cofre de Senhas multiusuário

Escopo: evoluir o cofre atual (cifragem no servidor, `X-Senha-Mestra` em toda requisição, PBKDF2 210k, AES-256-GCM, sem usuários) para um cofre empresarial zero-knowledge, mantendo FastAPI + Postgres/Supabase no backend e JS puro + WebCrypto no browser.

Nota de método: os parâmetros do OWASP, do Bitwarden e o suporte a X25519 foram confirmados por busca (links ao final). Parâmetros do RFC 9106, RFC 9807 (OPAQUE), modelo do 1Password e do Passbolt vêm de conhecimento prévio e estão marcados com `[a verificar]`. Confirme no MDN/caniuse o suporte a X25519 antes de fixar.

## 0. Diagnóstico do estado atual

- A senha-mestra trafega em header em toda requisição e o servidor deriva a chave: o servidor vê tudo. Não é zero-knowledge; logs, proxies e APM podem capturar o header.
- O verificador `cofre-ok` permite ataque offline e funciona como oráculo online sem rate limit.
- RLS `using (true)` para `anon`: quem tiver a chave anon do Supabase lê/escreve qualquer linha direto, contornando a API.
- Título/usuário/URL em claro.
- Sem versão de item: o AAD `cofre_id|segredo_id` impede mover blobs, mas não detecta rollback para uma versão antiga do mesmo item.
- `app.js` usa `innerHTML` (linhas 223, 238, 279): XSS no front derruba qualquer garantia criptográfica no cliente.

## 1. Decisões recomendadas (resumo)

| # | Tema | Decisão |
|---|------|---------|
| 1 | Modelo | Zero-knowledge: toda cifragem/decifragem no browser. Servidor guarda só blobs cifrados, chaves públicas, chaves envelopadas e hash de autenticação. |
| 2 | Autenticação | Estilo Bitwarden: `masterKey` (KDF) -> `authHash` derivado em separado, enviado ao servidor; servidor aplica Argon2id com sal próprio e pepper. **Não usar OPAQUE agora** (seção 2.3). |
| 3 | KDF | **Argon2id** no cliente via WASM vendorizado (alvo m=64 MiB, t=3, p=1; piso OWASP 19 MiB/t=2/p=1). Fallback PBKDF2-SHA256 600k via WebCrypto. Parâmetros por usuário, versionados. |
| 4 | Hierarquia | masterKey -> HKDF -> kek -> envelopa `userKey` (AES-256 aleatória) -> envelopa chave privada do usuário; `collectionKey` AES-256 por coleção, envelopada para cada membro com a chave pública; itens cifrados com a `collectionKey` (ou itemKey sob ela). |
| 5 | Assimétrico | **X25519** (ECDH + HKDF + AES-GCM, estilo HPKE) como alvo: Chrome >= 133, Firefox >= 130, Safari (dez/2024 a jan/2025) segundo fontes secundárias. RSA-OAEP-3072/SHA-256 só se precisar de browser antigo. Escolher um, não manter os dois. |
| 6 | Simétrico | AES-256-GCM, IV 96 bits aleatório por operação, AAD amarrando contexto, envelope versionado (`v1.`). |
| 7 | Compartilhamento | Por coleção. Convite com troca de chave pública e fingerprint verificado fora de banda. |
| 8 | Revogação | Remove o envelope do membro e **rotaciona a `collectionKey`** com recifragem atômica. O membro revogado já viu o que viu: rotacionar as credenciais armazenadas é o remédio real. |
| 9 | Trocar senha-mestra | Só re-envelopa a `userKey`. Itens, chave privada e envelopes de coleção não mudam. |
| 10 | Recuperação | Kit de emergência (Recovery Key) para todos + recuperação por admin opt-in por organização, com aprovação de 2 admins e auditoria. Documentar que admin recovery é escrow. |
| 11 | Metadados | `titulo`, `usuario`, `url` cifrados dentro do blob. Busca no cliente após sync. Em claro: ids, `colecao_id`, tipo, timestamps, versão, tamanho. |
| 12 | Sessão | Sessão opaca no servidor (mais simples) ou JWT 5-10 min + refresh opaco rotativo com detecção de reuso; cookie `HttpOnly; Secure; SameSite=Strict`. |
| 13 | Anti-abuso | Rate limit por IP e por conta, lockout progressivo, resposta uniforme (sem enumeração), KDF falso para usuário inexistente. |
| 14 | MFA | TOTP na primeira fase, WebAuthn depois. MFA protege o login, não a cifragem. |
| 15 | Front | CSP estrita sem inline, Trusted Types, SRI ou vendorizar, remover `innerHTML` com dados, headers de segurança no nginx. |
| 16 | Integridade | AAD = `v|org|colecao|item|chave_ver|item_ver`; contador monotônico por item; histórico em `item_versoes`; `If-Match` para concorrência. |
| 17 | Migração | **Não migrar no servidor.** Importação assistida no cliente (última vez que a senha antiga é usada) ou "recriar". Depois, remover endpoints legados e rotacionar as senhas importadas. |
| 18 | Risco residual | O servidor serve o JS: servidor comprometido entrega JS malicioso. Mitigar com CSP/SRI, deploy imutável com hash publicado e, como evolução, extensão ou app com código assinado. |

## 2. Modelo zero-knowledge

### 2.1 O que o servidor guarda

- Por usuário: e-mail, `kdf_tipo`, `kdf_params`, `kdf_sal` (público, 16 B aleatórios), hash do authHash (Argon2id + sal + pepper), `userKey` envelopada, chave privada envelopada, chave pública, segredo TOTP cifrado com chave do servidor.
- Por organização/coleção: envelopes de `collectionKey` por membro, itens cifrados.
- Nunca: senha-mestra, masterKey, kek, userKey em claro, chaves privadas em claro, conteúdo ou metadados de itens.

### 2.2 Autenticação sem o servidor ver a senha (modelo Bitwarden)

```
masterKey = KDF(senha NFKC, sal=kdf_sal, params)         // 32 B, nunca sai do browser
authHash  = HKDF-Expand(masterKey, info="cofre/auth/v1")  // o que vai ao servidor
kek       = HKDF-Expand(masterKey, info="cofre/enc/v1")   // só em memória
```

Servidor: `armazenado = Argon2id(authHash, sal_srv)` mais pepper em secret. Comparação em tempo constante. Um vazamento do banco não entrega um authHash utilizável, e o authHash não decifra nada porque é separado do kek por derivação unidirecional. O whitepaper do Bitwarden descreve esse desenho: master key via KDF (PBKDF2 600k ou Argon2id), stretch por HKDF para 512 bits, hash da senha enviado ao servidor, re-salgado e re-hasheado antes de armazenar; master key e stretched key nunca são enviadas ou guardadas.

Fraqueza aceita: o servidor recebe um segredo equivalente à senha (authHash) a cada login; um servidor malicioso pode fazer ataque offline de dicionário sobre ele, com custo igual ao KDF. Por isso o KDF forte importa.

### 2.3 OPAQUE (RFC 9807) vs authHash

| Critério | authHash (Bitwarden) | OPAQUE |
|---|---|---|
| Servidor vê algo equivalente à senha | Sim (authHash) | Não (aPAKE) |
| Banco vazado | Resiste (sal único + hash no servidor) | Resiste (OPRF + envelope) |
| Maturidade JS + Python | Trivial (WebCrypto + argon2-cffi) | Bibliotecas escassas e pouco auditadas nas duas pontas; OPRF sobre ristretto255 não é nativo no WebCrypto `[a verificar]` |
| Risco de implementação | Baixo | Alto |
| Ganho real aqui | Médio | Reduzido: o servidor serve o JS, então um servidor malicioso captura a senha no front de qualquer forma |

Recomendação: **authHash agora; OPAQUE como evolução** quando houver biblioteca auditada nas duas pontas.

## 3. KDF

| Opção | Parâmetros | Prós | Contras |
|---|---|---|---|
| PBKDF2-HMAC-SHA256 | >= 600.000 (OWASP; o cheat sheet só a recomenda quando há exigência FIPS-140) | Nativo no WebCrypto | Barato em GPU/ASIC, sem memória-dura |
| **Argon2id** | Piso OWASP: m=19 MiB, t=2, p=1. Alvo: **m=64 MiB, t=3, p=1** (RFC 9106 sugere perfil de 64 MiB/t=3/p=4 `[a verificar]`; p=1 no browser evita exigir COOP/COEP e threads em WASM) | Memória-dura, recomendado por OWASP e RFC 9106 | Precisa de WASM; ordem de 0,3 a 1 s em notebook, mais em celular |

Viabilidade no browser: libs WASM como `hash-wasm` ou `argon2-browser` rodam single-thread sem COOP/COEP. Pinar versão exata e **vendorizar** JS + `.wasm` no repositório do front; se usar CDN, SRI obrigatório. Executar em Web Worker. CSP precisa de `'wasm-unsafe-eval'`. Guardar `kdf_tipo` e params por usuário para subir o custo no futuro (re-derivar no login e re-envelopar a `userKey`). Bitwarden segue caminho equivalente: PBKDF2 600k por padrão (mínimo imposto desde a versão 2026.2.1 segundo a documentação), Argon2id opcional (padrão 32 MiB/6/4 na documentação consultada).

Detalhes:
- Sal de 16 B aleatório por usuário (não usar o e-mail). Exige endpoint `prelogin`; para e-mail desconhecido devolver sal e params falsos determinísticos (HMAC(e-mail, segredo do servidor)) para não enumerar.
- Normalizar a senha em Unicode NFKC antes do KDF (NIST 800-63B).
- Política de senha-mestra (NIST 800-63B, OWASP ASVS V2): mínimo 12 caracteres, aceitar 64 ou mais, sem regras de composição, bloquear senhas vazadas por k-anonymity (HIBP, consultado no cliente), medidor zxcvbn. Esta senha é a única proteção dos dados em repouso.

## 4. Hierarquia de chaves

```
senha-mestra
   | Argon2id(sal, m, t, p)
   v
masterKey (32 B) --HKDF("auth")--> authHash --> servidor: Argon2id + pepper
   |
   +--HKDF("enc")--> kek (AES-256, só em memória)
                       | AES-GCM (AAD: user_id|"userkey"|v)
                       v
                   userKey (32 B aleatória)           [guardada envelopada]
                       | AES-GCM (AAD: user_id|"privkey")
                       +--> chavePrivadaUsuario (X25519, PKCS8)
                       |       par: chavePublicaUsuario (raw/SPKI, pública no servidor)
                       +--> (opcional) chave de assinatura Ed25519

chavePublicaUsuario_i --> envelope(collectionKey, i)    // um por membro
   collectionKey (32 B aleatória por coleção, versionada: chave_ver)
        | AES-GCM (AAD: org|colecao|item|chave_ver|item_ver)
        v
     item cifrado {titulo, usuario, url, senha, notas, totp, campos...}

(opcional) itemKey (32 B) por item, cifrada pela collectionKey: a rotação
da collectionKey só re-envelopa itemKeys, sem recifrar todo o conteúdo.
```

Formatos:
- Simétrico: `v1.<b64 iv 12B>.<b64 ct||tag 16B>`; AAD reconstruído pelo cliente, nunca vindo do servidor. IV sempre de `crypto.getRandomValues`. GCM com chave de longa vida tem limite de 2^32 cifragens (NIST SP 800-38D): irrelevante nesta escala, e a itemKey elimina a preocupação.
- Assimétrico X25519 (HPKE-like): remetente gera par efêmero; `shared = ECDH(eph_priv, pub_destino)`; `key = HKDF(shared, salt = eph_pub || pub_destino, info = "cofre/v1/collectionKey")`; `AES-GCM(key, collectionKey, aad = ids)`; guardar `eph_pub` junto. Para provar quem convidou, assinar com Ed25519 (mesmo suporte nos browsers). Alternativa RSA-OAEP-3072/SHA-256 cifra direto os 32 B da chave.
- WebCrypto: importar chaves com `extractable: false` quando possível; manter tudo só em memória (o front atual já evita localStorage/sessionStorage/cookies para a senha).

Suporte a X25519 no WebCrypto (busca, fontes secundárias de 2024-2025): Firefox 130 (set/2024), Safari/WebKit (dez/2024, release em jan/2025), Chrome 133 (fev/2025). Em 2026 é viável exigir browser moderno; confirmar no MDN.

## 5. Compartilhamento, convite, revogação, troca de senha

### 5.1 Modelo de acesso

- Organização -> coleções -> itens. Papéis: `owner`, `admin`, `member` com permissão ler/escrever/gerenciar.
- O servidor autoriza ações (quem pode gravar, convidar); a confidencialidade vem de quem possui o envelope da `collectionKey`. O servidor não consegue conceder acesso real sozinho.
- Quem lê a `collectionKey` também pode forjar blobs válidos. Se a distinção ler/escrever for requisito forte, assinar itens por editor (Ed25519); senão, documentar como limitação.

### 5.2 Convite de membro

1. Admin informa o e-mail; o servidor cria convite com token aleatório de uso único, validade <= 7 dias (guardar só o hash do token).
2. Convidado se cadastra ou entra, gera suas chaves e envia a chave pública. Estado: `aceito`.
3. **Fingerprint**: os dois clientes exibem `SHA-256(chave pública)` formatado (grupos hex e/ou frase de palavras, como o fingerprint phrase do Bitwarden). O admin confere por canal fora de banda (voz, chat corporativo). Sem isso, um servidor malicioso troca a chave pública do convidado pela dele e recebe a `collectionKey`.
4. Admin confirma: o cliente dele decifra a `collectionKey`, cifra para a chave pública do convidado e envia o envelope. Estado: `confirmado`.
5. Depois, TOFU: o cliente guarda o fingerprint confirmado e alerta se mudar. Opcional: lista append-only das chaves de membros, assinada pelo owner.

Contraponto Passbolt (OpenPGP): cada usuário tem par OpenPGP e cada segredo é cifrado para a chave pública de cada destinatário, sem chave de coleção. Simples e padronizado, mas compartilhar com N pessoas custa N cifragens por segredo e revogar exige remover cópias (o segredo já visto continua conhecido). Para este projeto, o modelo de coleção estilo Bitwarden custa menos por item e permite rotação em um passo. `[a verificar detalhes do Passbolt]`

### 5.3 Revogação / offboarding

- Remover membro: apagar o envelope dele e bloquear a API (efeito imediato contra servidor honesto).
- Contra quem já tem a chave: **rotacionar**. Admin gera `collectionKey` nova (`chave_ver + 1`), recifra itens (ou re-envelopa itemKeys), envia tudo em uma transação (`POST /colecoes/{id}/rotacionar`, valida `chave_ver` antiga -> nova, recusa se algum item ficou para trás) e distribui envelopes novos aos membros restantes.
- Em saída por incidente, trocar também as senhas armazenadas: o que o ex-membro viu continua conhecido por ele. Isto vale para qualquer cofre.
- Estado `rotacao_pendente` para quando nenhum admin com a chave está online.

### 5.4 Troca de senha-mestra

Cliente: pede a senha atual, deriva a kek antiga, decifra a `userKey`, gera sal novo e deriva masterKey nova, cifra a **mesma** `userKey`, calcula authHash novo e envia `{authHash_antigo, authHash_novo, chave_usuario_cif, kdf_params, kdf_sal}`. Servidor valida o antigo, troca de forma atômica e **invalida todas as sessões e refresh tokens**. Itens, chave privada e envelopes de coleção não mudam. Se houver suspeita de comprometimento da `userKey`, existe a rotação completa de `userKey` (recifra a chave privada e re-envelopa tudo): operação separada e rara.

## 6. Recuperação de conta

| | Recuperação por admin (org) | Kit de emergência (Recovery Key) |
|---|---|---|
| Mecanismo | No enrollment, o cliente cifra a `userKey` com a chave pública de recuperação da org (privada com owners/admins). Admin autoriza o reset, o usuário define senha nova e a `userKey` é re-envelopada. Desenho do Account Recovery do Bitwarden (exige enrollment prévio; não burla SSO/2FA do IdP). | Na criação, gera-se uma Recovery Key aleatória de 128 a 256 bits; a `userKey` fica envelopada também por ela. Usuário imprime e guarda. Conceito equivalente ao Secret Key / Emergency Kit do 1Password `[a verificar]`. |
| Quem recupera | Admin com a chave privada da org (escrow) | Só quem tem o kit |
| Risco | Admin malicioso ou comprometido acessa contas inscritas | Perdeu o kit, perdeu os dados |
| Servidor sabe a chave | Não | Não |

Decisão: oferecer os dois. Admin recovery é opt-in por org, com política visível ao usuário, aprovação de 2 admins, e-mail de notificação e auditoria. Kit é o padrão. Em ambos, não burlar o MFA e **gerar kit novo** após o uso. Perguntas de segurança são desaconselhadas (NIST 800-63B não admite autenticadores baseados em conhecimento do tipo).

## 7. Proteções do servidor

- **RLS**: remover a policy `laboratorio`. O backend usa conexão direta ao Postgres ou `service_role` (nunca a chave anon no cliente); `anon` sem nenhuma policy. Opcional: RLS por `org_id` como defesa em profundidade.
- **Rate limit** (NIST 800-63B: limitar falhas consecutivas, no máximo 100; OWASP ASVS V2): por IP e por conta, backoff exponencial, lockout temporário (ex.: 15 min após 10 falhas) com notificação. Resposta idêntica e tempo equalizado para usuário inexistente. Também em `prelogin`, convite, recuperação e TOTP.
- **Sessão**: opaca (id de 256 bits, hash no banco, expiração absoluta 12 h, ociosa 30 min, revogável) ou JWT de 10 min + refresh opaco rotativo com detecção de reuso. Cookie `HttpOnly; Secure; SameSite=Strict` e header customizado como proteção CSRF. Nunca JWT em localStorage. **Auto-lock** por inatividade: descarta `userKey` da memória e exige a senha-mestra de novo.
- **MFA**: TOTP (segredo de 160 bits, cifrado em repouso com chave do servidor, janela ±1, anti-replay do código usado), códigos de backup hasheados. WebAuthn depois, por resistir a phishing.
- **Transporte e logs**: TLS, HSTS, nunca logar corpo de `/login` e `/trocar-senha`. Remover `X-Senha-Mestra` do CORS e das rotas.
- **Auditoria**: tabela append-only de eventos (login ok/falha, convite, confirmação, revogação, rotação, recuperação), sem dados cifrados.
- **Headers do nginx do front**:
  - `Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src <origem da API>; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'`
  - `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` restritiva, `Cross-Origin-Opener-Policy: same-origin`, `Cache-Control: no-store` nas respostas da API.
  - Sem `<script>` inline; SRI em qualquer recurso de terceiros, ou vendorizar. Trocar os `innerHTML` por `textContent` / `createElement`.

## 8. Integridade e versionamento

- AAD amarra o contexto: `"cofre/v1" | org_id | colecao_id | item_id | chave_ver | item_ver`. Impede mover blobs entre itens/coleções e reaproveitar um blob em contexto diferente (o código atual já faz `cofre_id|segredo_id`).
- **Rollback**: `item_ver` no AAD só ajuda se o cliente sabe qual versão esperar. O cliente guarda `ultima_versao_vista` por item (em memória; `localStorage` apenas como cache de conveniência) e alerta se retroceder. Proteção forte contra rollback total pelo servidor exige estado no cliente ou um manifesto por coleção (`{item_id, ver, hash}`) assinado pelo último editor (Ed25519): evolução, não requisito inicial.
- **Histórico**: `item_versoes` guarda blobs anteriores cifrados com a `collectionKey` da época (por isso `chave_ver` fica registrado). Na rotação, recifrar o histórico ou truncar para N versões. Restaurar = gravar como nova versão.
- Concorrência otimista: `PUT` com `If-Match: <item_ver>`; conflito retorna 409.
- Exclusão: soft delete com retenção, depois purge.

## 9. Esquema de dados sugerido

Convenção: `*_cif` = envelope `v1.iv.ct` em texto; demais colunas são visíveis ao servidor.

```sql
create table usuarios (
  id uuid primary key,
  email citext unique not null,
  kdf_tipo text not null,                 -- 'argon2id' | 'pbkdf2'
  kdf_params jsonb not null,              -- {m,t,p} ou {iter}
  kdf_sal bytea not null,                 -- 16 B, público
  auth_hash_srv text not null,            -- Argon2id(authHash, sal_srv) + pepper
  chave_usuario_cif text not null,        -- userKey sob kek
  chave_usuario_recup_cif text,           -- userKey sob Recovery Key (kit)
  chave_publica bytea not null,
  chave_privada_cif text not null,        -- sob userKey
  chave_assin_publica bytea,              -- Ed25519 (opcional)
  chave_assin_privada_cif text,
  totp_segredo_cif text,                  -- cifrado pelo servidor
  falhas_login int default 0, bloqueado_ate timestamptz,
  criado_em timestamptz default now()
);

create table organizacoes (
  id uuid primary key, nome text not null,
  chave_publica_recup bytea,              -- se recuperação por admin ativa
  recup_politica jsonb                    -- ex.: {aprovadores: 2}
);

create table membros_org (
  org_id uuid references organizacoes, usuario_id uuid references usuarios,
  papel text not null,                    -- owner|admin|member
  estado text not null,                   -- convidado|aceito|confirmado|revogado
  fingerprint_confirmado bytea,           -- SHA-256 da chave pública confirmada
  chave_usuario_recup_org_cif text,       -- userKey sob chave pública de recuperação da org
  primary key (org_id, usuario_id)
);

create table colecoes (
  id uuid primary key, org_id uuid not null references organizacoes,
  nome_cif text not null,                 -- sob collectionKey
  chave_ver int not null default 1
);

create table colecao_membros (            -- envelopes da collectionKey
  colecao_id uuid, usuario_id uuid, chave_ver int,
  chave_colecao_cif text not null,        -- sob chave pública do membro
  permissao text not null,                -- ler|escrever|gerenciar
  primary key (colecao_id, usuario_id, chave_ver)
);

create table itens (
  id uuid primary key, colecao_id uuid not null references colecoes,
  tipo text not null,                     -- login|nota|cartao
  versao int not null default 1,
  chave_ver int not null,
  chave_item_cif text,                    -- itemKey sob collectionKey (opcional)
  dados_cif text not null,                -- {titulo,usuario,url,senha,notas,campos,totp}
  criado_por uuid, criado_em timestamptz default now(),
  atualizado_em timestamptz default now(), excluido_em timestamptz
);

create table item_versoes (
  item_id uuid, versao int, chave_ver int, dados_cif text not null,
  editado_por uuid, em timestamptz default now(),
  primary key (item_id, versao)
);

create table sessoes  (id_hash bytea primary key, usuario_id uuid, expira_em timestamptz);
create table convites (token_hash bytea primary key, org_id uuid, email citext, expira_em timestamptz, usado bool);
create table eventos  (id bigserial primary key, em timestamptz default now(),
                       usuario_id uuid, org_id uuid, tipo text, ip inet, meta jsonb);
```

## 10. Fluxos

**Cadastro**
1. Browser gera `kdf_sal`, escolhe params, deriva masterKey (Worker), authHash e kek.
2. Gera `userKey` (32 B) e o par de chaves; cifra a `userKey` com a kek e a chave privada com a `userKey`. Gera a Recovery Key (exibir uma vez, exigir confirmação) e envelopa a `userKey` nela.
3. `POST /cadastro` com e-mail, params, authHash, envelopes e chave pública. Servidor guarda Argon2id(authHash). Em seguida, enrollment TOTP.

**Login**
1. `POST /prelogin {email}` devolve `{kdf_tipo, params, sal}` (falsos e determinísticos para e-mail desconhecido).
2. Cliente deriva masterKey e authHash. `POST /login {email, authHash, totp}`; servidor verifica em tempo constante, com rate limit, e emite a sessão.
3. Resposta traz `chave_usuario_cif` e `chave_privada_cif`; o cliente decifra com a kek. Falha de GCM aqui indica dado adulterado, não senha errada (senha errada já falhou na autenticação).
4. `GET /sync`: coleções, envelopes e itens cifrados. Cliente decifra as `collectionKey` e os metadados em memória e monta o índice de busca local.

**Criar item**: cliente gera `item_id`, monta o JSON, cifra com AES-GCM e AAD de contexto, `POST /itens {colecao_id, tipo, chave_ver, dados_cif}`. Servidor valida permissão, `chave_ver` atual e tamanho, grava e devolve `versao`. **Editar**: igual, com `If-Match`; o servidor copia a versão anterior para `item_versoes`.

**Compartilhar**: convite da seção 5.2. Dar acesso a outra coleção a um membro já verificado é só um novo envelope para a chave pública já confirmada.

**Revogar**: seção 5.3, endpoint transacional de rotação.

**Trocar senha-mestra**: seção 5.4.

**Recuperar**
- Kit: e-mail + Recovery Key + verificação do e-mail/MFA; cliente decifra a `userKey` por `chave_usuario_recup_cif`, define senha nova, envia novo authHash e `userKey` re-envelopada, e gera **kit novo**.
- Admin: usuário solicita, admins aprovam, o cliente do admin decifra a privada da org e a `userKey` do usuário, que define a senha nova e re-envelopa. Auditoria e notificação ao usuário.

## 11. Migração dos cofres atuais

Recomendação: **não migrar no servidor; descontinuar o modelo antigo.**
- O servidor só migraria recebendo a senha-mestra de cada cofre, exatamente o que se quer eliminar, e o cofre antigo não tem usuário/dono para associar.
- Caminho barato: manter por uma janela curta endpoints legados somente leitura. Ferramenta "importar" no front: pede id do cofre legado e a senha-mestra antiga, baixa e decifra via API antiga (última vez que a senha trafega), cria os itens no modelo novo cifrados no cliente. Em seguida, apagar as linhas legadas e remover a rota.
- Em contexto acadêmico, "recriar o cofre" é aceitável.
- Tratar o conteúdo legado como exposto ao servidor: após importar, rotacionar as senhas armazenadas.

## 12. Riscos residuais

1. **O servidor serve o JS.** Servidor, CDN, nginx ou pipeline de deploy comprometidos entregam código que exfiltra senha-mestra ou chaves; zero-knowledge vale contra vazamento do banco e operadores passivos. Mitigações: CSP estrita + Trusted Types, SRI, sem libs de terceiros em runtime (vendorizar o WASM), deploy imutável com hash do bundle publicado e verificável, build reproduzível, contas separadas para host estático e API, alerta de mudança de hash. Evolução forte: extensão de navegador ou app desktop com código assinado e instalado, em vez de servido a cada visita.
2. XSS no front dá acesso às chaves em memória: eliminar `innerHTML` com dados, Trusted Types, sem `eval`.
3. Metadados de uso: o servidor vê quem acessa o quê, quando e o tamanho dos blobs. Padding opcional.
4. Senha-mestra fraca permite ataque offline sobre authHash/envelopes se o banco vazar; KDF e política de senha mitigam.
5. Cliente comprometido (malware, keylogger) está fora de escopo.
6. Sem assinatura por item, não há autoria criptográfica de conteúdo (seção 5.1).
7. Recuperação por admin é escrow por definição: manter opt-in e auditável.
8. `crypto.subtle` exige contexto seguro (HTTPS/localhost). Memória JS não é zerável: usar auto-lock curto.

## Referências

Confirmadas por busca:
- Bitwarden Security White Paper: https://bitwarden.com/help/bitwarden-security-white-paper/
- Bitwarden KDF algorithms: https://bitwarden.com/help/kdf-algorithms/
- Bitwarden Account Recovery: https://bitwarden.com/help/account-recovery/
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- X25519 no WebCrypto (Igalia): https://blogs.igalia.com/jfernandez/?p=1913
- Firefox bug X25519: https://bugzil.la/1904836
- WebKit bug X25519: https://bugs.webkit.org/show_bug.cgi?id=284368

De conhecimento prévio (verificar antes de citar):
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-63B: https://pages.nist.gov/800-63-4/sp800-63b.html
- NIST SP 800-132: https://csrc.nist.gov/pubs/sp/800/132/final
- NIST SP 800-38D: https://csrc.nist.gov/pubs/sp/800/38/d/final
- RFC 9106 (Argon2): https://www.rfc-editor.org/rfc/rfc9106
- RFC 9807 (OPAQUE): https://www.rfc-editor.org/rfc/rfc9807
- RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180
- 1Password Security Design White Paper: https://1passwordstatic.com/files/security/1password-white-paper.pdf
- Passbolt Security White Paper: https://www.passbolt.com/security/white-paper
- MDN SubtleCrypto (suporte atual de algoritmos): https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
