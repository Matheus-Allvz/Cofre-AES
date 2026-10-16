# Fases de implementação — Cofre AES Empresarial

Referências obrigatórias para todo construtor/validador: `ARQUITETURA-ALVO.md` (formatos, AAD, contrato, esquema), `REQUISITOS.md` (IDs e critérios), `PROTOCOLO-AGENTES.md` (como trabalhar e validar).
Repos locais: backend `C:\Users\ACT\Documents\Personal\Cofre_AES` (= **BE**), frontend `C:\Users\ACT\Documents\Personal\Cofre-AES-Frontend` (= **FE**). Base de todo PR: `empresarial`.

## Visão geral

| Fase | Nome | Repos | Depende de | Paralelizável com |
|---|---|---|---|---|
| 1 | Fundação do backend (Postgres, migrations, CI) | BE | — | 2 |
| 2 | Fundação do frontend e núcleo cripto | FE | — | 1 |
| 3 | Contas, convite e sessão | BE + FE | 1, 2 | — |
| 4 | MFA, políticas e recuperação | BE + FE | 3 | — |
| 5 | Membros da organização | BE + FE | 4 | — |
| 6 | Coleções e itens | BE + FE | 5 | — |
| 7 | Compartilhamento, revogação e offboarding | BE + FE | 6 | — |
| 8 | Auditoria, LGPD e backup/restauração | BE + FE | 7 | — |
| 9 | Implantação na VPS | BE + FE | 8 + ações humanas | — |

Ordem de merge em fases com dois repos: **BE primeiro**, depois re-rodar o CI do FE (o E2E do FE usa o `empresarial` do BE).

## Comandos padrão (referenciados nas DoDs)

BE (Git Bash, raiz do repo):
```bash
docker compose -f docker-compose.teste.yml up -d --wait          # postgres:16-alpine em 127.0.0.1:55432 (postgres/postgres)
python -m venv .venv && . .venv/Scripts/activate                 # Linux/CI: .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
ruff check . && ruff format --check .
pytest -q --cov=app --cov-fail-under=80                          # [BE-TEST]
pip-audit -r requirements.txt                                    # [BE-AUDIT]
cp .env.exemplo .env && docker compose up -d --build --wait      # [BE-UP] api em 127.0.0.1:8098
```
FE (Node ≥ 22, sem `npm install`):
```bash
node --test test/unit/                                           # [FE-UNIT]
bash scripts/e2e-backend.sh ../Cofre_AES                         # sobe BE limpo (projeto compose cofre-e2e), cria org, exporta E2E_API e E2E_CONVITE_OWNER em .e2e.env
set -a; . ./.e2e.env; set +a; node --test test/e2e/              # [FE-E2E] (pula com aviso se E2E_API ausente)
docker compose up -d --build && curl -fsSI http://127.0.0.1:8097/  # [FE-UP]
```

---

## Fase 1 — Fundação do backend

**Objetivo:** trocar Supabase por Postgres 16 próprio com migrations, papéis de banco, auditoria append-only, health, logs JSON e CI; remover o modelo acadêmico da branch.
**Requisitos:** RF-O01 (org), RF-A04, RNF-07 (formatter), RNF-09, RNF-10, RNF-11, RNF-12, RNF-14 (parte compose/Docker).
**Repos:** BE. **Dependências:** nenhuma.

**Escopo**
- Remover: `app/banco.py`, `app/cripto.py`, `app/modelos.py`, rotas `/cofres*`, `sql/esquema.sql`, `supabase*`/`postgrest`/`realtime`/`storage3`/`pycryptodome` do `requirements.txt`, `.github/workflows/deploy.yml`, `deploy.sh`, `testes/` (evidências acadêmicas). `README.md` reescrito para a versão empresarial (curto: como subir, testar, arquitetura em 10 linhas, link para `docs/`).
- Criar:
  - `app/config.py` (lê env: `DATABASE_URL`, `DATABASE_URL_DONO` só no migrador, `COFRE_SEGREDO`, `COOKIE_SECURE`), `app/db.py` (pool `psycopg_pool`, helper de transação), `app/erros.py` (handler `{"erro": codigo}`), `app/logs.py` (formatter JSON stdlib, sem corpo de requisição), `app/main.py` (FastAPI, `/api/saude`, `/api/pronto`, middleware `Cache-Control: no-store`), `app/migrar.py` (runner D4), `app/auditoria.py` (`registrar(conn, ...)` — usa a conexão/transação recebida).
  - `migracoes/0001_base.sql`: `citext`, `schema_migracoes` (criada pelo runner), `organizacoes`, `eventos` + trigger anti-UPDATE/DELETE, `ALTER DEFAULT PRIVILEGES` concedendo `SELECT, INSERT, UPDATE, DELETE` em tabelas e `USAGE, SELECT` em sequências a `cofre_app`, `REVOKE UPDATE, DELETE, TRUNCATE ON eventos FROM cofre_app`.
  - `db/init/10-papel-app.sh` (cria `cofre_app` LOGIN com `$APP_DB_PASSWORD` no primeiro boot do container).
  - `Dockerfile` (python:3.14-slim, usuário não-root, `HEALTHCHECK` em `/api/saude`, `uvicorn --proxy-headers --forwarded-allow-ips '*' --workers 1`), `docker-compose.yml` (`db` sem `ports`, volume nomeado, `mem_limit`; `migrar` one-shot; `api` em `127.0.0.1:8098:8000`, `depends_on` `service_completed_successfully`), `docker-compose.teste.yml` (Postgres em `127.0.0.1:55432`), `.env.exemplo` (só nomes e valores fictícios).
  - `requirements.txt` (fixado: fastapi, uvicorn, psycopg[binary], psycopg_pool, argon2-cffi, cryptography) e `requirements-dev.txt` (pytest, pytest-cov, httpx, ruff, pip-audit). `pyproject.toml` só com config do ruff/pytest.
  - `tests/conftest.py`: conecta como dono em `TEST_DATABASE_URL_DONO` (padrão `postgresql://postgres:postgres@127.0.0.1:55432/postgres`), cria `cofre_app` se faltar, cria banco temporário por sessão de teste, roda migrations como dono, app sob teste conecta como `cofre_app`; limpa tabelas entre testes (como dono, `TRUNCATE ... RESTART IDENTITY CASCADE` — inclusive `eventos`, desabilitando o trigger só dentro do fixture); `TestClient(app, base_url="https://testserver")`.
  - `tests/test_migrar.py`, `tests/test_saude.py`, `tests/test_eventos_append_only.py`, `tests/test_compose.py` (lê o YAML: `db` sem `ports`; toda porta publicada começa com `127.0.0.1:`; `api` com `user` não-root no Dockerfile), `tests/test_logs.py`.
  - `.github/workflows/ci.yml`: `on: pull_request` e `push` para `empresarial`; service `postgres:16-alpine`; Python 3.14; ruff, pytest com cobertura, pip-audit, `gitleaks/gitleaks-action@v2`; `docker build .`. **Sem deploy.**
- Fora de escopo: qualquer rota de usuário/login; OTel; frontend.

**Entregáveis:** API que sobe com `docker compose up`, aplica migrations e responde health; CI verde.

**Definição de Pronto**
1. `git ls-files | grep -Ei "supabase|banco.py|cripto.py|esquema.sql|deploy.yml|deploy.sh"` → vazio. `grep -ri "x-senha-mestra\|supabase" app/ requirements*.txt` → vazio.
2. [BE-TEST] passa; cobertura ≥ 80%.
3. `ruff check .` e `ruff format --check .` → sem erro. [BE-AUDIT] → sem vulnerabilidade (ou cada exceção justificada no PR com `--ignore-vuln` e motivo).
4. [BE-UP] seguido de `curl -fsS http://127.0.0.1:8098/api/saude` → `{"status":"ok"}`; `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8098/api/pronto` → `200`; `docker compose stop db` e repetir → `503`.
5. `docker compose logs migrar` mostra `0001_base` aplicada; rodar `docker compose run --rm migrar` de novo → "nada a aplicar", exit 0.
6. Teste existe e passa: alterar o conteúdo de uma migration já aplicada faz o runner sair com erro `checksum_divergente`.
7. Teste existe e passa: como `cofre_app`, `UPDATE eventos ...` e `DELETE FROM eventos` → `psycopg.errors.InsufficientPrivilege`; como dono → erro levantado pelo trigger.
8. `docker compose exec api id -u` → diferente de `0`. `docker compose port db 5432` → sem mapeamento.
9. Teste existe e passa: log de uma requisição é JSON válido com `nivel`, `msg`, `rota`, `status`, `duracao_ms`, e **não** contém o corpo da requisição (envia corpo com sentinela `SENTINELA-F1` e verifica ausência em `caplog`/stdout).
10. Run do CI no PR verde; o PR contém link para um run anterior (commit descartável ou `workflow_dispatch`) em que um teste falhando deixou o CI vermelho.
11. Resposta de qualquer rota `/api/*` tem `Cache-Control: no-store`.

**Checklist do validador**
- Rodar tudo da DoD em clone limpo (`git clone -b fase-1-fundacao-backend`), não no diretório do construtor.
- Ler `migracoes/0001_base.sql`: trigger cobre `UPDATE` **e** `DELETE`; `REVOKE` explícito em `eventos`; nada de `GRANT ALL`.
- Conferir que `DATABASE_URL_DONO` só aparece no serviço `migrar` do compose, não no `api`.
- Conferir `.dockerignore` (`.env`, `.venv`, `.git`, `tests/`) e `.gitignore`.
- Negativo: `psql` como `cofre_app` tentando `TRUNCATE eventos` → falha.
- Conferir que `deploy.yml` da `main` não foi alterado (`git diff origin/main -- .github` só mostra o arquivo removido nesta branch; nenhum push na `main`).

**Riscos/armadilhas**
- Wheels de `psycopg[binary]`/`argon2-cffi` para Python 3.14: se faltarem, usar `psycopg[c]` com `libpq-dev` no build e registrar no PR.
- Init scripts do Postgres só rodam com volume vazio; documentar `docker compose down -v` para recriar.
- `ALTER DEFAULT PRIVILEGES` vale para objetos criados **pelo papel que o executa** (o dono): migrations devem rodar sempre como `cofre_dono`.
- Service container do GitHub não executa `db/init`: o `conftest` cria o papel.

**Ações humanas:** nenhuma.

---

## Fase 2 — Fundação do frontend e núcleo cripto

**Objetivo:** reestruturar o front em módulos ES, endurecer headers/CSP, vendorizar Argon2id e entregar `cripto.js` completo e testado contra vetores independentes. UI final ainda não existe: a página mostra o estado da API.
**Requisitos:** RNF-02 (headers), RNF-03 (KDF cliente), RNF-C02, RNF-C03, RNF-C04, RNF-10 (front).
**Repos:** FE. **Dependências:** nenhuma (pode rodar junto da Fase 1).

**Escopo**
- Remover: `app.js` acadêmico, `.github/workflows/deploy.yml`, `deploy.sh`.
- Criar:
  - `public/index.html` (sem script/estilo inline; `<script type="module" src="/js/main.js">`), `public/css/style.css` (reaproveitar o atual), `public/js/main.js` (detecta suporte; mostra "navegador não suportado" ou o resultado de `GET /api/saude`), `public/js/dom.js` (helpers `el(tag, attrs, ...filhos)` com `textContent`; único lugar que cria DOM).
  - `public/js/cripto.js` (funções puras, sem DOM, importável no Node): `b64u`/`deB64u`, `normalizarSenha` (NFKC), `derivarMasterKey(senha, sal, kdf)`, `derivarAuthHash`, `derivarKek`, `gerarChaveAes`, `cifrarV1(chave, dados, aad)`/`decifrarV1`, `gerarParX25519`, `envelopeX1(pubDestino, collectionKeyBytes, aad)`/`abrirX1(privada, env, aad)`, `aad.*` (um construtor por linha da tabela §3.3), `gerarRecoveryKey`/`formatarRecoveryKey`/`lerRecoveryKey`, `derivarRecupKek`/`derivarRecupAuth`, `fingerprint(pubRaw)`, `detectarSuporte()`, `validarSenhaMestra(s)` (≥ 12 code points). Funções internas que aceitam IV/par efêmero fixos ficam exportadas com prefixo `_paraTeste`.
  - `public/vendor/hash-wasm/<arquivo>` + `public/vendor/README.md` (nome, versão exata, URL do tarball npm, SHA-256 do arquivo, licença).
  - `test/unit/cripto.test.mjs`, `test/unit/varredura.test.mjs` (proíbe `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, atributos `on*=` e `<script>` sem `src` em `public/`; confere SHA-256 do vendorizado), `test/unit/nginx.test.mjs` (confere cada header de §6 da arquitetura no `nginx.conf`).
  - `test/vetores/gerar_vetores.py` (usa `argon2-cffi` low-level `hash_secret_raw` e `cryptography` HKDF/AESGCM/X25519 com entradas fixas) + `test/vetores/vetores.json` versionado. README do diretório diz como regerar.
  - `nginx.conf` (headers §6; `location /api/ { proxy_pass ${API_UPSTREAM}; }` via `/etc/nginx/templates`), `Dockerfile` (`nginx:alpine`, copia só `public/` e o template), `docker-compose.yml` (`127.0.0.1:8097:80`, `extra_hosts: host.docker.internal:host-gateway`, `API_UPSTREAM` padrão `http://host.docker.internal:8098`), `.dockerignore`, `package.json` mínimo (`{"private":true,"type":"module"}`, sem dependências).
  - `.github/workflows/ci.yml`: `on: pull_request`/`push` para `empresarial`; Node 22; `node --test test/unit/`; gitleaks. (Job E2E entra na Fase 3.)
- Fora de escopo: telas de login/cofre; chamadas autenticadas; Web Worker (D7).

**Entregáveis:** `cripto.js` testado; front servido com CSP estrita; CI verde.

**Definição de Pronto**
1. [FE-UNIT] passa com, no mínimo, estes testes nomeados: `argon2id confere com vetor python`, `hkdf auth/kek conferem`, `v1 cifra/decifra ida e volta`, `v1 com AAD diferente falha`, `v1 com 1 bit trocado no ct falha`, `x1 confere com vetor python`, `x1 com chave privada errada falha`, `x1 com AAD diferente falha`, `recovery key formata e relê (com/sem hífen, minúscula)`, `fingerprint de vetor conhecido`, `validarSenhaMestra 11 recusa / 12 aceita / emoji conta como 1`, `detectarSuporte falso sem X25519`.
2. `python test/vetores/gerar_vetores.py --verificar` (regera em memória e compara com `vetores.json`) → exit 0.
3. Varredura (`varredura.test.mjs`) passa; o validador insere `el.innerHTML = x` num arquivo de `public/js/` e o teste falha.
4. SHA-256 de `public/vendor/hash-wasm/*` (via `sha256sum`) igual ao de `vendor/README.md`, e igual ao do tarball oficial no npm na versão registrada.
5. [FE-UP] com a API da Fase 1 rodando (ou não): `curl -sI http://127.0.0.1:8097/` traz todos os headers de §6 com valores exatos. `docker compose exec front ls /usr/share/nginx/html` não lista `test`, `package.json`, `.git` nem `Dockerfile`.
6. M: abrir `http://127.0.0.1:8097/` no Chromium e no Firefox: console sem violação de CSP/Trusted Types; página mostra status da API (ok se Fase 1 de pé, mensagem de erro clara se não). Executar `derivarMasterKey` pela página (botão de diagnóstico **só** se `?diag=1`) termina em < 3 s num notebook comum; registrar tempo no PR.
7. CI verde no PR.

**Checklist do validador**
- Comparar à mão `cripto.js` com §3 da arquitetura: strings de `info` do HKDF, ordem do `salt` do x1 (`eph_pub||pub_destino`), formato `v1.`/`x1.`, base64url sem padding, AAD por tabela.
- Confirmar que `vetores.json` foi gerado pelo Python (não pelo JS): rodar o passo 2.
- Confirmar que `importKey` de chaves AES usa `extractable:false` exceto onde §2 permite.
- Confirmar que nada usa `Math.random` (`grep -rn "Math.random" public/` → vazio).
- Negativo: servir `index.html` com um `<script>alert(1)</script>` inline localmente → bloqueado pela CSP (console mostra violação).

**Riscos/armadilhas**
- `hash-wasm` embute o WASM em base64 e chama `WebAssembly.compile`: exige `'wasm-unsafe-eval'` (já na CSP). Escolher build que funcione como ES module no browser **e** no Node (`import`); se só houver UMD, carregar via `<script src>` no browser e `createRequire` no Node — registrar a escolha.
- `trusted-types 'none'` quebra qualquer lib que use sinks de TT; validar no Chromium.
- Node: `crypto.subtle` global existe no Node ≥ 19; X25519 no Node ≥ 20 **[CONFIRMAR versão]**. CI fixa Node 22.
- HKDF no WebCrypto exige `salt` mesmo vazio (`new Uint8Array(0)`).

**Ações humanas:** nenhuma.

---

## Fase 3 — Contas, convite e sessão

**Objetivo:** owner inicial por CLI, convite, aceite com geração de chaves e kit de recuperação no browser, prelogin/login/logout, sessão por cookie, rate limit/lockout, troca de senha-mestra.
**Requisitos:** RF-I01, RF-I02, RF-I08 (expiração/logout), RF-I10 (sem TOTP), RF-U01 (até `aceito`), RF-P01, RF-A01 (eventos `auth.*`, `convite.*`, `org.criada`), RNF-01, RNF-03, RNF-15c.
**Repos:** BE + FE. **Dependências:** 1, 2.

**Escopo BE**
- `migracoes/0002_contas.sql`: `usuarios`, `convites`, `sessoes`, `limites` (§4).
- `app/cli.py` `criar-org --nome --email`: cria org + usuário `convidado` papel `owner` + convite; imprime JSON `{"org_id","usuario_id","token"}`; segunda execução → exit 1 `org_ja_existe`. Evento `org.criada`.
- `app/seguranca.py`: hash de authHash (D5/D19), tokens (256 bits, SHA-256), dependência `sessao_atual` (expiração ociosa/absoluta, `X-Cofre` em não-GET, atualiza `ultimo_uso`), checagem de papel.
- `app/limites.py`: regra RNF-01 com tabela `limites`.
- `app/rotas/auth.py`: `prelogin`, `convites/consultar`, `convites/aceitar`, `login`, `logout`, `eu`, `eu/senha` (§5.1/5.2). Aceite do convite do owner do bootstrap (único usuário da org) → `ativo` direto com `fingerprint_confirmado` = o próprio; demais → `aceito`.
- `app/rotas/convites.py`: `POST /convites` (owner/admin), `DELETE /convites/{id}` — necessário aqui para testar o fluxo com 2 usuários.
- Validação de entrada: regex de envelope (§3.1), base64url de 32 B (`auth_hash`, `recup_auth`, `chave_publica`), `kdf` exatamente `{"tipo":"argon2id","m":65536,"t":3,"p":1}`.
- Testes: `tests/test_convites.py`, `tests/test_login.py`, `tests/test_sessao.py` (relógio injetável em `app/relogio.py`), `tests/test_limites.py`, `tests/test_troca_senha.py`, `tests/test_cli.py`.

**Escopo FE**
- `public/js/api.js` (fetch com `credentials:'same-origin'`, `X-Cofre: 1` em não-GET, mapeia `{"erro"}` para mensagens), `public/js/estado.js` (chaves só em memória; `limpar()`), `public/js/telas/convite.js` (lê `#/convite/<token>`, consulta, define senha com `validarSenhaMestra` + confirmação, gera chaves, **mostra o kit** com checkbox "guardei" obrigatório e botão de download `.txt` via `Blob`, envia aceite), `public/js/telas/login.js` (prelogin → KDF com aviso "Derivando chave…" → login → decifra userKey e privada), `public/js/telas/conta.js` (troca de senha, logout), roteador por `location.hash`.
- `test/e2e/contas.test.mjs`: cliente Node que usa `public/js/cripto.js` e reproduz o fluxo do browser (gerencia o cookie à mão).
- `scripts/e2e-backend.sh` e job `e2e` no CI do FE: faz checkout de `Matheus-Allvz/Cofre-AES@empresarial`, sobe com compose, roda [FE-E2E].

**Fora de escopo:** MFA, políticas, confirmação de membro por admin, coleções.

**Definição de Pronto**
1. [BE-TEST] e [FE-UNIT] passam; cobertura BE ≥ 80%.
2. [FE-E2E] passa com o teste `owner aceita convite do bootstrap, faz login e decifra a própria chave privada` e `owner convida member; member aceita; member faz login; estado = aceito`.
3. Testes BE existem e passam para cada critério de RF-I01, RF-I02, RF-I08 e RNF-01 em `REQUISITOS.md` (nomes dos testes listados no PR, um por critério).
4. Teste BE: e-mail inexistente e senha errada de e-mail existente devolvem **corpo e status idênticos** (`401 {"erro":"credenciais_invalidas"}`), e a função de verificação Argon2 é chamada 1× em ambos (spy).
5. Teste BE: `prelogin` de e-mail inexistente devolve o mesmo `sal` em duas chamadas e `sal` diferente para outro e-mail; formato idêntico ao de e-mail existente.
6. Teste BE: `POST` autenticado sem `X-Cofre` → 403 `csrf`. Cookie emitido tem `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api`.
7. Teste BE: após `POST /eu/senha`, a sessão usada continua válida, outra sessão do mesmo usuário → 401, login com authHash antigo → 401.
8. Verificação de segredo em claro: teste BE após o aceite consulta `usuarios` e confirma que `auth_hash` começa com `$argon2id$` e que nenhuma coluna contém o `auth_hash` enviado nem o `recup_auth` enviado (bytes ou base64url).
9. `SELECT tipo, resultado FROM eventos` após o fluxo do item 2 contém `org.criada`, `convite.criado`, `convite.aceito` (×2), `auth.login` ok, e um `auth.login` falha após senha errada; nenhum `meta` contém e-mail em claro de tentativa falha.
10. Token de convite não aparece em nenhum log da API durante [FE-E2E] (`docker compose -p cofre-e2e logs api | grep -c <token>` → 0).
11. M (roteiro no PR com prints): aceitar convite no browser, kit exibido e baixado, login, logout; DevTools → Application: `localStorage`, `sessionStorage`, IndexedDB vazios; cookie `sessao` HttpOnly.

**Checklist do validador**
- Ler `seguranca.py`: comparação de hash em tempo constante (`argon2` verify / `hmac.compare_digest`), token de sessão por `secrets.token_bytes(32)`, só o hash persistido.
- Negativo: reutilizar token de convite → 410; aceitar com `kdf` diferente do padrão → 422; enviar `chave_usuario_cif` fora do regex → 422; 11 logins errados → 429 mesmo com senha correta na 12ª; requisição com cookie de sessão expirada (alterar `ultimo_uso` no banco) → 401.
- Negativo: tentar `POST /api/v1/convites` como member → 403.
- Conferir que `limites` usa `sha256(email)` e não e-mail em claro.
- Conferir que o JS descarta `masterKey`/`kek` após uso e que nada é gravado em storage (`grep -rn "localStorage\|sessionStorage\|indexedDB" public/js` → vazio).

**Riscos/armadilhas**
- `TestClient` com `base_url` http não reenvia cookie `Secure`: usar `https://testserver`.
- `uvicorn --proxy-headers` + rate limit por IP: em teste, injetar IP via header `X-Forwarded-For` só se o cliente for confiável; não confiar em XFF vindo de fora do proxy.
- KDF de 64 MiB por login no servidor (argon2 do authHash) + cliente: E2E pode ficar lento; aceitável. Não reduzir parâmetros em produção para acelerar teste — use variável de teste explícita só no servidor (`COFRE_ARGON2_TESTE=1`, recusada se `COOKIE_SECURE=true`).

**Ações humanas:** nenhuma.

---

## Fase 4 — MFA, políticas e recuperação

**Objetivo:** TOTP com códigos de recuperação, política da org (MFA obrigatório, inatividade), sessões ativas, auto-lock, recuperação por kit.
**Requisitos:** RF-I03, RF-I04/RF-P02, RF-I08 (listar/encerrar), RF-I09, RF-I10 (exigir TOTP), RF-U06, RF-P03, RF-P07.
**Repos:** BE + FE. **Dependências:** 3.

**Escopo BE**
- `migracoes/0003_mfa_politicas.sql`: colunas TOTP em `usuarios`, `codigos_mfa`, `recuperacoes`, `politicas` (linha criada junto com a org; migration cria para org existente).
- `app/totp.py` (RFC 6238 com `hmac`/`struct`, janela ±1, retorna o passo usado), `app/cifra_servidor.py` (AES-GCM com subchave `totp`).
- Rotas §5.2 (`eu/mfa/*`, `eu/sessoes`, `eu/eventos`), §5.3 (`GET /org`, `PUT /org/politica`), §5.1 (`recuperar/iniciar|concluir`). Login passa a exigir TOTP/código quando MFA ativo; `mfa_pendente` quando política exige e usuário não tem MFA. `eu/senha` exige TOTP se MFA ativo.
- Testes por critério de RF-I03, I04, I08, U06, P03, P07.

**Escopo FE**
- Atualizar `test/e2e/contas.test.mjs` da Fase 3: com a política padrão (MFA obrigatório) o fluxo passa pela configuração de TOTP.
- Telas: configurar MFA (segredo base32 + URI `otpauth://` copiável, campo de código, exibição única dos 10 códigos com download), login com campo TOTP/código de recuperação, sessões ativas com "encerrar", política (owner/admin), recuperação por kit (gera novo kit e exibe).
- `public/js/inatividade.js`: temporizador com relógio injetável; em `inatividade_min` sem `pointerdown/keydown` chama `bloquear()` (= `estado.limpar()` + `POST /logout` + tela de login); também em `pagehide`.
- `test/unit/inatividade.test.mjs`; `test/e2e/mfa_recuperacao.test.mjs` (gera TOTP no Node com o segredo recebido).

**Definição de Pronto**
1. [BE-TEST], [FE-UNIT], [FE-E2E] passam.
2. Teste BE com os vetores SHA-1 do Apêndice B do RFC 6238 (T=59, 1111111109, 1111111111, 1234567890, 2000000000) truncados a 6 dígitos → passa.
3. Testes BE: código TOTP reutilizado no mesmo passo → 401 `mfa_invalido`; código de recuperação usado 2× → 401 na segunda; `totp_segredo_cif` casa com regex `v1.` e não contém o base32.
4. Teste BE: org com `mfa_obrigatorio=true`, usuário sem MFA faz login → 200 com `mfa_pendente:true`; `GET /api/v1/org` → 403 `mfa_configuracao_requerida`; após `mfa/confirmar` → 200 na mesma sessão.
5. Teste BE: `PUT /org/politica` com `inatividade_min` 4 e 61 → 422; como member → 403; como admin → 200 e evento `politica.alterada` com `meta.antes` e `meta.depois`.
6. Teste BE: sessão ociosa por `inatividade_min`+1 min (relógio simulado) → 401.
7. E2E: recuperação com kit → login com a nova senha funciona e a chave privada decifra com a userKey re-envelopada; senha antiga → 401; kit antigo → 401 em `recuperar/iniciar`; sessões anteriores → 401.
8. Teste Node: `inatividade` com relógio falso chama `bloquear` exatamente uma vez após o prazo e zero vezes se houver interação antes.
9. M (roteiro com prints): ativar MFA com app autenticador real; login exige código; com `inatividade_min=5`, após 5 min a tela volta ao login e a aba Network mostra `POST /api/v1/logout`.

**Checklist do validador**
- Negativo: `DELETE /eu/mfa` com política obrigatória → 403 `politica_mfa`; `recuperar/concluir` com token expirado (alterar `expira_em`) → 401; `recuperar/iniciar` 11× errado → 429.
- Conferir que `recuperar/iniciar` só devolve `chave_usuario_recup_cif` após `recup_auth` **e** segundo fator válidos.
- Conferir que os 10 códigos são gerados com `secrets` e guardados só como HMAC.
- Conferir que nenhum log contém código TOTP, segredo base32 ou código de recuperação (rodar E2E e `grep` nos logs com os valores gerados).

**Riscos/armadilhas**
- Bootstrap: owner nasce sem MFA e a política padrão exige MFA → primeira sessão é `mfa_pendente`; fluxo de aceite deve levar direto à configuração.
- Relógio do container vs. app autenticador: janela ±1 cobre ±30 s.

**Ações humanas:** nenhuma.

---

## Fase 5 — Membros da organização

**Objetivo:** gestão de usuários pelo admin: listar, convidar com papel, confirmar com fingerprint, suspender/reativar, remover (anonimizando), trocar papel admin↔member.
**Requisitos:** RF-O02 (parcial), RF-U01 (`aceito→ativo`), RF-U02, RNF-15d, RF-A01 (`membro.*`).
**Repos:** BE + FE. **Dependências:** 4.

**Escopo BE**
- Rotas §5.3 exceto promoção a owner (Fase 7) e o relatório/rotação da remoção (Fase 7; aqui remover só revoga sessões, anonimiza e muda estado).
- Regras: `confirmar` recalcula o fingerprint de `chave_publica` e compara com o enviado; suspender/remover revogam todas as sessões; último owner protegido; admin não altera owner; ninguém suspende, remove ou muda o papel de si mesmo (409 `auto_acao`).
- Testes: máquina de estados completa (tabela de transições válidas/ inválidas), matriz papel × rota desta fase.

**Escopo FE**
- Tela "Pessoas" (owner/admin): lista com estado, convidar (mostra link uma vez + aviso "entregue por canal seguro"), confirmar (mostra o fingerprint calculado localmente da chave pública recebida e exige digitar/confirmar que conferiu com o usuário por voz/chat), suspender/reativar/remover com confirmação.
- Tela "Minha conta" passa a mostrar o próprio fingerprint (para o usuário ditar ao admin).

**Definição de Pronto**
1. [BE-TEST], [FE-UNIT], [FE-E2E] passam.
2. Teste BE parametrizado com todas as transições de estado: válidas → 200/204; inválidas → 409 (ex.: confirmar `convidado`, reativar `ativo`, suspender `removido`).
3. Teste BE: `confirmar` com fingerprint divergente → 422 `fingerprint_divergente`; correto → `ativo`, `confirmado_por` preenchido, evento `membro.confirmado`.
4. Teste BE: após suspender, cookie do suspenso → 401; login dele com credencial correta → 403 `conta_suspensa`.
5. Teste BE: remover → `GET /membros` não contém o e-mail original; `SELECT count(*) FROM eventos WHERE ator_id=<id>` igual ao de antes da remoção; e-mail fica `removido-<id>@invalido`.
6. Teste BE: remover/suspender/rebaixar o único owner → 409 `ultimo_owner`; admin tentando alterar papel de owner → 403.
7. Teste BE parametrizado papel × rota (owner/admin/member) para todas as rotas §5.3 implementadas.
8. E2E: owner convida, member aceita, owner confirma com o fingerprint calculado pelo cliente do owner a partir de `GET /membros` → member `ativo`.
9. M: roteiro com prints da tela Pessoas, incluindo confirmação com fingerprint.

**Checklist do validador**
- Negativo: member chama `POST /membros/{id}/suspender` → 403; admin tenta suspender a si mesmo → 409 `auto_acao`; admin suspende outro admin → 200.
- Conferir que o fingerprint mostrado na UI é calculado no cliente a partir da chave pública, não lido de um campo pronto do servidor.
- Conferir que a remoção não apaga linhas de `eventos` nem tenta `UPDATE` nelas.

**Riscos/armadilhas**
- Anonimizar o e-mail libera o mesmo e-mail para novo convite (reconvite após perda de kit) — testar que funciona.

**Ações humanas:** nenhuma.

---

## Fase 6 — Coleções e itens

**Objetivo:** o cofre em si: coleções cifradas, itens com meta/segredo separados, revelar auditado, histórico, lixeira, gerador, busca local, clipboard.
**Requisitos:** RF-O03/O04 (níveis), RF-O05, RF-T01, RF-T06, RF-T07, RF-T08, RF-T10, RF-T11, RF-A02, RF-A03, RNF-C01.
**Repos:** BE + FE. **Dependências:** 5.

**Escopo BE**
- `migracoes/0004_colecoes_itens.sql`: `colecoes`, `colecao_membros`, `itens`, `item_versoes` (§4).
- Rotas §5.4 exceto `membros` de coleção (POST/PUT/DELETE) e `rotacionar` (Fase 7). `POST /colecoes` valida envelopes do criador e de todos os owners ativos.
- `sync` com purga preguiçosa da lixeira (> 30 dias) e evento `item.purgado`.
- Revelação e versão revelada gravam evento na mesma transação (RF-A02).
- Limite de 64 KiB por blob (422 `blob_grande`).
- Testes: níveis de permissão × operação (tabela), 404 para coleção sem envelope, histórico (3 e 12 edições), lixeira com relógio simulado, RF-A02 com trigger de falha.

**Escopo FE**
- `public/js/cofre.js`: após login, `sync` → abre envelopes x1 com a privada → decifra nomes e metas → índice em memória. Criar coleção (envelopes p/ si e owners vindos de `GET /membros`). CRUD de itens dos 3 tipos com AAD da §3.3 (`versao` futura). Revelar/copiar chamam a rota auditada; copiar chama também `/copiado` e agenda limpeza do clipboard em 30 s (só limpa se `readText` não estiver disponível ou o conteúdo ainda for o copiado; se `clipboard-read` for negado, sobrescreve com string vazia). Histórico com "restaurar" (recifra como nova versão). Lixeira.
- `public/js/gerador.js` (senha e passphrase com rejeição de viés; lista de palavras pt-BR vendorizada com fonte/licença em `vendor/README.md`).
- `public/js/busca.js` (filtro local por título/usuário/URLs, normalizado sem acento).
- Tooltip de `ver_sem_revelar` com o texto de RF-O05; `docs/seguranca.md` no BE com as limitações (RF-O05).
- Testes: `test/unit/gerador.test.mjs`, `test/unit/busca.test.mjs`, `test/unit/itens_aad.test.mjs` (AAD de item com versão errada não decifra), `test/e2e/cofre.test.mjs`.

**Definição de Pronto**
1. [BE-TEST], [FE-UNIT], [FE-E2E] passam.
2. Teste BE: resposta de `sync` e de `lixeira` serializada não contém a chave `segredo_cif` (assert sobre o JSON bruto).
3. Teste BE (RF-A02): instala trigger que faz `RAISE` em `INSERT` de `eventos`; `GET /itens/{id}/segredo` → 500, corpo sem `segredo_cif`; sem trigger → 200 e exatamente 1 evento `item.revelado`.
4. Teste BE: `ver_sem_revelar` → `GET .../segredo` 403, `sync` 200; `ver` → `POST .../itens` 403; `editar` → `DELETE .../definitivo` 403; usuário sem envelope → 404 em toda rota da coleção.
5. Teste BE: `PUT` sem `If-Match` → 428; com versão velha → 409 `conflito_versao`; 12 edições → `count(*) FROM item_versoes = 10`.
6. Teste BE: `POST /colecoes` sem envelope de um owner ativo → 422 `envelopes_incompletos`; com envelope para usuário `aceito` → 422 `destinatario_invalido`.
7. Teste BE: item com `excluido_em = now() - 31 days` some após `sync` e gera `item.purgado`; com 29 dias permanece na lixeira.
8. E2E (RNF-C01): owner cria coleção e um item de cada tipo com sentinelas `SENT-SENHA-<rand>`, `SENT-TITULO-<rand>`, senha-mestra `SENT-MESTRA-<rand>`; `docker compose -p cofre-e2e exec -T db pg_dump -U cofre_dono cofre` e `docker compose -p cofre-e2e logs api` não contêm nenhum sentinela nem seu base64/base64url.
9. E2E: adulterar `meta_cif` de um item direto no banco (trocar 1 caractere do ct) → cliente reporta "item adulterado" para aquele item e continua listando os outros; mover `segredo_cif` de um item para outro no banco → decifragem falha (AAD).
10. E2E: restaurar a versão 1 após 2 edições → senha decifrada = senha original; `versao` atual = 4.
11. Teste Node do gerador: 10 000 senhas de 20 chars só com o alfabeto pedido; cada classe exigida presente; qui-quadrado sobre 100 000 caracteres abaixo do valor crítico p=0,001.
12. M: roteiro com prints: criar coleção, item, revelar, copiar, aguardar 30 s, colar → vazio; buscar; excluir; restaurar da lixeira; histórico.

**Checklist do validador**
- Conferir em `cofre.js` que o AAD é montado com ids locais (o `id` do item é gerado pelo cliente com `crypto.randomUUID()`), nunca concatenando string vinda do servidor sem validação de UUID.
- Negativo: usuário A cria item; usuário B (sem envelope) tenta `GET /itens/{id}/segredo`, `PUT`, `DELETE`, `versoes` → 404 em todos.
- Negativo: `POST` de item com `chave_ver` diferente da atual → 409; `meta_cif` com 70 KiB → 422.
- Conferir que `segredo_cif` revelado não fica em variável global após fechar o item (descartado ao fechar/ bloquear).
- Conferir a lista de palavras do gerador: tamanho ≥ 2048, sem duplicatas (teste).

**Riscos/armadilhas**
- `navigator.clipboard.readText` pede permissão e nem sempre existe; a limpeza é melhor esforço (documentar).
- Versão no AAD: o cliente cifra com `versao+1` antes de saber se o `PUT` vence a corrida; em 409, re-sincronizar e recifrar.
- `sync` grande: sem paginação no MVP (≤ alguns milhares de itens). Anotar limite no código (`ponytail:`).

**Ações humanas:** nenhuma.

---

## Fase 7 — Compartilhamento, revogação e offboarding

**Objetivo:** dar/alterar/remover acesso a coleções, rotação atômica da collectionKey, painel de senhas a rotacionar, relatório de offboarding, promoção/transferência de owner.
**Requisitos:** RF-O03/O04 (gestão de membros), RF-U03, RF-U04, RF-U05, RF-A01 (`colecao.*`, `membro.papel_alterado`).
**Repos:** BE + FE. **Dependências:** 6.

**Escopo BE**
- Rotas `colecoes/{id}/membros` (POST/PUT/DELETE) e `colecoes/{id}/rotacionar` (§5.4); `PUT /membros/{id}/papel` com promoção a owner; `DELETE /membros/{id}` completa (relatório + marcações).
- `rotacionar`: numa transação, `SELECT ... FOR UPDATE` na coleção; confere `chave_ver_atual`; conjunto de envelopes == membros atuais; conjunto de itens == todos os itens da coleção (inclusive lixeira) com `versao` igual à atual; conjunto de versões == todas as linhas de `item_versoes` desses itens; grava tudo com `chave_ver+1`; `rotacao_pendente=false`; evento `colecao.rotacionada` com contagens.
- Testes por critério de RF-U03/U04/U05 e cada código de erro de `rotacionar`.

**Escopo FE**
- Tela da coleção (gerenciar): membros, adicionar (escolhe membro **ativo**, mostra fingerprint confirmado; cria envelope x1), alterar permissão, remover (aviso de rotação).
- Banner "rotação pendente" para quem tem `gerenciar`: botão executa rotação (gera chave nova, recifra nome/itens/versões, envelopa para membros atuais) e trata 409 re-sincronizando.
- Painel "Senhas a trocar" (itens com `rotacao_senha_pendente`); editar com senha nova envia `senha_trocada=true`.
- Pessoas: remover mostra o relatório devolvido; promover a owner gera envelopes de todas as coleções.
- `test/e2e/compartilhar.test.mjs`.

**Definição de Pronto**
1. [BE-TEST], [FE-UNIT], [FE-E2E] passam.
2. E2E: owner compartilha coleção com member (`ver`); member lê a senha; owner remove o member; coleção `rotacao_pendente`; owner rotaciona; **o member, usando a collectionKey antiga que guardou no teste, não decifra o `meta_cif` nem o `segredo_cif` novos** (AES-GCM falha) e recebe 404 nas rotas da coleção.
3. Teste BE: `rotacionar` faltando 1 item da lixeira → 422 `rotacao_incompleta` e `chave_ver`, envelopes e blobs inalterados (comparar snapshot das linhas antes/depois); faltando 1 versão → 422; sobrando envelope de não-membro → 422; `chave_ver_atual` velha → 409; item com `versao` divergente → 409 `conflito_versao`.
4. Teste BE: dois `rotacionar` concorrentes (threads) → exatamente um 200 e um 409.
5. Teste BE: `DELETE /membros/{id}` devolve relatório com exatamente os itens (ids) das coleções que ele alcançava, inclusive lixeira; todas essas coleções ficam `rotacao_pendente`; itens `rotacao_senha_pendente`.
6. Teste BE: `PUT /itens/{id}` com `senha_trocada=true` limpa `rotacao_senha_pendente`; com `false` mantém.
7. Teste BE: promover a owner sem envelope de alguma coleção → 422 `envelopes_incompletos`; com todos → 200 e o novo owner recebe `gerenciar` em todas; rebaixar o antigo depois → 200; rebaixar o último → 409.
8. Teste BE: `POST /colecoes/{id}/membros` para usuário `aceito`/`suspenso` → 422 `destinatario_invalido`; tirar `gerenciar` de owner → 409 `owner_gerencia`; teste confirma que toda coleção mantém envelope `gerenciar` de todos os owners ativos após qualquer operação desta fase (invariante D13).
9. M: roteiro com prints (compartilhar, remover, banner, rotacionar, painel de senhas a trocar).

**Checklist do validador**
- Ler a transação de `rotacionar`: tudo em um `BEGIN…COMMIT`, lock na coleção, nenhuma escrita antes de todas as validações.
- Negativo: member com `editar` chama `rotacionar` e `membros` → 403.
- Negativo: envelope x1 cujo AAD usa outro `usuario_dest` → o destinatário não abre (teste Node).
- Conferir que a UI de adicionar membro só oferece usuários `ativo` com fingerprint confirmado.

**Riscos/armadilhas**
- Payload de rotação grande (itens × 10 versões): definir limite de corpo da requisição (ex. 20 MiB) e documentar.
- Corrida: edição de item durante rotação → 409 e o cliente refaz.

**Ações humanas:** nenhuma.

---

## Fase 8 — Auditoria, LGPD e backup/restauração

**Objetivo:** consulta de auditoria, matriz de autorização completa, teste de sentinela em logs, documentação de segurança/LGPD, scripts de backup e restauração testados localmente.
**Requisitos:** RF-A01 (completo), RF-A06, RF-O02 (matriz completa), RNF-05 (scripts), RNF-06, RNF-07 (sentinela completo), RNF-15a/b/e, RNF-C01 (reforço).
**Repos:** BE + FE. **Dependências:** 7.

**Escopo BE**
- `GET /api/v1/auditoria` (§5.5) com índice `(org_id, id desc)` e filtros.
- `tests/test_matriz_autorizacao.py`: uma tabela (rota, método, papel/permissão) → status esperado cobrindo **todas** as rotas de `/api/v1`; teste extra que falha se existir rota no app não listada na tabela.
- `tests/test_eventos_completos.py`: cada tipo de §5.6 é gerado por alguma ação (falha se surgir tipo sem teste).
- `tests/test_sentinela_logs.py`: percorre todas as rotas com valores sentinela em todos os campos sensíveis; sentinela ausente de logs.
- `scripts/backup.sh` (`docker compose exec -T db pg_dump -Fc` | `age -r $BACKUP_AGE_RECIPIENT` > `backups/cofre-<UTC>.dump.age`; retenção 7 diários + 4 semanais (domingo) + 3 mensais (dia 1); opcional `rclone copy` se `BACKUP_RCLONE_DEST` definido; escreve `backups/ultimo_ok`), `scripts/restaurar.sh <arquivo> --verifica` (sobe Postgres temporário em container próprio, `age -d -i $AGE_IDENTITY`, `pg_restore`, confere `schema_migracoes` = migrations do repo e contagens de linhas ≥ manifesto; exit ≠ 0 em qualquer falha; derruba o temporário).
- `docs/seguranca.md` (modelo de ameaças, limitações, matriz requisito→controle), `docs/ropa.md`, `docs/incidente.md` (prazo **[CONFIRMAR na Resolução CD/ANPD nº 15/2024]**), `docs/operacao.md` (backup, restauração, bootstrap, rotação de `COFRE_SEGREDO` — com aviso de que trocar o pepper invalida todos os logins), README referenciando os quatro.
- Job opcional no CI: `backup→restaurar --verifica` com chave `age` gerada no próprio job.

**Escopo FE**
- Tela "Auditoria" (owner/admin): filtros, paginação por cursor, tabela via `dom.js`. "Minha conta" mostra os próprios eventos de login.

**Definição de Pronto**
1. [BE-TEST], [FE-UNIT], [FE-E2E] passam; cobertura BE ≥ 80%.
2. `test_matriz_autorizacao.py` cobre 100% das rotas (o teste de completude passa) e todas as combinações passam.
3. `test_eventos_completos.py` passa para todos os tipos de §5.6.
4. Teste: member → `GET /auditoria` 403; filtro `tipo=item.revelado&ator_id=X` devolve só esses; paginar com `limite=2` por 3 páginas não repete nem pula ids.
5. Com [BE-UP] e dados do E2E: `AGE` keypair temporário → `scripts/backup.sh` gera `.age`; `grep -c SENT- backups/*.age` → 0; `scripts/restaurar.sh backups/<arquivo> --verifica` → exit 0; truncar o arquivo pela metade → exit ≠ 0.
6. Retenção: teste do script (bats não é exigido; pode ser `tests/test_backup_retencao.py` chamando a função de seleção com datas falsas) mantém exatamente 7+4+3 arquivos esperados.
7. `docs/*.md` existem, README os referencia, `docs/seguranca.md` contém as limitações de RF-O05 e o risco "servidor serve o JS".
8. M: roteiro com prints da tela de auditoria filtrando um `item.revelado`.

**Checklist do validador**
- Rodar `restaurar.sh --verifica` ele mesmo, com backup gerado por ele.
- Conferir que a chave privada `age` nunca é lida pelo `backup.sh` (só o recipient público).
- Negativo: adicionar rota fictícia no app local → teste de completude da matriz falha.
- Conferir que a consulta de auditoria não permite SQL dinâmico com filtro do usuário (parâmetros sempre bind).

**Riscos/armadilhas**
- `age` precisa estar instalado no host (local e VPS); no CI, `apt-get install age`.
- `pg_dump` por `docker compose exec` depende do nome do projeto compose; parametrizar.

**Ações humanas:** decidir destino externo do backup (ver Fase 9).

---

## Fase 9 — Implantação na VPS

**Objetivo:** publicar a branch `empresarial` em diretórios, portas e domínio novos, sem tocar na versão acadêmica, com deploy automático a cada push na `empresarial` e backup diário.
**Requisitos:** RNF-02 (TLS/HSTS reais), RNF-05 (cron + cópia externa), RNF-14 (verificação no host), RNF-04 (monitor, se Uptime Kuma existir).
**Repos:** BE + FE. **Dependências:** 8 e **todas** as ações humanas abaixo.

**Decisões do usuário (registradas na Fase 7; valem sobre o texto abaixo)**
- Domínio: `secrets.matheus-alves.dev` (substitui a proposta `cofre-empresa.matheus-alves.dev`), com o **proxy da Cloudflare** ligado (registro proxied, não "DNS only").
- Cadeia real: Cloudflare → `<IP_DA_VPS>:443` (sslh) → Caddy `:4443` → `127.0.0.1:8097` (front) / `127.0.0.1:8098` (API). O Caddy vê todo cliente como `127.0.0.1`.
- IP do cliente para rate limit e eventos: `CF-Connecting-IP`, aceito **só** quando a conexão vem do proxy local confiável (`127.0.0.1`); fora disso, ignorado. Tirar `--forwarded-allow-ips '*'`. Recomendado: **Authenticated Origin Pulls** no Caddy (só a Cloudflare fala com a origem). Teste: header forjado vindo de fora do proxy não muda o IP registrado.
- Backup externo: **Cloudflare R2**, bucket `secrets-backup`, `rclone` com remoto `r2`, sempre com `--s3-no-check-bucket`. Prefixos `diario/` (retenção 8 d), `semanal/` (35 d), `mensal/` (100 d); a expiração é feita por **regras de ciclo de vida do R2** — o script **nunca apaga** no R2. Guarda de cota: antes do upload, `rclone size r2:secrets-backup` + tamanho do arquivo novo; se passar de **9 GB** (90% do plano grátis de 10 GB), o script falha (exit ≠ 0) sem enviar. Isso substitui o item 8 abaixo ("backup só local" deixa de ser opção).
- MFA opcional por padrão (migração `0005`); a política da org continua podendo exigir.
- No host ainda **não** há `rclone` nem `age` (instalar é ação humana) e `systemctl reload caddy` exige `sudo` do usuário (não entra no deploy automático).
- Nada de IP real da VPS nem segredo no repositório (público): usar `<IP_DA_VPS>`; dados de infraestrutura ficam no `VPS_CONTEXTO.md` local.

**Pré-requisitos humanos (bloqueantes, nesta ordem)**
1. Restaurar acesso SSH à VPS <IP_DA_VPS> (hoje timeout): conferir firewall/allowlist do provedor, fail2ban, porta do sshd. Confirmar com `ssh deploy@<IP_DA_VPS> true`.
2. Rodar os comandos read-only da §8 do `VPS_CONTEXTO.md` e anexar a saída ao PR (portas livres, RAM/disco, versão do Caddy, existência do Uptime Kuma).
3. Domínio `secrets.matheus-alves.dev` (decidido): registro DNS **A** → `<IP_DA_VPS>` com proxy da Cloudflare ligado.
4. Confirmar portas livres **8097** (front) e **8098** (API) com `ss -tlnp` (trocar no compose se ocupadas).
5. No host, como `deploy`: `git clone -b empresarial https://github.com/Matheus-Allvz/Cofre-AES.git /home/deploy/cofre-empresa-api` e `git clone -b empresarial https://github.com/Matheus-Allvz/Cofre-AES-Frontend.git /home/deploy/cofre-empresa-front`.
6. Criar `/home/deploy/cofre-empresa-api/.env` (modo 600) com `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`, `COFRE_SEGREDO` gerados com `openssl rand -base64 32`, `COOKIE_SECURE=true`, `BACKUP_AGE_RECIPIENT`. Guardar cópia dos segredos fora da VPS (perder `COFRE_SEGREDO` = ninguém loga).
7. Instalar `age` no host (`sudo apt install age`); gerar o par `age` **fora da VPS**; colocar só a chave pública no `.env`.
8. Decidir e configurar o destino externo do backup (`rclone config` para S3/Backblaze/outra máquina) ou aceitar explicitamente "backup só local" como pendência registrada.
9. Adicionar no `/etc/caddy/Caddyfile` (sudo), validar e recarregar:
   ```
   secrets.matheus-alves.dev:4443 {
     encode gzip zstd
     handle /api/* { reverse_proxy 127.0.0.1:8098 }
     handle { reverse_proxy 127.0.0.1:8097 }
   }
   ```
   `sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy`.
10. GitHub Actions: confirmar que os secrets `CI_DEPLOY_SSH_HOST/USER/KEY` (BE) e `FRONT_DEPLOY_SSH_HOST/USER/KEY` (FE) existem e funcionam (são reaproveitados; workflows novos só rodam em push na `empresarial`).
11. Após o primeiro deploy: `docker compose exec api python -m app.cli criar-org --nome "<Empresa>" --email <owner>` e abrir `https://<dominio>/#/convite/<token>`.

**Escopo BE**
- `deploy-empresarial.sh`: `set -euo pipefail`; `git fetch origin empresarial && git reset --hard origin/empresarial`; `docker compose build`; `docker compose up -d --wait`; `curl -fsS --retry 10 --retry-delay 2 http://127.0.0.1:8098/api/pronto` (falha o deploy se não 200).
- `.github/workflows/deploy-empresarial.yml`: `on: push: branches: [empresarial]`, `needs` o job de testes (reusar `ci.yml` via `workflow_call` ou repetir o job), `appleboy/ssh-action` fixado por versão, `script: /home/deploy/cofre-empresa-api/deploy-empresarial.sh`.
- `docker-compose.yml`: `mem_limit` (db 512m, api 384m), `restart: unless-stopped`, nomes de container `cofre-empresa-db|api|migrar`, nome de projeto `cofre-empresa` (não colide com `cofre-aes`).
- `scripts/instalar-cron.sh`: adiciona (idempotente) `30 3 * * * /home/deploy/cofre-empresa-api/scripts/backup.sh >> .../backups/backup.log 2>&1`.
**Escopo FE**
- `deploy-empresarial.sh` e `deploy-empresarial.yml` equivalentes (`127.0.0.1:8097`, container `cofre-empresa-front`).
- `API_UPSTREAM` irrelevante em produção (Caddy roteia `/api`); documentar no README.

**Fora de escopo:** qualquer alteração em `/home/deploy/cofre-aes*`, no bloco Caddy de `vault.`/`keep.`/`cofre.`, ou na `main`.

**Definição de Pronto**
1. Push do merge na `empresarial` dispara os dois workflows de deploy; ambos verdes; o de deploy só roda após os testes passarem.
2. `curl -fsS https://<dominio>/api/saude` → `{"status":"ok"}`; `curl -fsS https://<dominio>/api/pronto` → 200.
3. `curl -sI https://<dominio>/` contém todos os headers de §6 (incluindo HSTS); certificado válido (`curl` sem `-k`).
4. Versão acadêmica intacta: `curl -s -o /dev/null -w "%{http_code}" https://vault.matheus-alves.dev/cofres/00000000-0000-0000-0000-000000000000/abrir -X POST -H "X-Senha-Mestra: x"` mantém o mesmo código de antes do deploy (registrar antes/depois); `docker ps` mostra `cofre-aes` e `cofre-aes-frontend` com o mesmo `CreatedAt` de antes.
5. No host: `ss -tlnp | grep -E "8097|8098"` só em `127.0.0.1`; `docker compose -p cofre-empresa port db 5432` sem mapeamento; `docker compose exec api id -u` ≠ 0.
6. Fluxo real em produção (roteiro com prints, executado pelo usuário ou validador com conta de teste): bootstrap → aceite → MFA → coleção → item → revelar → auditoria mostra o evento.
7. `crontab -l` contém a linha do backup; executar `scripts/backup.sh` manualmente gera `.age` e (se configurado) cópia externa; `scripts/restaurar.sh <arquivo> --verifica` no host → exit 0.
8. Uptime Kuma (se existir): monitor HTTP para `/api/pronto` criado (print).
9. `README.md` dos dois repos tem a seção "Produção (empresarial)" com domínio, diretórios, portas, como fazer deploy e rollback (`git reset --hard <sha>` + `deploy-empresarial.sh`).

**Checklist do validador**
- Reproduzir 2, 3, 4 e 5 por conta própria.
- Negativo: `curl https://<dominio>/api/v1/sync` sem cookie → 401; `curl -X POST https://<dominio>/api/v1/logout -H "Cookie: sessao=x"` sem `X-Cofre` → 403/401; tentar conexão externa às portas 8097/8098/5432 (`nc -vz <IP_DA_VPS> 8098`) → recusada.
- Conferir que o workflow da `main` não mudou e que nenhum commit novo foi para a `main` (`git log origin/main -1` igual ao de antes).
- Conferir que o `.env` da VPS tem modo 600 e não está versionado (`git status --ignored` no host).

**Riscos/armadilhas**
- SSH indisponível bloqueia toda a fase; não tentar contornar.
- `docker compose up --wait` exige healthcheck em todos os serviços com `restart`; `migrar` é one-shot (sem healthcheck).
- Memória da VPS (8 GB, stack de observabilidade): conferir `free -h` antes; Argon2 de 64 MiB por login no servidor + cliente.
- Caddy: confirmar que `handle /api/*` não reescreve o path (a API espera `/api/...`).

**Ações humanas:** itens 1–11 acima.
