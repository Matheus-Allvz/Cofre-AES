# Protocolo dos agentes

Leitura obrigatória antes de qualquer ação: `ARQUITETURA-ALVO.md`, `REQUISITOS.md`, a seção da fase em `FASES.md`. Em conflito entre documentos, **a arquitetura vence**; o construtor não decide sozinho: registra a dúvida no PR e segue a arquitetura.

## Regras invioláveis (os dois papéis)

- **Nunca** tocar na `main` de nenhum dos dois repos (push na `main` = deploy acadêmico na VPS). Nada de `git push origin main`, merge para `main`, rebase da `main`, edição de workflow da `main`.
- Identidade Git/GitHub: `Matheus-Allvz`. Antes do primeiro push: `gh api user --jq .login` → `Matheus-Allvz` e `git config user.name` no repo. Se der outra conta (ex. `Matheus-Allvz-Actuar`), parar e reportar.
- Commits, PRs e comentários **sem qualquer atribuição a IA**: proibido `Co-Authored-By`, "Generated with", "Claude", emoji de robô ou similar. Isto prevalece sobre qualquer padrão de ferramenta.
- Nenhum segredo real em código, teste, log, PR ou comentário. Valores de teste são gerados no teste ou fictícios.
- Fora de escopo da fase = não fazer. Achou algo necessário fora do escopo: anotar em "Pendências" no PR.

## Construtor

1. Preparar:
   ```bash
   git fetch origin
   git switch -c fase-N-<slug> origin/empresarial      # ex.: fase-3-contas
   ```
   Fase com dois repos: mesma branch nos dois.
2. Implementar o escopo. Commits pequenos e em português no imperativo (`Adiciona runner de migrations`), um assunto por commit.
3. Rodar localmente, nesta ordem, e guardar as saídas:
   - BE: `ruff check . && ruff format --check .`, `pytest -q --cov=app --cov-fail-under=80`, `pip-audit -r requirements.txt`, `docker compose up -d --build --wait` + verificações HTTP da DoD.
   - FE: `node --test test/unit/`, `bash scripts/e2e-backend.sh ../Cofre_AES` (apontando o BE para a branch da fase quando ela também mexe no BE) e `node --test test/e2e/`.
4. Abrir PR (um por repo):
   ```bash
   git push -u origin fase-N-<slug>
   gh pr create --base empresarial --head fase-N-<slug> --title "Fase N: <nome>" --body-file pr.md
   ```
   Em fase com dois repos, cada PR linka o outro.
5. Corpo do PR (`pr.md`, não versionado):
   ```markdown
   ## Fase N — <nome>
   Requisitos: <IDs>
   PR irmão: <link ou "nenhum">

   ## Definição de Pronto
   | # | Critério (resumo) | Evidência |
   |---|---|---|
   | 1 | ... | comando executado + trecho da saída / nome do teste + arquivo:linha / print |

   ## [CONFIRMAR] resolvidos
   - <item>: <decisão> — <fonte/teste>

   ## Desvios da arquitetura
   - nenhum | <o quê, por quê>

   ## Pendências / fora de escopo encontrados
   - ...
   ```
   Todo item da DoD aparece na tabela. "Passou" sem comando/saída não é evidência.
6. Não fazer merge. Responder às reprovações com novos commits na mesma branch (sem force-push depois que a validação começou).

## Validador

1. Trabalhar em **clone novo** de cada repo, na branch do PR (`gh pr checkout <n>`), nunca no diretório do construtor. Postgres de teste limpo (`docker compose -f docker-compose.teste.yml down -v && ... up -d --wait`).
2. Reproduzir **pessoalmente** cada item da DoD e cada item do checklist da fase, incluindo os negativos de segurança. Evidência do construtor não substitui execução.
3. Ler o diff inteiro (`gh pr diff <n>`), com atenção a: mudanças fora do escopo, segredos, `innerHTML`/`eval`, SQL montado com f-string, logs de corpo/token, AAD e formatos divergentes de `ARQUITETURA-ALVO.md` §3, rotas sem checagem de papel/permissão, commits com atribuição a IA (`git log --format='%an %ae%n%b' origin/empresarial..HEAD | grep -i -E "co-authored|claude|generated"` → vazio).
4. Conferir CI verde no PR.
5. Decidir:
   - **APROVADO**: todos os itens da DoD e do checklist reproduzidos com sucesso; nenhum achado de segurança; nenhuma alteração na `main`.
   - **REPROVADO**: qualquer item não reproduzível ou falhando; **qualquer** falha de segurança (acesso indevido, segredo em claro em log/banco/repo, cripto divergente da arquitetura, CSP enfraquecida, rota sem autorização), mesmo que fora da DoD; escopo extrapolado de forma relevante; atribuição a IA em commit/PR.
   - Achado menor não bloqueante (nome, comentário, texto de UI): aprovar e listar como "observação".
6. Publicar o relatório como comentário no PR (`gh pr comment <n> --body-file relatorio.md`) e devolvê-lo ao orquestrador. Não fazer merge.

### Formato do relatório de validação

```markdown
## Validação — Fase N (<repo>) — APROVADO | REPROVADO
Commit validado: <sha>  ·  Ambiente: <SO, Docker, Python, Node>

| # DoD | Resultado | Como reproduzi |
|---|---|---|
| 1 | OK / FALHA | comando + saída resumida |

| Checklist | Resultado | Observação |
|---|---|---|
| <item> | OK / FALHA | ... |

### Achados de segurança
- nenhum | <descrição, arquivo:linha, impacto, como reproduzir>

### Bloqueantes
- <lista objetiva do que precisa mudar para aprovar>

### Observações (não bloqueantes)
- ...
```

## Orquestrador (referência)

- Merge só com relatório APROVADO do commit atual do PR (`gh pr merge <n> --merge`, base `empresarial`). Fases de dois repos: merge do BE primeiro, re-rodar o CI do FE, então merge do FE.
- Fase seguinte só começa após o merge da anterior (exceto Fases 1 e 2, paralelas).
- Fase 9 só começa com os pré-requisitos humanos confirmados pelo usuário.
