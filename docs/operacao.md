# Operação

Backup, restauração, bootstrap e segredos do servidor. Riscos e controles: [`seguranca.md`](seguranca.md).
A instalação na VPS (cron, `age`/`rclone` no host, Caddy) é a Fase 9; aqui está o que os scripts fazem
e como usá-los.

## Pré-requisitos no host

- Docker com o compose do projeto rodando (serviço `db`).
- [`age`](https://github.com/FiloSottile/age) (só para cifrar: o host recebe a chave **pública**).
- `rclone` com um remoto `r2` configurado pelo operador (credencial do bucket `secrets-backup` com
  leitura/escrita de objetos; não precisa listar nem criar buckets). O script não cria remoto nem
  lida com chaves.

## Chaves do backup

```bash
age-keygen -o cofre-backup.key      # numa máquina FORA da VPS; imprime "Public key: age1..."
```

- A chave privada (`cofre-backup.key`) fica fora do servidor (cofre pessoal + cópia offline). Sem
  ela nenhum backup é legível; perdê-la = perder os backups.
- No host só vai a pública: `BACKUP_AGE_RECIPIENT=age1...`. O `backup.sh` recusa uma chave privada
  nessa variável (sem imprimi-la) e nunca usa `age -d`.

## Backup: `scripts/backup.sh`

```bash
BACKUP_AGE_RECIPIENT=age1... COMPOSE_PROJECT=<projeto> scripts/backup.sh
```

1. Grava o manifesto (contagens de `eventos`, `organizacoes`, `usuarios`, tabelas que nunca perdem
   linhas) e então `docker compose exec -T db pg_dump -Fc`, os dois cifrados no pipe com
   `age -r`. Resultado em `backups/` (`BACKUP_DIR`): `cofre-<UTC>.dump.age` e
   `cofre-<UTC>.manifesto.age`, com `umask 077`.
2. **Retenção local:** fica o backup mais novo de cada um dos 7 dias mais recentes, dos 4 domingos
   mais recentes e dos 3 dias 1 mais recentes (um arquivo pode contar em mais de uma regra); o resto
   é apagado (com o manifesto). `scripts/backup.sh --retencao < nomes` mostra o que ficaria.
3. **Cópia externa (R2):** destino `BACKUP_RCLONE_DEST` (padrão `r2:secrets-backup`). Prefixos
   fixos: `diario/` sempre, `semanal/` no domingo (UTC) e `mensal/` no dia 1 (UTC). Só
   `rclone copyto --s3-no-check-bucket --no-check-dest` de arquivo novo: **o script nunca apaga
   nada no R2**. A validade lá é das regras de ciclo de vida do bucket: `diario/` 8 dias,
   `semanal/` 35, `mensal/` 100.
4. Sem destino utilizável (`BACKUP_RCLONE_DEST` vazio, `rclone` ausente ou remoto não configurado)
   o backup local vale, com `AVISO` no log e `motivo=ignorado: ...` no status.
5. Escreve `backups/status` (`em=<UTC> resultado=ok|falha motivo=...`) e, só em sucesso,
   `backups/ultimo_ok` (`<UTC> <arquivo>`). Log em stderr, sem segredos.

Saída: `0` ok · `2` configuração · `3` guarda de cota · `4` falha ao medir/enviar ao destino.
Em `3`/`4` o backup local fica e o status traz o motivo; o cron deve alertar em saída ≠ 0.

### Guarda de cota do R2 (nunca passar de 90% do plano grátis)

Antes de enviar, o script mede o uso atual do bucket (`rclone size --json`) e calcula

```
projetado = uso_atual + (tamanho do .dump.age + tamanho do .manifesto.age) × nº de prefixos do dia
```

Se `projetado > BACKUP_LIMITE_BYTES` (padrão `9000000000` = 9 GB = 90% dos 10 GB grátis), **nada é
enviado**, a saída é `3` e o motivo vai ao log e ao `backups/status`. O uso medido inclui objetos
que o ciclo de vida ainda vai expirar, então a conta é conservadora. Testado em
`tests/test_backup.py` com um `rclone` simulado no `PATH` (exatamente no limite passa, um byte acima
não envia nada).

Espaço em regime: com um backup por dia ficam no bucket ~8 cópias em `diario/`, ~5 em `semanal/` e
~4 em `mensal/` ≈ 17 cópias do dump. A guarda só dispara com dump perto de 9 GB / 17 ≈ 530 MB; o
cofre (blobs de até 64 KiB, dezenas de usuários) fica em poucos MB.

### Operações do R2 por mês (plano grátis: 1 milhão Class A, 10 milhões Class B)

| Operação do script | Classe | Por execução | Por mês (1 execução/dia) |
|---|---|---|---|
| `rclone size` (ListObjectsV2, até 1000 objetos por chamada; o bucket tem ~35) | A | 1 | 31 |
| `copyto` em `diario/` (PutObject × 2 arquivos; `--no-check-dest` evita o HEAD antes) | A | 2 | 62 |
| `copyto` em `semanal/` (domingos) | A | 2 | ~10 |
| `copyto` em `mensal/` (dia 1) | A | 2 | 2 |
| `--s3-no-check-bucket` (sem HeadBucket/CreateBucket) | — | 0 | 0 |
| Expiração pelo ciclo de vida | grátis | — | — |
| **Total** | **A** | **3–7** | **≈ 105 (≤ 217 no pior caso)** |

Class A: ~105 de 1.000.000 por mês (0,01%; o teto de 90% é 900.000). Class B: o script não faz
leitura; uma restauração baixa 2 objetos (2 Class B, contra 9.000.000 de teto). Mesmo rodando o
backup de hora em hora (24×) ficaria em ~2.500 Class A/mês, longe do limite.

## Verificar a restauração: `scripts/restaurar.sh --verifica`

```bash
AGE_IDENTITY=/caminho/cofre-backup.key scripts/restaurar.sh backups/cofre-<UTC>.dump.age --verifica
```

Sobe um `postgres:16-alpine` temporário em container próprio, decifra com `age -d -i`, roda
`pg_restore --exit-on-error` e confere: `schema_migracoes` = migrations de `migracoes/` (versão e
SHA-256) e contagens ≥ o manifesto. Qualquer falha (arquivo truncado ou adulterado, chave errada,
`pg_restore`, conferência) → saída ≠ 0. O container e os arquivos decifrados somem no fim. Rode
numa máquina com a chave privada (ex.: baixando os dois arquivos de `diario/`), nunca deixando a
chave na VPS. O CI roda backup → `--verifica` → arquivo truncado falha a cada PR (job `backup`).

## Restaurar de verdade (procedimento manual)

Reversão de migration = restaurar backup (D4). Com a API parada:

```bash
docker compose stop api
age -d -i cofre-backup.key -o /tmp/cofre.dump backups/cofre-<UTC>.dump.age   # fora da VPS se possível
docker compose exec -T db dropdb -U cofre_dono cofre
docker compose exec -T db createdb -U cofre_dono cofre
docker compose exec -T db pg_restore -U cofre_dono -d cofre --exit-on-error < /tmp/cofre.dump
shred -u /tmp/cofre.dump
docker compose up -d
```

O dump traz os grants para `cofre_app` (o papel já existe no volume). Verifique antes com
`--verifica` o mesmo arquivo.

## Bootstrap

Ver o README: `docker compose up -d --build --wait`, depois `python -m app.cli criar-org` (uma vez
por instalação; o link de convite do owner sai só nessa saída) e `reemitir-convite` se ele se
perder antes do aceite.

## `COFRE_SEGREDO` (pepper)

`COFRE_SEGREDO` (32 B em base64) gera as subchaves `pepper`, `prelogin` e `totp` (D19). **Trocar o
pepper invalida todos os logins**: o `auth_hash` guardado é `Argon2id(HMAC(pepper, authHash))`, então
nenhuma senha-mestra confere depois da troca; também deixam de valer os kits de recuperação
(`HMAC(pepper, recup_auth)`), os códigos de recuperação do MFA e todos os segredos TOTP (cifrados com a
subchave `totp`), e o `prelogin` falso muda de valor. Os dados cifrados no banco continuam
intactos, mas ninguém consegue entrar para abri-los. Não há rotação suave no MVP: trocar só em
comprometimento confirmado, com um plano de reemissão de acesso para todas as contas. Guarde o valor fora do servidor junto
com a chave privada do backup: restaurar um backup exige o mesmo `COFRE_SEGREDO`.
