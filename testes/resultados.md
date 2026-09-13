# Roteiro de verificação — resultados

Testes executados contra o Supabase real do projeto (`https://frresqlkqjuumthybxkk.supabase.co`),
com a API rodando localmente (`uvicorn app.main:app --port 8030`).

**Nota sobre as consultas ao banco:** o roteiro (Seção 12) descreve as consultas
dos Testes 1, 3, 4 e 5 como executadas no SQL Editor do Supabase. Nesta sessão
não há uma sessão interativa do SQL Editor disponível, então essas consultas
foram feitas via **REST do Supabase** (`/rest/v1/segredos`), usando a chave
publishable (`apikey` / `Authorization: Bearer`) — o mesmo mecanismo de acesso
liberado pelas políticas RLS da Seção 8.3, com semântica equivalente a um
`select`/`update` direto na tabela: mesma leitura sem passar pela API, mesma
escrita direta no banco. Cada seção abaixo cita, ao lado do comando, a consulta
SQL correspondente do documento.

Cofre de teste criado para o roteiro:

- `cofre_id`: `d2c125cb-b779-462e-890b-4501b585dac5`
- senha-mestra: `senha-mestra-teste-2026`

---

## Teste 1 — Nonces distintos

**O que foi feito:** cadastrados dois segredos (`POST /cofres/{id}/segredos`)
no mesmo cofre, com a mesma senha protegida (`S3nh@-Compartilhada!`) e títulos
diferentes ("Servico A" / "Servico B"). Em seguida, consulta REST equivalente a
`select nonce, criptograma from public.segredos where cofre_id = '...'`.

**Comando:**
```
curl -s -X POST http://127.0.0.1:8030/cofres/d2c125cb-b779-462e-890b-4501b585dac5/segredos \
  -H 'Content-Type: application/json' -H 'X-Senha-Mestra: senha-mestra-teste-2026' \
  -d '{"titulo":"Servico A","usuario":"admin","senha":"S3nh@-Compartilhada!"}'

curl -s -X POST http://127.0.0.1:8030/cofres/d2c125cb-b779-462e-890b-4501b585dac5/segredos \
  -H 'Content-Type: application/json' -H 'X-Senha-Mestra: senha-mestra-teste-2026' \
  -d '{"titulo":"Servico B","usuario":"admin","senha":"S3nh@-Compartilhada!"}'

curl -s 'https://frresqlkqjuumthybxkk.supabase.co/rest/v1/segredos?select=id,titulo,nonce,criptograma&cofre_id=eq.d2c125cb-b779-462e-890b-4501b585dac5' \
  -H 'apikey: <KEY>' -H 'Authorization: Bearer <KEY>'
```

**Resultado observado** (evidência completa em `evidencias/teste1.txt`):

| Segredo | nonce | criptograma |
|---|---|---|
| A (`10e8d34a...`) | `Etx0nvK7ONGR/Ok7` | `oOCXV94bTVanLNBDXphz3RVplls=` |
| B (`621b1681...`) | `hMecghfucsrRI9Gx` | `9FWL6wutWVSIWoZR7KXElG5ia3M=` |

`nonce` e `criptograma` são diferentes entre os dois registros, mesmo com a
senha protegida idêntica nos dois.

**Bateu com o esperado da Seção 12:** sim.

---

## Teste 2 — Senha-mestra incorreta

**O que foi feito:** `GET /cofres/{id}/segredos/{sid}` do segredo A, com o
cabeçalho `X-Senha-Mestra` incorreto.

**Comando:**
```
curl -s -i -X GET http://127.0.0.1:8030/cofres/d2c125cb-b779-462e-890b-4501b585dac5/segredos/10e8d34a-0dc5-4c96-8225-d2a00b297c84 \
  -H 'X-Senha-Mestra: senha-errada-qualquer'
```

**Resultado observado** (evidência completa em `evidencias/teste2.txt`):
```
HTTP/1.1 401 Unauthorized
{"detail":"senha-mestra incorreta"}
```
Corpo da resposta não contém a senha nem qualquer conteúdo do segredo — apenas
a mensagem de erro do verificador.

**Bateu com o esperado da Seção 12:** sim.

---

## Teste 3 — O que o invasor enxerga

**O que foi feito:** consulta REST equivalente a
`select titulo, usuario, nonce, criptograma, etiqueta from public.segredos;`
(filtrada pelo cofre de teste), usando a chave publishable — o mesmo acesso
que as políticas RLS liberam a qualquer portador da chave.

**Comando:**
```
curl -s 'https://frresqlkqjuumthybxkk.supabase.co/rest/v1/segredos?select=titulo,usuario,nonce,criptograma,etiqueta&cofre_id=eq.d2c125cb-b779-462e-890b-4501b585dac5' \
  -H 'apikey: <KEY>' -H 'Authorization: Bearer <KEY>'
```

**Resultado observado** (evidência completa em `evidencias/teste3.txt`):
```
[{"titulo":"Servico A","usuario":"admin","nonce":"Etx0nvK7ONGR/Ok7","criptograma":"oOCXV94bTVanLNBDXphz3RVplls=","etiqueta":"++Y/d6Ob6ddVu9cTymELGg=="},
 {"titulo":"Servico B","usuario":"admin","nonce":"hMecghfucsrRI9Gx","criptograma":"9FWL6wutWVSIWoZR7KXElG5ia3M=","etiqueta":"JngC7P3iNuGS3kLyEaJZ2A=="}]
```
`titulo` e `usuario` aparecem em texto claro (comportamento esperado e
documentado na Seção 5.4/8.3); `nonce`, `criptograma` e `etiqueta` são apenas
Base64 sem significado — nenhuma senha legível.

**Bateu com o esperado da Seção 12:** sim.

---

## Teste 4 — Registro adulterado

**O que foi feito:** alterado manualmente, via REST (`PATCH`, equivalente ao
`update ... set criptograma = 'X' || substring(criptograma from 2) where id = '...'`
do documento), o primeiro caractere do campo `criptograma` do segredo A —
de `oOCXV94bTVanLNBDXphz3RVplls=` para `XOCXV94bTVanLNBDXphz3RVplls=`. Em
seguida, `GET` desse segredo pela API com a senha-mestra **correta**.

**Comando:**
```
curl -s -X PATCH 'https://frresqlkqjuumthybxkk.supabase.co/rest/v1/segredos?id=eq.10e8d34a-0dc5-4c96-8225-d2a00b297c84' \
  -H 'apikey: <KEY>' -H 'Authorization: Bearer <KEY>' -H 'Content-Type: application/json' \
  -H 'Prefer: return=representation' -d '{"criptograma":"XOCXV94bTVanLNBDXphz3RVplls="}'

curl -s -i -X GET http://127.0.0.1:8030/cofres/d2c125cb-b779-462e-890b-4501b585dac5/segredos/10e8d34a-0dc5-4c96-8225-d2a00b297c84 \
  -H 'X-Senha-Mestra: senha-mestra-teste-2026'
```

**Resultado observado** (evidência completa em `evidencias/teste4.txt`):
```
HTTP/1.1 500 Internal Server Error
{"detail":"registro adulterado"}
```
Nenhum texto claro devolvido. Conferido no log do servidor (`uvicorn`) que a
resposta veio do bloco `except ValueError` de `app/main.py` (rota
`ler_segredo`) — o log de acesso mostra só a linha
`"GET .../segredos/10e8d34a..." 500 Internal Server Error`, sem traceback de
exceção não tratada, confirmando que o 500 é deliberado (`HTTPException`) e
não um crash genérico.

**Bateu com o esperado da Seção 12:** sim.

---

## Teste 5 — Troca de criptogramas entre registros

**O que foi feito:** criado um terceiro segredo no mesmo cofre ("Servico C -
destino", com senha própria, distinta das anteriores) para servir de destino.
Copiados `nonce`, `criptograma` e `etiqueta` do segredo B (origem, intacto)
para o registro do segredo C (destino) via REST. Em seguida, `GET` do segredo
de **destino** com a senha-mestra correta.

**Comando:**
```
curl -s -X POST http://127.0.0.1:8030/cofres/d2c125cb-b779-462e-890b-4501b585dac5/segredos \
  -H 'Content-Type: application/json' -H 'X-Senha-Mestra: senha-mestra-teste-2026' \
  -d '{"titulo":"Servico C - destino","usuario":"admin","senha":"OutraSenhaDistinta#9"}'

curl -s -X PATCH 'https://frresqlkqjuumthybxkk.supabase.co/rest/v1/segredos?id=eq.bff51f9d-d563-43a4-986f-741b712de8fc' \
  -H 'apikey: <KEY>' -H 'Authorization: Bearer <KEY>' -H 'Content-Type: application/json' \
  -H 'Prefer: return=representation' \
  -d '{"nonce":"hMecghfucsrRI9Gx","criptograma":"9FWL6wutWVSIWoZR7KXElG5ia3M=","etiqueta":"JngC7P3iNuGS3kLyEaJZ2A=="}'

curl -s -i -X GET http://127.0.0.1:8030/cofres/d2c125cb-b779-462e-890b-4501b585dac5/segredos/bff51f9d-d563-43a4-986f-741b712de8fc \
  -H 'X-Senha-Mestra: senha-mestra-teste-2026'
```

**Resultado observado** (evidência completa em `evidencias/teste5.txt`):
```
HTTP/1.1 500 Internal Server Error
{"detail":"registro adulterado"}
```
A leitura do segredo de destino foi recusada: o criptograma foi cifrado com
AAD `cofre_id|segredo_B_id`, e a decifragem no registro de destino usa AAD
`cofre_id|segredo_C_id` — a etiqueta não confere, `decrypt_and_verify` lança
`ValueError`, e a API responde 500 sem devolver texto claro. Nenhum
`ValueError` não tratado apareceu no log do servidor.

**Bateu com o esperado da Seção 12:** sim.

---

## Limpeza pós-testes

Após os cinco testes, o cofre de teste (`d2c125cb-b779-462e-890b-4501b585dac5`)
foi removido via REST (`DELETE /rest/v1/cofres?id=eq...`); o `on delete cascade`
da tabela `segredos` removeu os três segredos junto. Consulta REST final
confirmou as tabelas `cofres` e `segredos` vazias.
