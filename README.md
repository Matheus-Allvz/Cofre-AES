# Cofre de Senhas Corporativo

API em FastAPI para guardar senhas de forma cifrada (AES-256-GCM), com chave
derivada por cofre a partir de uma senha-mestra (PBKDF2-HMAC-SHA256) e
persistência no Supabase.

## Interface web (exemplo)

Este repositório é só a API — a interface web é um projeto separado, fora do
escopo do trabalho, que consome esta API pelas mesmas rotas documentadas
abaixo:

- Repositório: https://github.com/Matheus-Allvz/Cofre-AES-Frontend
- Demo ao vivo: https://keep.matheus-alves.dev

## Equipe

- Matheus Alves da Costa — Matheus-Allvz


## Instalação e execução

1. Clonar o repositório:
   ```bash
   git clone https://github.com/Matheus-Allvz/Cofre-AES.git
   cd Cofre-AES
   ```
2. Criar e ativar o ambiente virtual (Python 3.10+):
   ```bash
   python -m venv .venv
   .venv\Scripts\activate      # Windows
   source .venv/bin/activate   # Linux/macOS
   ```
3. Instalar as dependências:
   ```bash
   pip install -r requirements.txt
   ```
4. Criar o `.env` a partir do `.env.exemplo`, preenchendo com as credenciais
   do projeto Supabase **da própria equipe** (URL do projeto e chave
   anon/publishable):
   ```bash
   copy .env.exemplo .env   # Windows
   cp .env.exemplo .env     # Linux/macOS
   ```
   Depois de copiar, **abra o `.env` e substitua os dois valores** pelos
   reais do seu projeto (Project Settings → API, no painel do Supabase):
   ```
   SUPABASE_URL=https://SEU-PROJETO-AQUI.supabase.co
   SUPABASE_KEY=SUA-CHAVE-ANON-OU-PUBLISHABLE-AQUI
   ```
   Sem esse passo o `.env` fica com os valores fictícios do `.env.exemplo`
   e a API falha ao conectar no Supabase.
5. Rodar `sql/esquema.sql` no SQL Editor do Supabase (cria as tabelas
   `cofres` e `segredos`, o índice e as políticas de RLS).
6. Subir a API:
   ```bash
   uvicorn app.main:app --reload
   ```
7. Abrir `http://127.0.0.1:8000/docs` para testar as rotas pelo Swagger UI.

## Rotas disponíveis

Todas as rotas de segredo exigem o header `X-Senha-Mestra` com a senha-mestra
do cofre — é ela que permite derivar a chave AES e verificar o acesso.

### `POST /cofres`

Cria um cofre novo: gera um sal de 16 bytes, deriva a chave a partir da
`senha_mestra` recebida e grava um verificador cifrado (não a senha em si).

Requisição:
```json
{
  "nome": "Cofre da equipe",
  "senha_mestra": "senha-mestra-teste-2026"
}
```

Resposta (201):
```json
{"id": "d2c125cb-b779-462e-890b-4501b585dac5"}
```

### `POST /cofres/{cofre_id}/abrir`

Só confere se a senha-mestra bate com o verificador do cofre — não devolve
nem cria nada além disso.

Requisição: sem corpo, com o header `X-Senha-Mestra`.

Resposta (200):
```json
{"detail": "senha-mestra correta"}
```
Senha errada → `401 {"detail": "senha-mestra incorreta"}`.

### `POST /cofres/{cofre_id}/segredos`

Cadastra um segredo no cofre. A senha é cifrada com AES-256-GCM antes de
gravar; `titulo`, `usuario` e `url` vão para o banco em texto claro.

Requisição:
```json
{
  "titulo": "Servico A",
  "usuario": "admin",
  "senha": "S3nh@-Compartilhada!"
}
```

Resposta (201):
```json
{"id": "10e8d34a-0dc5-4c96-8225-d2a00b297c84"}
```

### `GET /cofres/{cofre_id}/segredos`

Lista os segredos do cofre — só metadados, nunca `nonce`/`criptograma`/
`etiqueta`.

Resposta (200):
```json
[
  {
    "id": "10e8d34a-0dc5-4c96-8225-d2a00b297c84",
    "titulo": "Servico A",
    "usuario": "admin",
    "url": null,
    "criado_em": "2026-09-13T20:10:00+00:00"
  }
]
```

### `GET /cofres/{cofre_id}/segredos/{segredo_id}`

Decifra e devolve a senha de um segredo específico.

Resposta (200):
```json
{"senha": "S3nh@-Compartilhada!"}
```
Registro adulterado (nonce/criptograma/etiqueta trocados) → `500
{"detail": "registro adulterado"}`.

### `PUT /cofres/{cofre_id}/segredos/{segredo_id}`

Atualiza a senha do segredo — sempre cifra de novo com um nonce novo.

Requisição:
```json
{
  "titulo": "Servico A",
  "usuario": "admin",
  "senha": "NovaSenha#2026"
}
```

Resposta (200):
```json
{"detail": "segredo atualizado"}
```

### `DELETE /cofres/{cofre_id}/segredos/{segredo_id}`

Remove o segredo.

Resposta (200):
```json
{"detail": "segredo removido"}
```
Segredo (ou cofre) inexistente → `404`.

## Justificativa dos parâmetros criptográficos

- **PBKDF2-HMAC-SHA256, ≥210.000 iterações:** a senha-mestra é o único
  segredo que o usuário guarda de cabeça, então tende a ter pouca entropia.
  PBKDF2 torna cada tentativa de força bruta cara ao repetir o HMAC milhares
  de vezes; 210.000 iterações é o piso considerado aceitável hoje para
  SHA-256 nesse tipo de derivação — abaixo disso um ataque offline com
  hardware comum fica rápido demais.
- **Sal de 16 bytes por cofre:** sem sal, a mesma senha-mestra em dois
  cofres geraria a mesma chave, e um atacante poderia pré-computar tabelas
  de ataque reaproveitáveis entre cofres. Um sal aleatório de 16 bytes por
  cofre elimina esse reaproveitamento e obriga o atacante a atacar cada
  cofre separadamente.
- **AES-256-GCM em vez de ECB/CBC:** ECB vaza padrão do texto claro (blocos
  iguais viram criptogramas iguais) e CBC, sozinho, não autentica — um
  atacante pode adulterar bytes do criptograma sem que a decifragem acuse
  erro. GCM cifra e autentica na mesma operação: qualquer bit alterado no
  criptograma, no nonce ou na etiqueta faz `decrypt_and_verify` falhar com
  `ValueError`, em vez de devolver texto corrompido silenciosamente.
- **Nonce de 12 bytes sorteado a cada cifragem:** GCM perde a garantia de
  segurança se o mesmo par (chave, nonce) for reusado — reuso permite
  recuperar a tag de autenticação e, em alguns casos, texto claro. Sortear
  um nonce novo (12 bytes, o tamanho recomendado para GCM) a cada `cifrar`,
  inclusive nas atualizações, evita esse reuso sem precisar de nenhum estado
  compartilhado entre chamadas.
- **AAD amarrando o criptograma ao cofre e ao segredo:** o AAD (`cofre_id|
  segredo_id`) não é cifrado, mas entra na verificação de integridade do
  GCM. Isso impede um ataque de "copiar e colar" — pegar o
  nonce/criptograma/etiqueta de um segredo válido e colocá-los em outro
  registro: a etiqueta só confere para o AAD com que foi gerada, então a
  troca é detectada e recusada (é exatamente o que o Teste 5 comprova).

## Limitações do sistema

**O que o cofre protege / não protege:**

| Protege | Não protege |
|---|---|
| Senha em repouso no banco (nunca em texto claro, mesmo com acesso direto à tabela) | Servidor comprometido em runtime — a chave derivada e as senhas decifradas existem em memória do processo durante a requisição |
| Adulteração do criptograma, nonce, etiqueta ou troca entre registros (recusada pelo AES-GCM + AAD) | Senha-mestra fraca ou vazada — é a única credencial do cofre; se ela vazar, o cofre inteiro é comprometido |
| Reuso de chave/nonce entre cifragens | Ausência de auditoria — não há log de quem acessou ou tentou acessar qual segredo, nem quando |

**O que é armazenado vs. nunca armazenado:**

| Armazenado (em claro) | Nunca armazenado |
|---|---|
| `titulo`, `usuario`, `url` dos segredos, `nome` do cofre | Senha-mestra |
| `nonce`, `criptograma`, `etiqueta` (Base64, sem valor sem a chave) | Chave derivada (só existe em memória, por requisição) |
| Sal do KDF e número de iterações (não são segredo, servem para reproduzir a derivação) | Senha em texto claro de qualquer segredo |

Guardar `titulo`/`usuario`/`url` em claro é decisão de projeto: sem isso não
dá para listar ou identificar os segredos sem decifrar todos a cada consulta.
O custo é que qualquer um com acesso de leitura ao banco (ou à mesma chave
REST usada pelas políticas de RLS) vê esses três campos — nunca a senha em
si, que só sai em claro na rota que a decifra.
