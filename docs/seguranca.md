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
- **Purga de `limites`.** Sem job externo: a cada login (ou outra credencial) válido, as linhas
  sem bloqueio vigente e com janela iniciada há mais de 15 min são apagadas — elas seriam
  recriadas do zero na próxima tentativa, então apagar não muda nenhuma regra. Sob ataque sem
  nenhum login válido a tabela cresce com o número de IPs distintos até o próximo login.

## MFA (RF-I03, RF-I04)

- TOTP RFC 6238 (SHA-1, 6 dígitos, 30 s, janela ±1) com `hmac` da stdlib; vetores do Apêndice B
  nos testes. Um passo vale uma vez (anti-replay atômico em `totp_ultimo_passo`).
- O segredo TOTP fica cifrado (envelope `v1`, AES-256-GCM, AAD com o id do usuário) com a
  subchave `totp` de `COFRE_SEGREDO`. Quem tem banco **e** `COFRE_SEGREDO` tem os segredos TOTP:
  o segundo fator protege contra senha vazada, não contra comprometimento do servidor.
- Os 10 códigos de recuperação (40 bits cada, `secrets`) ficam só como
  `HMAC-SHA256(pepper, código)`, aparecem uma vez e valem uma vez.
- Política `mfa_obrigatorio` (padrão ligada): sessão de usuário sem MFA só alcança `/eu`,
  `/eu/mfa/*` e `/logout`. A condição é recalculada a cada requisição, então ligar a política
  vale na hora para sessões já abertas.

## Recuperação por kit (RF-U06)

- `recuperar/iniciar` exige o `recup_auth` derivado da Recovery Key **e** o segundo fator (se o
  MFA estiver ativo) antes de entregar a userKey envelopada pelo kit. O token de conclusão vale
  5 min, uma vez. A conclusão troca senha e kit e revoga todas as sessões.
- Sem senha-mestra e sem kit, o acesso pessoal é perdido (D18).
