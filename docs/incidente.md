# Resposta a incidente de segurança — RNF-15e

Roteiro para incidente que envolva o cofre (servidor, banco, backups, chaves ou contas).

## Prazo de comunicação (LGPD art. 48 + Resolução CD/ANPD nº 15/2024)

- Incidente que possa acarretar **risco ou dano relevante** aos titulares: o controlador comunica a
  **ANPD e os titulares em até 3 (três) dias úteis**, contados de quando soube que o incidente afetou
  dados pessoais. Informações que faltarem podem ser complementadas em até **20 dias úteis** da
  comunicação. Agente de pequeno porte tem os prazos contados em dobro.
- [CONFIRMADO na Fase 8 por resumos jurídicos da Resolução CD/ANPD nº 15, de 24/04/2024, publicada no
  DOU de 26/04/2024; conferir o texto oficial no DOU/site da ANPD antes do go-live e registrar aqui o
  artigo.]
- Mesmo sem risco relevante, o incidente é registrado internamente (a Resolução exige o registro) e o
  registro é guardado.

## Passos

1. **Conter (horas).**
   - Conta comprometida: suspender o membro (`POST /membros/{id}/suspender` derruba as sessões na
     hora) e, se ele saiu, remover — as coleções dele ficam com rotação pendente.
   - Servidor comprometido: tirar a API do ar (`docker compose stop api`), preservar logs e o volume.
     Lembrar do risco aceito "servidor serve o JS": quem controlou o servidor pode ter capturado
     senhas digitadas no período — tratar todas as senhas-mestras usadas desde o comprometimento
     como expostas.
   - Chave privada do backup ou `COFRE_SEGREDO` vazados: ver "Segredos" abaixo.
2. **Preservar evidências.** `GET /api/v1/auditoria` (owner/admin) com filtros de data/ator/tipo;
   `docker compose logs api`; cópia do `backups/` e do status. Os eventos são append-only.
3. **Avaliar** quais dados e titulares foram afetados. O conteúdo do cofre é cifrado no navegador: um
   vazamento só do banco ou de backup expõe metadados (e-mails, nomes, horários, IPs) e permite
   ataque offline caro às senhas-mestras, não as credenciais em claro.
4. **Comunicar** no prazo acima (ANPD pelo formulário oficial; titulares por canal direto), com:
   descrição, natureza e categoria dos dados, número de titulares, medidas de segurança (cifragem),
   riscos, medidas de mitigação e contato do encarregado.
5. **Remediar.**
   - Rotacionar as coleções afetadas (botão "Rotacionar a chave agora" no Cofre) e trocar no
     sistema de origem as senhas em "Senhas a trocar".
   - Pedir troca de senha-mestra e novo kit aos afetados; revogar sessões.
6. **Registrar** o incidente (o quê, quando soube, decisões, comunicações) e revisar os controles.

## Segredos

| Segredo | Se vazar |
|---|---|
| Chave privada `age` do backup | Gerar novo par, trocar `BACKUP_AGE_RECIPIENT`, apagar os backups antigos onde for possível (no R2, deixar o ciclo de vida expirar ou apagar manualmente). O conteúdo do cofre continua cifrado pelas chaves dos usuários |
| `COFRE_SEGREDO` | Permite ataque offline aos hashes de autenticação e lê os segredos TOTP. Trocar invalida todos os logins (ver `operacao.md`) |
| Credencial do bucket R2 | Revogar no painel da Cloudflare e criar outra; os objetos são cifrados |
| Senhas do Postgres (`.env`) | Trocar no `.env` e no papel do banco; a porta do banco não é publicada |
