# Registro das operações de tratamento (ROPA) — RNF-15a

Registro do art. 37 da LGPD para o Cofre AES Empresarial. A organização que instala o cofre é a
**controladora** dos dados das pessoas dela; quem opera o servidor atua como operador. Preencher os
campos entre colchetes na instalação.

| Campo | Conteúdo |
|---|---|
| Controlador | [razão social, CNPJ, contato] |
| Encarregado (DPO) | [nome e canal de contato] |
| Operador | [quem opera a VPS e os backups] |
| Finalidade | Guardar e compartilhar credenciais de trabalho entre membros da organização, com controle de acesso e auditoria |
| Base legal | Execução de contrato / legítimo interesse do controlador na segurança da informação (art. 7º, V e IX) — [confirmar com o encarregado] |
| Titulares | Membros convidados da organização (owners, admins, members) |
| Compartilhamento | Nenhum com terceiros; backup cifrado no Cloudflare R2 (provedor de armazenamento, sem acesso ao conteúdo: o arquivo é cifrado com `age` antes de sair do servidor) |
| Transferência internacional | Possível pela localização do R2/Cloudflare — [confirmar região e cláusulas do provedor]; o conteúdo vai cifrado |

## Dados tratados (minimização, RNF-15c)

| Dado | Onde | Para quê | Retenção |
|---|---|---|---|
| E-mail, nome, papel, estado | `usuarios` | Identificar o membro, convidar, autorizar | Enquanto membro; na remoção nome e e-mail são anonimizados (`removido-<id>@invalido`) |
| Hash de autenticação (Argon2id sobre HMAC do authHash) | `usuarios` | Login (o servidor nunca recebe a senha-mestra) | Enquanto membro |
| Chaves cifradas (userKey, chave privada), chave pública, fingerprint | `usuarios` | Zero-knowledge: só o navegador do titular abre | Enquanto membro |
| Segredo TOTP (cifrado), códigos de recuperação (HMAC) | `usuarios`, `codigos_mfa` | Segundo fator | Até desativar o MFA |
| Sessões: IP, user agent, horários | `sessoes` | Segurança da sessão, "sessões ativas" | Até expirar/revogar (12 h no máximo); a linha fica para auditoria |
| Eventos: ator, IP, user agent, tipo, alvo, horário | `eventos` | Auditoria (RF-A01) | 12 meses (D23; purga manual) — o `ator_id` permanece após a remoção |
| Login falho: `sha256(e-mail)[:8]` | `eventos.meta` | Detectar ataque sem guardar o e-mail digitado | Como os eventos |
| Rate limit: `sha256(e-mail)` e IP | `limites` | Conter força bruta | Minutos (purga automática) |
| Conteúdo do cofre (credenciais) | `colecoes`, `itens`, `item_versoes` | Finalidade principal | Cifrado no navegador: o servidor não lê. Lixeira: 30 dias |
| Backups | `backups/` e R2 | Continuidade (RNF-05) | Local 7 diários + 4 semanais + 3 mensais; R2 8/35/100 dias |

## Direitos do titular

- Acesso e correção: o próprio membro vê os dados em "Minha conta"; o nome é corrigido por um admin.
- Eliminação: remoção pelo owner/admin anonimiza nome e e-mail e apaga envelopes; eventos ficam com o
  `ator_id` (obrigação de auditoria). Os backups expiram pelos prazos acima.
- Pedidos: pelo canal do encarregado.

## Segurança (art. 46)

Controles em [`seguranca.md`](seguranca.md) (modelo de ameaças e matriz requisito → controle);
incidentes em [`incidente.md`](incidente.md).
