# Ajustes do orquestrador ao plano

Valem sobre `FASES.md` e `PROTOCOLO-AGENTES.md` em caso de conflito.

1. **Clones de trabalho.** Construtores e validadores nunca trabalham nos checkouts locais do usuário
   (`C:\Users\ACT\Documents\Personal\Cofre_AES` e `...\Cofre-AES-Frontend`). Cada um clona do GitHub
   num diretório próprio. No E2E do frontend, o caminho do backend é passado por parâmetro.
2. **Verificações manuais ("M").** O validador executa pelo navegador quando tiver um disponível
   (Chromium/Firefox via ferramenta de browser). Se não conseguir, o item vira "pendente de verificação
   manual do usuário" no relatório, e só esse item não bloqueia a aprovação. Itens de segurança automatizáveis
   continuam bloqueantes.
3. **Fases 1 e 2 em paralelo** (repos diferentes). Da 3 em diante, uma fase por vez.
4. **Fase 9** só começa com os pré-requisitos humanos confirmados pelo usuário na conversa.
5. **Dados de infraestrutura** (IP, portas reais, observabilidade) ficam no `VPS_CONTEXTO.md` local do
   usuário, fora do repositório público.
