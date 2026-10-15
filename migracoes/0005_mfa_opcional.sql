-- 0005_mfa_opcional: MFA deixa de ser obrigatório por padrão (decisão do usuário, Fase 7).
-- Continua configurável por org em PUT /api/v1/org/politica. Só o padrão muda: linhas
-- existentes ficam como estão (não havia dados em produção).
ALTER TABLE politicas ALTER COLUMN mfa_obrigatorio SET DEFAULT false;
