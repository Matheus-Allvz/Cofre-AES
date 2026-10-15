-- 0003_mfa_politicas: TOTP, códigos de recuperação de MFA, recuperação por kit e política (Fase 4).

-- Segredo TOTP só cifrado (envelope v1, chave do servidor). MFA ativo = totp_ultimo_passo
-- preenchido: a confirmação grava o passo usado; entre iniciar e confirmar ele fica NULL.
ALTER TABLE usuarios
    ADD COLUMN totp_segredo_cif  text,
    ADD COLUMN totp_ultimo_passo bigint;

-- Códigos só como HMAC-SHA256(pepper, código normalizado).
CREATE TABLE codigos_mfa (
    usuario_id  uuid NOT NULL REFERENCES usuarios (id),
    codigo_hmac bytea NOT NULL,
    usado_em    timestamptz,
    PRIMARY KEY (usuario_id, codigo_hmac)
);

-- Token de recuperação (5 min, uso único): só o SHA-256.
CREATE TABLE recuperacoes (
    token_hash bytea PRIMARY KEY,
    usuario_id uuid NOT NULL REFERENCES usuarios (id),
    expira_em  timestamptz NOT NULL,
    usado_em   timestamptz
);

CREATE TABLE politicas (
    org_id           uuid PRIMARY KEY REFERENCES organizacoes (id),
    mfa_obrigatorio  boolean NOT NULL DEFAULT true,
    inatividade_min  integer NOT NULL DEFAULT 15 CHECK (inatividade_min BETWEEN 5 AND 60),
    atualizado_em    timestamptz NOT NULL DEFAULT now()
);
INSERT INTO politicas (org_id) SELECT id FROM organizacoes;
