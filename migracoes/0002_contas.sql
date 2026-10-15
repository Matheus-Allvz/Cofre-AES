-- 0002_contas: usuários, convites, sessões e rate limit (Fase 3).
-- Tokens (convite, sessão) só como SHA-256; auth_hash só como Argon2id(HMAC(pepper, ·)).

CREATE TABLE usuarios (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  uuid NOT NULL REFERENCES organizacoes (id),
    email                   citext NOT NULL UNIQUE,
    nome                    text,
    papel                   text NOT NULL CHECK (papel IN ('owner', 'admin', 'member')),
    estado                  text NOT NULL DEFAULT 'convidado'
                            CHECK (estado IN ('convidado', 'aceito', 'ativo', 'suspenso', 'removido')),
    kdf                     jsonb,
    kdf_sal                 bytea,
    auth_hash               text,
    chave_usuario_cif       text,
    chave_usuario_recup_cif text,
    recup_auth_hmac         bytea,
    chave_publica           bytea,
    chave_privada_cif       text,
    fingerprint_confirmado  text,
    confirmado_por          uuid REFERENCES usuarios (id),
    criado_em               timestamptz NOT NULL DEFAULT now(),
    atualizado_em           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX usuarios_org_id_idx ON usuarios (org_id);

CREATE TABLE convites (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES organizacoes (id),
    usuario_id  uuid NOT NULL REFERENCES usuarios (id),
    token_hash  bytea NOT NULL UNIQUE,
    papel       text NOT NULL CHECK (papel IN ('owner', 'admin', 'member')),
    criado_por  uuid REFERENCES usuarios (id),  -- NULL = bootstrap pela CLI
    criado_em   timestamptz NOT NULL DEFAULT now(),
    expira_em   timestamptz NOT NULL,
    usado_em    timestamptz,
    revogado_em timestamptz
);

CREATE TABLE sessoes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario_id   uuid NOT NULL REFERENCES usuarios (id),
    token_hash   bytea NOT NULL UNIQUE,
    criada_em    timestamptz NOT NULL,
    ultimo_uso   timestamptz NOT NULL,
    expira_em    timestamptz NOT NULL,
    ip           inet,
    user_agent   text,
    mfa_pendente boolean NOT NULL DEFAULT false,
    revogada_em  timestamptz
);
CREATE INDEX sessoes_usuario_id_idx ON sessoes (usuario_id);

-- Infraestrutura de rate limit (RNF-01), não é dado de negócio: chave
-- 'conta:<sha256 email>' ou 'ip:<ip>:<rota>' existe antes de qualquer org/usuário.
CREATE TABLE limites (
    chave         text PRIMARY KEY,
    falhas        integer NOT NULL,
    janela_inicio timestamptz NOT NULL,
    bloqueado_ate timestamptz
);
