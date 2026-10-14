-- 0001_base: organização e auditoria append-only.
-- Rodar sempre como o papel dono (cofre_dono): os DEFAULT PRIVILEGES abaixo valem
-- para objetos criados por quem executa. O papel cofre_app precisa existir antes.

CREATE EXTENSION IF NOT EXISTS citext;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cofre_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO cofre_app;

CREATE TABLE organizacoes (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nome      text NOT NULL,
    criada_em timestamptz NOT NULL DEFAULT now()
);

-- org_id aceita NULL só para eventos sem organização identificável
-- (ex.: login falho com e-mail inexistente, Fase 3).
CREATE TABLE eventos (
    id         bigserial PRIMARY KEY,
    em         timestamptz NOT NULL DEFAULT now(),
    org_id     uuid REFERENCES organizacoes (id),
    ator_id    uuid,
    tipo       text NOT NULL,
    alvo_tipo  text,
    alvo_id    text,
    resultado  text NOT NULL CHECK (resultado IN ('ok', 'falha')),
    ip         inet,
    user_agent text,
    meta       jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX eventos_org_id_idx ON eventos (org_id, id DESC);

-- Append-only (RF-A04): grant + trigger. O trigger barra inclusive o dono;
-- purga (D23) é operação manual que desabilita o trigger conscientemente.
REVOKE UPDATE, DELETE, TRUNCATE ON eventos FROM cofre_app;

CREATE FUNCTION eventos_imutaveis() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'eventos e append-only: % bloqueado', TG_OP;
END
$$;

CREATE TRIGGER eventos_sem_update_delete
    BEFORE UPDATE OR DELETE ON eventos
    FOR EACH ROW EXECUTE FUNCTION eventos_imutaveis();

CREATE TRIGGER eventos_sem_truncate
    BEFORE TRUNCATE ON eventos
    FOR EACH STATEMENT EXECUTE FUNCTION eventos_imutaveis();
