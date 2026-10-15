-- 0004_colecoes_itens: coleções, envelopes por membro, itens e histórico (Fase 6).
-- Tudo *_cif é envelope opaco (v1/x1) cifrado no cliente: o servidor não decifra nada.
-- ids de coleção e item vêm do cliente (entram no AAD antes da gravação, §3.3).

CREATE TABLE colecoes (
    id               uuid PRIMARY KEY,
    org_id           uuid NOT NULL REFERENCES organizacoes (id),
    nome_cif         text NOT NULL,
    chave_ver        integer NOT NULL DEFAULT 1 CHECK (chave_ver >= 1),
    rotacao_pendente boolean NOT NULL DEFAULT false,
    criada_por       uuid NOT NULL REFERENCES usuarios (id),
    criada_em        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX colecoes_org_id_idx ON colecoes (org_id);

-- Só o envelope da chave_ver atual. Sem linha = sem acesso (404 nas rotas da coleção).
CREATE TABLE colecao_membros (
    colecao_id        uuid NOT NULL REFERENCES colecoes (id),
    usuario_id        uuid NOT NULL REFERENCES usuarios (id),
    permissao         text NOT NULL
                      CHECK (permissao IN ('ver_sem_revelar', 'ver', 'editar', 'gerenciar')),
    chave_ver         integer NOT NULL,
    chave_colecao_cif text NOT NULL,
    PRIMARY KEY (colecao_id, usuario_id)
);
CREATE INDEX colecao_membros_usuario_id_idx ON colecao_membros (usuario_id);

CREATE TABLE itens (
    id                     uuid PRIMARY KEY,
    colecao_id             uuid NOT NULL REFERENCES colecoes (id),
    tipo                   text NOT NULL CHECK (tipo IN ('login', 'nota', 'chave_api')),
    versao                 integer NOT NULL DEFAULT 1 CHECK (versao >= 1),
    chave_ver              integer NOT NULL,
    meta_cif               text NOT NULL,
    segredo_cif            text NOT NULL,
    rotacao_senha_pendente boolean NOT NULL DEFAULT false,
    criado_por             uuid NOT NULL REFERENCES usuarios (id),
    criado_em              timestamptz NOT NULL,
    atualizado_por         uuid NOT NULL REFERENCES usuarios (id),
    atualizado_em          timestamptz NOT NULL,
    excluido_em            timestamptz
);
CREATE INDEX itens_colecao_id_idx ON itens (colecao_id);

-- Versões anteriores (até 10 por item; as mais antigas saem na gravação). Quem editou/quando
-- é o autor daquela versão (atualizado_por/atualizado_em do item enquanto ela era a atual).
CREATE TABLE item_versoes (
    item_id     uuid NOT NULL REFERENCES itens (id) ON DELETE CASCADE,
    versao      integer NOT NULL,
    chave_ver   integer NOT NULL,
    meta_cif    text NOT NULL,
    segredo_cif text NOT NULL,
    editado_por uuid NOT NULL REFERENCES usuarios (id),
    em          timestamptz NOT NULL,
    PRIMARY KEY (item_id, versao)
);
