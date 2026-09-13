-- Seção 8.2 — Criação das tabelas
create table public.cofres (
  id                       uuid primary key,
  nome                     text        not null,
  kdf_sal                  text        not null,
  kdf_iteracoes            integer     not null,
  verificador_nonce        text        not null,
  verificador_criptograma  text        not null,
  verificador_etiqueta     text        not null,
  criado_em                timestamptz not null default now()
);

create table public.segredos (
  id            uuid primary key,
  cofre_id      uuid        not null,
  titulo        text        not null,
  usuario       text,
  url           text,
  nonce         text        not null,
  criptograma   text        not null,
  etiqueta      text        not null,
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  foreign key (cofre_id) references public.cofres(id)
    on delete cascade
);

create index idx_segredos_cofre on public.segredos (cofre_id);

-- Seção 8.3 — Políticas de acesso
alter table public.cofres   enable row level security;
alter table public.segredos enable row level security;

create policy "laboratorio" on public.cofres
  for all to anon using (true) with check (true);

create policy "laboratorio" on public.segredos
  for all to anon using (true) with check (true);
