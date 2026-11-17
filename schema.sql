-- =====================================================================
-- Teleriabilitazione - schema Supabase
-- Incolla tutto nel SQL Editor di Supabase e premi "Run".
-- =====================================================================

-- ---------- TABELLE ----------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  ruolo text not null check (ruolo in ('terapista','paziente')),
  creato timestamptz not null default now()
);

-- Elenco dei nomi utente "autorizzati a registrarsi". Il terapista inserisce
-- il codice qui PRIMA di creare l'account: chi prova a registrarsi con un
-- nome non presente viene rifiutato dal trigger.
create table public.attesi (
  username text primary key,
  ruolo text not null default 'paziente' check (ruolo in ('terapista','paziente'))
);

create table public.esercizi (
  id text primary key,
  nome text not null,
  html text not null,
  params jsonb not null default '[]'::jsonb,
  creato timestamptz not null default now()
);

create table public.assegnazioni (
  id bigint generated always as identity primary key,
  paziente_id uuid not null references public.profiles(id) on delete cascade,
  esercizio_id text not null references public.esercizi(id) on delete cascade,
  params jsonb not null default '{}'::jsonb,
  unique (paziente_id, esercizio_id)
);

create table public.sessioni (
  id bigint generated always as identity primary key,
  paziente_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  esercizio_id text not null references public.esercizi(id) on delete cascade,
  report jsonb not null,
  creato timestamptz not null default now()
);

create table public.accessi (
  id bigint generated always as identity primary key,
  paziente_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  tipo text not null,
  creato timestamptz not null default now()
);

create index on public.sessioni (paziente_id, creato desc);
create index on public.accessi (paziente_id, creato desc);

-- ---------- FUNZIONI ----------
create or replace function public.is_terapista()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and ruolo = 'terapista')
$$;

-- Alla creazione di un account: ammesso solo se il nome è in "attesi".
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  u text := lower(split_part(new.email, '@', 1));
  a public.attesi%rowtype;
begin
  select * into a from public.attesi where username = u;
  if not found then
    raise exception 'Registrazione non autorizzata';
  end if;
  insert into public.profiles (id, username, ruolo) values (new.id, u, a.ruolo);
  delete from public.attesi where username = u;
  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Il terapista elimina un paziente (account, assegnazioni, sedute, accessi).
create or replace function public.elimina_paziente(p uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_terapista() then raise exception 'Non autorizzato'; end if;
  if not exists (select 1 from public.profiles where id = p and ruolo = 'paziente') then
    raise exception 'Paziente non trovato';
  end if;
  delete from auth.users where id = p;
end $$;

-- Il terapista reimposta la password di un paziente.
create or replace function public.reimposta_password(p uuid, nuova text)
returns void language plpgsql security definer set search_path = public, auth, extensions as $$
begin
  if not public.is_terapista() then raise exception 'Non autorizzato'; end if;
  if not exists (select 1 from public.profiles where id = p and ruolo = 'paziente') then
    raise exception 'Paziente non trovato';
  end if;
  if length(nuova) < 6 then raise exception 'Password troppo corta'; end if;
  update auth.users set encrypted_password = crypt(nuova, gen_salt('bf')), updated_at = now() where id = p;
end $$;

revoke execute on function public.elimina_paziente(uuid) from public, anon;
revoke execute on function public.reimposta_password(uuid, text) from public, anon;
grant execute on function public.elimina_paziente(uuid) to authenticated;
grant execute on function public.reimposta_password(uuid, text) to authenticated;

-- ---------- SICUREZZA A LIVELLO DI RIGA (RLS) ----------
alter table public.profiles     enable row level security;
alter table public.attesi       enable row level security;
alter table public.esercizi     enable row level security;
alter table public.assegnazioni enable row level security;
alter table public.sessioni     enable row level security;
alter table public.accessi      enable row level security;

-- profiles: ognuno vede il proprio, il terapista vede tutti
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_terapista());

-- attesi: solo terapista (e solo per creare pazienti)
create policy attesi_all on public.attesi for all to authenticated
  using (public.is_terapista())
  with check (public.is_terapista() and ruolo = 'paziente');

-- esercizi: il terapista gestisce tutto; il paziente legge solo quelli assegnati
create policy esercizi_select on public.esercizi for select to authenticated
  using (
    public.is_terapista()
    or exists (select 1 from public.assegnazioni a
               where a.esercizio_id = esercizi.id and a.paziente_id = auth.uid())
  );
create policy esercizi_write on public.esercizi for all to authenticated
  using (public.is_terapista()) with check (public.is_terapista());

-- assegnazioni: il paziente legge le sue; il terapista gestisce tutto
create policy assegn_select on public.assegnazioni for select to authenticated
  using (paziente_id = auth.uid() or public.is_terapista());
create policy assegn_write on public.assegnazioni for all to authenticated
  using (public.is_terapista()) with check (public.is_terapista());

-- sessioni: il paziente inserisce e legge le sue; il terapista legge/elimina tutto
create policy sessioni_select on public.sessioni for select to authenticated
  using (paziente_id = auth.uid() or public.is_terapista());
create policy sessioni_insert on public.sessioni for insert to authenticated
  with check (paziente_id = auth.uid());
create policy sessioni_delete on public.sessioni for delete to authenticated
  using (public.is_terapista());

-- accessi: come sessioni
create policy accessi_select on public.accessi for select to authenticated
  using (paziente_id = auth.uid() or public.is_terapista());
create policy accessi_insert on public.accessi for insert to authenticated
  with check (paziente_id = auth.uid());
create policy accessi_delete on public.accessi for delete to authenticated
  using (public.is_terapista());

-- ---------- PRIMO ACCOUNT TERAPISTA ----------
-- 1) Esegui questa riga (cambia 'terapista' se vuoi un altro nome utente):
insert into public.attesi (username, ruolo) values ('terapista', 'terapista');
-- 2) Poi crea l'utente da Authentication > Users > Add user:
--    email  terapista@tele.local   (stesso dominio di config.js), una password
--    robusta, e spunta "Auto Confirm User".
