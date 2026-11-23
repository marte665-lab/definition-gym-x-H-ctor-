-- Héctor Tu Entrenador Personal · esquema de Supabase
-- Se pega UNA vez en Supabase → SQL Editor → Run. Se puede volver a correr sin dañar nada.
--
-- Cómo funciona la seguridad:
--  · Todas las tablas tienen RLS (seguridad por filas) activa.
--  · El administrador entra con correo y contraseña (Supabase Auth) y solo él lee y escribe las tablas.
--  · Los clientes NO tocan las tablas: entran por funciones que comprueban su código y solo
--    devuelven SU propia ficha. El código se guarda cifrado (bcrypt), nunca en texto.
--  · Máximo 5 intentos fallidos cada 15 minutos por cliente.

create extension if not exists pgcrypto with schema extensions;

-- ───────────── tablas ─────────────
create table if not exists public.administradores (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.clientes (
  id         text primary key,
  usuario    text not null default '',
  telefono   text not null default '',
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.catalogo (
  id         int primary key default 1 check (id = 1),
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.clientes_acceso (
  cliente_id     text primary key references public.clientes(id) on delete cascade,
  codigo_hash    text not null,
  creado         timestamptz not null default now(),
  ultimo_ingreso timestamptz
);

create table if not exists public.sesiones_cliente (
  token_hash text primary key,
  cliente_id text not null references public.clientes(id) on delete cascade,
  creada     timestamptz not null default now(),
  expira     timestamptz not null
);

create table if not exists public.intentos_acceso (
  id      bigserial primary key,
  clave   text not null,
  momento timestamptz not null default now()
);
create index if not exists intentos_acceso_clave on public.intentos_acceso (clave, momento);

create table if not exists public.consentimientos (
  id          bigserial primary key,
  cliente_id  text not null references public.clientes(id) on delete cascade,
  version     text not null,
  terminos    boolean not null,
  datos       boolean not null,
  salud       boolean not null,
  aceptado_en timestamptz not null default now()
);

-- ───────────── RLS ─────────────
alter table public.administradores   enable row level security;
alter table public.clientes          enable row level security;
alter table public.catalogo          enable row level security;
alter table public.clientes_acceso   enable row level security;
alter table public.sesiones_cliente  enable row level security;
alter table public.intentos_acceso   enable row level security;
alter table public.consentimientos   enable row level security;

-- Nadie anónimo toca ninguna tabla.
revoke all on public.administradores, public.clientes, public.catalogo, public.clientes_acceso,
              public.sesiones_cliente, public.intentos_acceso, public.consentimientos from anon;
-- Quien inicia sesión solo puede lo que dicen las políticas de abajo.
revoke all on public.sesiones_cliente, public.intentos_acceso from authenticated;
revoke all on public.clientes_acceso, public.consentimientos, public.administradores from authenticated;
grant select (cliente_id, creado, ultimo_ingreso) on public.clientes_acceso to authenticated; -- sin el código cifrado
grant select on public.consentimientos, public.administradores to authenticated;
grant select, insert, update, delete on public.clientes, public.catalogo to authenticated;

create or replace function public.es_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.administradores where user_id = auth.uid())
$$;
revoke execute on function public.es_admin() from public, anon, authenticated;
grant  execute on function public.es_admin() to authenticated;

drop policy if exists "admin ve su fila" on public.administradores;
create policy "admin ve su fila" on public.administradores for select to authenticated using (user_id = auth.uid());

drop policy if exists "admin todo" on public.clientes;
create policy "admin todo" on public.clientes for all to authenticated using (public.es_admin()) with check (public.es_admin());

drop policy if exists "admin todo" on public.catalogo;
create policy "admin todo" on public.catalogo for all to authenticated using (public.es_admin()) with check (public.es_admin());

drop policy if exists "admin ve accesos" on public.clientes_acceso;
create policy "admin ve accesos" on public.clientes_acceso for select to authenticated using (public.es_admin());

drop policy if exists "admin ve consentimientos" on public.consentimientos;
create policy "admin ve consentimientos" on public.consentimientos for select to authenticated using (public.es_admin());

-- ───────────── funciones de los clientes (sin cuenta, con código) ─────────────
create or replace function public.cliente_entrar(p_ident text, p_codigo text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  v_ident text := lower(btrim(coalesce(p_ident, '')));
  v_dig   text := regexp_replace(coalesce(p_ident, ''), '\D', '', 'g');
  v_cod   text := upper(regexp_replace(coalesce(p_codigo, ''), '[\s\-]', '', 'g'));
  v_id    text;
  v_hash  text;
  v_fallos int;
  v_tok   text;
begin
  if length(v_ident) < 3 or length(v_cod) < 6 then
    return jsonb_build_object('ok', false, 'error', 'incorrecto');
  end if;

  delete from public.intentos_acceso where momento < now() - interval '1 day';
  delete from public.sesiones_cliente where expira < now();

  select c.id, a.codigo_hash into v_id, v_hash
    from public.clientes c join public.clientes_acceso a on a.cliente_id = c.id
   where lower(btrim(c.usuario)) = v_ident
      or (length(v_dig) >= 10 and right(regexp_replace(c.telefono, '\D', '', 'g'), 10) = right(v_dig, 10))
   limit 1;

  select count(*) into v_fallos from public.intentos_acceso
   where momento > now() - interval '15 minutes'
     and (clave = 'u:' || v_ident or (v_id is not null and clave = 'c:' || v_id));
  if v_fallos >= 5 then
    return jsonb_build_object('ok', false, 'error', 'bloqueado');
  end if;

  if v_id is null or v_hash <> extensions.crypt(v_cod, v_hash) then
    insert into public.intentos_acceso (clave) values ('u:' || v_ident);
    if v_id is not null then insert into public.intentos_acceso (clave) values ('c:' || v_id); end if;
    return jsonb_build_object('ok', false, 'error', 'incorrecto');
  end if;

  delete from public.intentos_acceso where clave = 'u:' || v_ident or clave = 'c:' || v_id;
  v_tok := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.sesiones_cliente (token_hash, cliente_id, expira)
    values (encode(extensions.digest(v_tok, 'sha256'), 'hex'), v_id, now() + interval '30 days');
  update public.clientes_acceso set ultimo_ingreso = now() where cliente_id = v_id;
  return jsonb_build_object('ok', true, 'token', v_tok);
end $$;

create or replace function public._cliente_de_token(p_token text)
returns text language sql stable security definer set search_path = public, extensions as $$
  select cliente_id from public.sesiones_cliente
   where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expira > now()
$$;

create or replace function public.cliente_datos(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_id text := public._cliente_de_token(p_token);
begin
  if v_id is null then return jsonb_build_object('ok', false, 'error', 'sesion'); end if;
  return jsonb_build_object(
    'ok', true,
    'id', v_id,
    'cliente', (select data from public.clientes where id = v_id),
    'catalogo', (select data from public.catalogo where id = 1),
    'consentimiento', exists (select 1 from public.consentimientos
                               where cliente_id = v_id and terminos and datos and salud));
end $$;

create or replace function public.cliente_aceptar(p_token text, p_version text, p_terminos boolean, p_datos boolean, p_salud boolean)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_id text := public._cliente_de_token(p_token);
begin
  if v_id is null then return jsonb_build_object('ok', false, 'error', 'sesion'); end if;
  if not (coalesce(p_terminos, false) and coalesce(p_datos, false) and coalesce(p_salud, false)) then
    return jsonb_build_object('ok', false, 'error', 'faltan');
  end if;
  insert into public.consentimientos (cliente_id, version, terminos, datos, salud)
    values (v_id, coalesce(p_version, 'v1'), true, true, true);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.cliente_cambiar_codigo(p_token text, p_actual text, p_nuevo text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  v_id   text := public._cliente_de_token(p_token);
  v_hash text;
  v_act  text := upper(regexp_replace(coalesce(p_actual, ''), '[\s\-]', '', 'g'));
  v_new  text := regexp_replace(coalesce(p_nuevo, ''), '[\s]', '', 'g');
begin
  if v_id is null then return jsonb_build_object('ok', false, 'error', 'sesion'); end if;
  if length(v_new) < 6 then return jsonb_build_object('ok', false, 'error', 'corto'); end if;
  select codigo_hash into v_hash from public.clientes_acceso where cliente_id = v_id;
  if v_hash is null or v_hash <> extensions.crypt(v_act, v_hash) then
    return jsonb_build_object('ok', false, 'error', 'incorrecto');
  end if;
  update public.clientes_acceso set codigo_hash = extensions.crypt(upper(v_new), extensions.gen_salt('bf')) where cliente_id = v_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.cliente_salir(p_token text)
returns void language sql security definer set search_path = public, extensions as $$
  delete from public.sesiones_cliente where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

-- ───────────── funciones del administrador ─────────────
create or replace function public.admin_dar_acceso(p_cliente text, p_codigo text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_cod text := upper(regexp_replace(coalesce(p_codigo, ''), '[\s\-]', '', 'g'));
begin
  if not public.es_admin() then raise exception 'No autorizado' using errcode = '42501'; end if;
  if length(v_cod) < 6 then return jsonb_build_object('ok', false, 'error', 'corto'); end if;
  if not exists (select 1 from public.clientes where id = p_cliente) then
    return jsonb_build_object('ok', false, 'error', 'cliente');
  end if;
  insert into public.clientes_acceso (cliente_id, codigo_hash)
    values (p_cliente, extensions.crypt(v_cod, extensions.gen_salt('bf')))
    on conflict (cliente_id) do update set codigo_hash = excluded.codigo_hash, creado = now();
  delete from public.sesiones_cliente where cliente_id = p_cliente;   -- cierra sesiones anteriores
  delete from public.intentos_acceso  where clave = 'c:' || p_cliente;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_quitar_acceso(p_cliente text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.es_admin() then raise exception 'No autorizado' using errcode = '42501'; end if;
  delete from public.clientes_acceso  where cliente_id = p_cliente;
  delete from public.sesiones_cliente where cliente_id = p_cliente;
end $$;

-- ───────────── permisos de ejecución (cerrado por defecto) ─────────────
revoke execute on function public.cliente_entrar(text, text)                                  from public, anon, authenticated;
revoke execute on function public._cliente_de_token(text)                                     from public, anon, authenticated;
revoke execute on function public.cliente_datos(text)                                         from public, anon, authenticated;
revoke execute on function public.cliente_aceptar(text, text, boolean, boolean, boolean)      from public, anon, authenticated;
revoke execute on function public.cliente_cambiar_codigo(text, text, text)                    from public, anon, authenticated;
revoke execute on function public.cliente_salir(text)                                         from public, anon, authenticated;
revoke execute on function public.admin_dar_acceso(text, text)                                from public, anon, authenticated;
revoke execute on function public.admin_quitar_acceso(text)                                   from public, anon, authenticated;

grant execute on function public.cliente_entrar(text, text)                              to anon, authenticated;
grant execute on function public.cliente_datos(text)                                     to anon, authenticated;
grant execute on function public.cliente_aceptar(text, text, boolean, boolean, boolean)  to anon, authenticated;
grant execute on function public.cliente_cambiar_codigo(text, text, text)                to anon, authenticated;
grant execute on function public.cliente_salir(text)                                     to anon, authenticated;
grant execute on function public.admin_dar_acceso(text, text)                            to authenticated;
grant execute on function public.admin_quitar_acceso(text)                               to authenticated;

-- ───────────── AL FINAL: convertir tu cuenta en administrador ─────────────
-- 1) En Supabase → Authentication → Users → "Add user" crea tu correo y contraseña (marca "Auto confirm user").
-- 2) Cambia el correo y corre esta línea:
-- insert into public.administradores (user_id) select id from auth.users where email = 'TU_CORREO@ejemplo.com' on conflict do nothing;
