begin;

-- Ecolimpieza: ciclo de vida de sesiones y RPC administrativas vinculadas a auth.uid().
-- Esta migración presupone que 20261110_users_security.sql ya fue aplicada.
-- No aplicar hasta completar pruebas de integración del Custom Access Token Hook.

do $preflight$
begin
  if current_user <> 'postgres' then
    raise exception 'Ejecutar como postgres';
  end if;
  if to_regclass('public.profiles') is null
     or to_regclass('public.audit_logs') is null
     or to_regclass('auth.sessions') is null
     or to_regnamespace('private') is null then
    raise exception 'Falta la estructura base de Ecolimpieza o auth.sessions';
  end if;
  if to_regprocedure('public.eco_set_seller_active(uuid,uuid,boolean)') is null
     or to_regprocedure('public.eco_edit_seller_profile(uuid,uuid,text,text)') is null then
    raise exception 'No se encontraron las RPC administrativas originales';
  end if;
  if not exists (
    select 1 from information_schema.columns
    where table_schema='auth' and table_name='sessions'
      and column_name in ('id','user_id','not_after')
    group by table_schema,table_name
    having count(*)=3
  ) then
    raise exception 'Esquema inesperado de auth.sessions';
  end if;
  if not exists (select 1 from pg_roles where rolname='supabase_auth_admin') then
    raise exception 'Falta el rol supabase_auth_admin';
  end if;
end
$preflight$;

alter table public.profiles
  add column deactivated_at timestamptz null;

create table private.profile_session_grants (
  user_id uuid not null references auth.users(id) on delete cascade,
  session_id uuid not null,
  granted_at timestamptz not null default pg_catalog.now(),
  deactivated_at timestamptz not null,
  primary key (user_id, session_id)
);

create index profile_session_grants_session_idx
  on private.profile_session_grants(session_id);

alter table private.profile_session_grants enable row level security;

revoke all on private.profile_session_grants from public, anon, authenticated, service_role;
grant select on private.profile_session_grants to supabase_auth_admin;
grant usage on schema private to supabase_auth_admin;
grant usage on schema public to supabase_auth_admin;
grant usage on schema auth to supabase_auth_admin;
grant select on public.profiles to supabase_auth_admin;

create policy profile_session_grants_auth_hook_select
  on private.profile_session_grants
  for select to supabase_auth_admin
  using (true);

create policy profiles_auth_hook_select
  on public.profiles
  for select to supabase_auth_admin
  using (true);

-- La función consulta el estado actual de la cuenta y distingue un refresh
-- de una autenticación nueva. auth.sessions permite invalidar el grant al hacer logout.
create function public.eco_custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
security invoker
set search_path=''
as $f$
declare
  v_user_id uuid;
  v_session_id uuid;
  v_method text;
  v_active boolean;
begin
  v_user_id := nullif(event->>'user_id','')::uuid;
  v_session_id := nullif(event->'claims'->>'session_id','')::uuid;
  v_method := event->>'authentication_method';

  if v_user_id is null or v_session_id is null then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 403,
        'message', 'invalid_auth_context'
      )
    );
  end if;

  -- Serializa emisión de tokens con la operación de desactivación.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ecolimpieza.auth:' || v_user_id::text, 0)
  );

  select p.activo
    into v_active
  from public.profiles p
  where p.id = v_user_id;

  if not found then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 403,
        'message', 'profile_not_found'
      )
    );
  end if;

  if v_active then
    return event;
  end if;

  if v_method = 'token_refresh'
     and exists (
       select 1
       from private.profile_session_grants g
       join auth.sessions s
         on s.id = g.session_id
        and s.user_id = g.user_id
       where g.user_id = v_user_id
         and g.session_id = v_session_id
     ) then
    return event;
  end if;

  return jsonb_build_object(
    'error', jsonb_build_object(
      'http_code', 403,
      'message', 'account_inactive'
    )
  );
end
$f$;

alter function public.eco_custom_access_token_hook(jsonb) owner to postgres;
revoke all on function public.eco_custom_access_token_hook(jsonb)
  from public, anon, authenticated, service_role;
grant execute on function public.eco_custom_access_token_hook(jsonb)
  to supabase_auth_admin;

-- Función usada por RLS: una cuenta activa accede normalmente; una inactiva
-- solo conserva acceso con una sesión previamente concedida y aún existente en Auth.
create function public.eco_session_allowed()
returns boolean
language sql
stable
security definer
set search_path=''
set row_security=off
as $f$
  select coalesce((
    select p.activo
    from public.profiles p
    where p.id = auth.uid()
  ), false)
  or exists (
    select 1
    from public.profiles p
    join private.profile_session_grants g
      on g.user_id = p.id
    join auth.sessions s
      on s.id = g.session_id
     and s.user_id = g.user_id
    where p.id = auth.uid()
      and p.activo = false
      and g.session_id = nullif(auth.jwt()->>'session_id','')::uuid
  )
$f$;

alter function public.eco_session_allowed() owner to postgres;
revoke all on function public.eco_session_allowed()
  from public, anon, service_role;
grant execute on function public.eco_session_allowed() to authenticated;

-- Reemplaza las RPC que recibían actor_id desde el servidor.
-- La identidad de la jefa se obtiene exclusivamente del JWT autenticado.
drop function public.eco_set_seller_active(uuid,uuid,boolean);
create function public.eco_set_seller_active(target uuid, active boolean)
returns void
language plpgsql
security definer
set search_path=''
set row_security=off
as $f$
declare
  v_actor uuid := auth.uid();
  v_actor_role text;
  v_actor_active boolean;
  v_target_role text;
  v_previous boolean;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_granted integer := 0;
  v_lock_user uuid;
begin
  if coalesce(auth.role(),'') <> 'authenticated'
     or v_actor is null
     or target is null
     or active is null then
    raise exception 'authenticated_jefa_required';
  end if;

  if v_actor = target then
    raise exception 'self_status_change_forbidden';
  end if;

  -- Locks de usuario en orden UUID para reducir deadlocks entre operaciones cruzadas.
  for v_lock_user in
    select x.user_id
    from unnest(array[v_actor,target]) as x(user_id)
    order by x.user_id
  loop
    perform pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended('ecolimpieza.auth:' || v_lock_user::text, 0)
    );
  end loop;

  perform 1
  from public.profiles p
  where p.id in (v_actor,target)
  order by p.id
  for update;

  select p.rol,p.activo
    into v_actor_role,v_actor_active
  from public.profiles p
  where p.id=v_actor;

  if not found or v_actor_role <> 'jefa' or not v_actor_active then
    raise exception 'active_jefa_required';
  end if;

  select p.rol,p.activo
    into v_target_role,v_previous
  from public.profiles p
  where p.id=target;

  if not found or v_target_role <> 'vendedora' then
    raise exception 'seller_target_required';
  end if;

  if v_previous is not distinct from active then
    return;
  end if;

  if active = false then
    -- Captura las sesiones Auth que existen al momento de la desactivación.
    insert into private.profile_session_grants(
      user_id,session_id,granted_at,deactivated_at
    )
    select target,s.id,v_now,v_now
    from auth.sessions s
    where s.user_id=target
      and (s.not_after is null or s.not_after > v_now)
    on conflict (user_id,session_id) do update
      set granted_at=excluded.granted_at,
          deactivated_at=excluded.deactivated_at;

    get diagnostics v_granted = row_count;
  else
    delete from private.profile_session_grants
    where user_id=target;
  end if;

  insert into private.profile_write_capabilities(
    txid,profile_id,field_name,field_value
  )
  values(pg_catalog.txid_current(),target,'activo',active::text);

  update public.profiles
  set activo=active,
      deactivated_at=case when active then null else v_now end,
      updated_at=v_now
  where id=target;

  delete from private.profile_write_capabilities
  where txid=pg_catalog.txid_current()
    and profile_id=target
    and field_name='activo';

  insert into public.audit_logs(actor_id,affected_user_id,action,details)
  values(
    v_actor,
    target,
    case when active then 'seller_reactivated' else 'seller_deactivated' end,
    jsonb_build_object(
      'previous_active',v_previous,
      'active',active,
      'authorized_existing_sessions',case when active then 0 else v_granted end
    )
  );
end
$f$;

alter function public.eco_set_seller_active(uuid,boolean) owner to postgres;
revoke all on function public.eco_set_seller_active(uuid,boolean)
  from public, anon, service_role;
grant execute on function public.eco_set_seller_active(uuid,boolean)
  to authenticated;

drop function public.eco_edit_seller_profile(uuid,uuid,text,text);
create function public.eco_edit_seller_profile(target uuid, full_name text, username text)
returns void
language plpgsql
security definer
set search_path=''
set row_security=off
as $f$
declare
  v_actor uuid := auth.uid();
  v_actor_role text;
  v_actor_active boolean;
  v_target_role text;
  v_clean_name text;
  v_clean_username text;
  v_lock_user uuid;
begin
  if coalesce(auth.role(),'') <> 'authenticated'
     or v_actor is null
     or target is null
     or full_name is null
     or username is null then
    raise exception 'authenticated_jefa_required';
  end if;

  if v_actor = target then
    raise exception 'self_admin_edit_forbidden';
  end if;

  for v_lock_user in
    select x.user_id
    from unnest(array[v_actor,target]) as x(user_id)
    order by x.user_id
  loop
    perform pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended('ecolimpieza.auth:' || v_lock_user::text, 0)
    );
  end loop;

  perform 1
  from public.profiles p
  where p.id in (v_actor,target)
  order by p.id
  for update;

  select p.rol,p.activo
    into v_actor_role,v_actor_active
  from public.profiles p
  where p.id=v_actor;

  if not found or v_actor_role <> 'jefa' or not v_actor_active then
    raise exception 'active_jefa_required';
  end if;

  select p.rol
    into v_target_role
  from public.profiles p
  where p.id=target;

  if not found or v_target_role <> 'vendedora' then
    raise exception 'seller_target_required';
  end if;

  v_clean_name := pg_catalog.btrim(full_name);
  v_clean_username := pg_catalog.lower(pg_catalog.btrim(username));

  if pg_catalog.char_length(v_clean_name) not between 2 and 100 then
    raise exception 'invalid_full_name';
  end if;
  if v_clean_username !~ '^[a-z0-9._-]{3,30}$' then
    raise exception 'invalid_username';
  end if;

  update public.profiles
  set nombre_completo=v_clean_name,
      nombre_usuario=v_clean_username,
      updated_at=pg_catalog.now()
  where id=target;

  insert into public.audit_logs(actor_id,affected_user_id,action,details)
  values(
    v_actor,
    target,
    'seller_profile_updated',
    jsonb_build_object('fields',jsonb_build_array('nombre_completo','nombre_usuario'))
  );
end
$f$;

alter function public.eco_edit_seller_profile(uuid,text,text) owner to postgres;
revoke all on function public.eco_edit_seller_profile(uuid,text,text)
  from public, anon, service_role;
grant execute on function public.eco_edit_seller_profile(uuid,text,text)
  to authenticated;

-- Permite a la sesión previamente autorizada consultar su perfil y seguir usando RLS.
drop policy profiles_select_self_or_jefa on public.profiles;
create policy profiles_select_self_or_jefa
  on public.profiles
  for select to authenticated
  using ((id=auth.uid() and public.eco_session_allowed())
         or public.eco_is_current_jefa());

drop policy profiles_update_self_name on public.profiles;
create policy profiles_update_self_name
  on public.profiles
  for update to authenticated
  using (id=auth.uid() and public.eco_session_allowed())
  with check (id=auth.uid() and public.eco_session_allowed());

commit;
