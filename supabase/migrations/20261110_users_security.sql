begin;

-- Evita altas concurrentes mientras se comprueba auth.users y se instala el trigger.
LOCK TABLE auth.users IN SHARE ROW EXCLUSIVE MODE;

do $preflight$
declare role_name text; role_row record; target record;
begin
  if exists(select 1 from auth.users) then
    raise exception 'auth.users contiene usuarios; revisión manual requerida, no se realizará backfill';
  end if;
  foreach role_name in array array['postgres','anon','authenticated','service_role'] loop
    if not exists(select 1 from pg_roles where rolname=role_name) then raise exception 'Falta rol requerido: %',role_name; end if;
  end loop;
  if current_user<>'postgres' then raise exception 'Ejecutar como postgres'; end if;
  if current_setting('server_version_num')::integer<160000 then raise exception 'Se requiere PostgreSQL 16+'; end if;
  if to_regnamespace('private') is not null then raise exception 'Esquema private preexistente'; end if;
  if to_regclass('public.profiles') is not null or to_regclass('public.audit_logs') is not null then raise exception 'Tablas Ecolimpieza preexistentes'; end if;
  if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','private') and p.proname like 'eco_%') then raise exception 'Función eco_* preexistente'; end if;
  if exists(select 1 from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace where not t.tgisinternal and n.nspname='auth' and c.relname='users' and t.tgname='on_auth_user_created') then raise exception 'Trigger on_auth_user_created preexistente'; end if;
  if not exists(select 1 from pg_extension e join pg_namespace n on n.oid=e.extnamespace where e.extname='pgcrypto' and n.nspname='extensions') then raise exception 'pgcrypto no está en extensions'; end if;
  if to_regprocedure('extensions.digest(bytea,text)') is null or to_regprocedure('extensions.gen_random_bytes(integer)') is null then raise exception 'Faltan funciones pgcrypto requeridas'; end if;
  if not has_table_privilege('postgres','auth.users','TRIGGER') or not has_table_privilege('postgres','auth.users','SELECT') or not has_table_privilege('postgres','auth.users','DELETE') then raise exception 'postgres requiere TRIGGER, SELECT y DELETE sobre auth.users'; end if;
  if (select rolsuper or rolcreaterole or rolcreatedb or rolreplication or not rolbypassrls from pg_roles where rolname='service_role') then raise exception 'Atributos inesperados en service_role'; end if;
  if (select rolsuper or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls from pg_roles where rolname='anon') then raise exception 'Atributos privilegiados en anon'; end if;
  if (select rolsuper or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls from pg_roles where rolname='authenticated') then raise exception 'Atributos privilegiados en authenticated'; end if;
  for role_row in select rolname from pg_roles where rolname in ('anon','authenticated','service_role') loop
    for target in select rolname,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls from pg_roles
      where (role_row.rolname in ('anon','authenticated') and (rolname in ('postgres','service_role') or rolsuper or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls))
         or (role_row.rolname='service_role' and (rolname='postgres' or rolsuper or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls))
    loop
      if role_row.rolname=target.rolname then continue; end if;
      if pg_has_role(role_row.rolname,target.rolname,'MEMBER') or pg_has_role(role_row.rolname,target.rolname,'USAGE') or pg_has_role(role_row.rolname,target.rolname,'SET') then
        raise exception 'Membresía inesperada role=% target=% superuser=% createrole=% createdb=% replication=% bypassrls=%',role_row.rolname,target.rolname,target.rolsuper,target.rolcreaterole,target.rolcreatedb,target.rolreplication,target.rolbypassrls;
      end if;
    end loop;
  end loop;
end
$preflight$;

-- Solo defaults específicos; no altera defaults globales de postgres ni de supabase_admin.
create schema private authorization postgres;
alter default privileges for role postgres in schema public revoke all on tables from public,anon,authenticated,service_role;
alter default privileges for role postgres in schema public revoke all on sequences from public,anon,authenticated,service_role;
alter default privileges for role postgres in schema public revoke execute on functions from public,anon,authenticated,service_role;
alter default privileges for role postgres in schema private revoke all on tables from public,anon,authenticated,service_role;
alter default privileges for role postgres in schema private revoke all on sequences from public,anon,authenticated,service_role;
alter default privileges for role postgres in schema private revoke execute on functions from public,anon,authenticated,service_role;
revoke all on schema private from public,anon,authenticated,service_role;
grant usage on schema private to postgres;

do $schema_acl_guard$
declare a record; role_name text;
begin
  if (select nspowner from pg_namespace where nspname='private')<>'postgres'::regrole then raise exception 'Owner inesperado de private'; end if;
  for a in select x.grantee,x.grantor,x.privilege_type,x.is_grantable from pg_namespace n cross join lateral aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) x where n.nspname='private' loop
    if a.grantee='postgres'::regrole and a.grantor='postgres'::regrole and a.privilege_type in ('USAGE','CREATE') then continue; end if;
    raise exception 'ACL inesperada en private: grantee=% grantor=% privilege=% grant_option=%',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,case when a.grantor=0 then 'PUBLIC' else pg_get_userbyid(a.grantor) end,a.privilege_type,a.is_grantable;
  end loop;
  foreach role_name in array array['anon','authenticated','service_role'] loop
    if has_schema_privilege(role_name,'private','USAGE') then raise exception 'USAGE efectivo inesperado en private para %',role_name; end if;
    if has_schema_privilege(role_name,'private','CREATE') then raise exception 'CREATE efectivo inesperado en private para %',role_name; end if;
    if pg_has_role(role_name,'postgres','MEMBER') or pg_has_role(role_name,'postgres','USAGE') or pg_has_role(role_name,'postgres','SET') then raise exception 'Membresía a postgres inesperada para %',role_name; end if;
  end loop;
end
$schema_acl_guard$;

do $default_guard$
declare d record;
begin
  for d in select coalesce(n.nspname,'<global>') as schema_name,d.defaclobjtype,coalesce(r.rolname,'PUBLIC') as grantee,pg_get_userbyid(x.grantor) as grantor,x.privilege_type,x.is_grantable
    from pg_default_acl d left join pg_namespace n on n.oid=d.defaclnamespace cross join lateral aclexplode(d.defaclacl) x left join pg_roles r on r.oid=x.grantee
    where d.defaclrole='postgres'::regrole and d.defaclnamespace<>0 and n.nspname in ('public','private')
  loop
    if d.grantee='postgres' and d.grantor='postgres' then continue; end if;
    raise exception 'Default ACL inesperada schema=% type=% grantee=% grantor=% privilege=% grant_option=%',d.schema_name,d.defaclobjtype,d.grantee,d.grantor,d.privilege_type,d.is_grantable;
  end loop;
end
$default_guard$;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  nombre_usuario text not null,
  nombre_completo text not null,
  rol text not null default 'vendedora',
  activo boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint profiles_username_format check(nombre_usuario ~ '^[a-z0-9._-]{3,30}$'),
  constraint profiles_name_length check(char_length(trim(nombre_completo)) between 2 and 100),
  constraint profiles_role_valid check(rol in ('jefa','vendedora'))
);
create unique index profiles_username_lower_uidx on public.profiles(lower(nombre_usuario));

create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid null references auth.users(id) on delete restrict,
  affected_user_id uuid null references auth.users(id) on delete restrict,
  action text not null check(char_length(action) between 2 and 80),
  details jsonb not null default '{}'::jsonb check(jsonb_typeof(details)='object'),
  created_at timestamptz not null default now()
);
create index audit_logs_created_idx on public.audit_logs(created_at desc);
create index audit_logs_actor_idx on public.audit_logs(actor_id,created_at desc);

create table private.auth_rate_limits (
  dimension text not null check(dimension in ('user','ip')),
  subject_hash text not null check(subject_hash ~ '^[0-9a-f]{64}$'),
  attempts integer not null default 0 check(attempts>=0),
  window_started_at timestamptz not null default now(),
  block_level integer not null default 0 check(block_level between 0 and 6),
  blocked_until timestamptz,
  updated_at timestamptz not null default now(),
  primary key(dimension,subject_hash)
);
create index auth_rate_limits_cleanup_idx on private.auth_rate_limits(updated_at);

create table private.bootstrap_state (
  singleton boolean primary key default true check(singleton),
  status text not null check(status in ('pending','completed','blocked')),
  target_user_id uuid null references auth.users(id) on delete restrict,
  completed_at timestamptz null,
  constraint bootstrap_state_consistency check((status='pending' and target_user_id is null and completed_at is null) or (status='completed' and target_user_id is not null and completed_at is not null) or (status='blocked' and completed_at is null))
);
insert into private.bootstrap_state(singleton,status) values(true,'pending');

create table private.bootstrap_claims (
  user_id uuid primary key references auth.users(id) on delete cascade,
  secret_hash bytea not null check(octet_length(secret_hash)=32),
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  created_at timestamptz not null default now()
);
create unique index bootstrap_one_unconsumed_claim on private.bootstrap_claims((true)) where consumed_at is null;

create table private.profile_write_capabilities (
  txid bigint not null,
  profile_id uuid not null references auth.users(id) on delete cascade,
  field_name text not null check(field_name in ('rol','activo')),
  field_value text not null,
  primary key(txid,profile_id,field_name)
);

create function public.eco_set_updated_at() returns trigger language plpgsql security invoker set search_path=''
as $f$ begin new.updated_at:=pg_catalog.now(); return new; end $f$;
alter function public.eco_set_updated_at() owner to postgres;
create trigger profiles_set_updated_at before update on public.profiles for each row execute function public.eco_set_updated_at();

create function public.eco_protect_profile_privileges() returns trigger language plpgsql security definer set search_path='' set row_security=off
as $f$
declare ok boolean; tx bigint:=pg_catalog.txid_current();
begin
 if tg_op='INSERT' then
   if new.rol is distinct from 'vendedora' or new.activo is distinct from true then raise exception 'privileged_profile_insert_forbidden'; end if;
   return new;
 end if;
 if new.rol is distinct from old.rol then
   select exists(select 1 from private.profile_write_capabilities where txid=tx and profile_id=new.id and field_name='rol' and field_value=new.rol) into ok;
   if not coalesce(ok,false) then raise exception 'role_change_forbidden'; end if;
 end if;
 if new.activo is distinct from old.activo then
   select exists(select 1 from private.profile_write_capabilities where txid=tx and profile_id=new.id and field_name='activo' and field_value=new.activo::text) into ok;
   if not coalesce(ok,false) then raise exception 'active_change_forbidden'; end if;
 end if;
 return new;
end $f$;
alter function public.eco_protect_profile_privileges() owner to postgres;
create trigger profiles_protect_privileges before insert or update on public.profiles for each row execute function public.eco_protect_profile_privileges();

create function public.eco_is_current_jefa() returns boolean language sql stable security definer set search_path='' set row_security=off
as $f$ select exists(select 1 from public.profiles where id=auth.uid() and rol='jefa' and activo) $f$;
alter function public.eco_is_current_jefa() owner to postgres;
create function public.eco_is_current_active() returns boolean language sql stable security definer set search_path='' set row_security=off
as $f$ select coalesce((select activo from public.profiles where id=auth.uid()),false) $f$;
alter function public.eco_is_current_active() owner to postgres;

create function public.eco_handle_new_user() returns trigger language plpgsql security definer set search_path='' set row_security=off
as $f$
declare u text; n text; p public.profiles;
begin
 u:=pg_catalog.lower(pg_catalog.btrim(new.raw_user_meta_data->>'nombre_usuario')); n:=pg_catalog.btrim(new.raw_user_meta_data->>'nombre_completo');
 if u is null or u !~ '^[a-z0-9._-]{3,30}$' or n is null or pg_catalog.char_length(n) not between 2 and 100 then raise exception 'valid_profile_metadata_required'; end if;
 select * into p from public.profiles where id=new.id;
 if found then
  if p.nombre_usuario is distinct from u or p.nombre_completo is distinct from n or p.rol is distinct from 'vendedora' or p.activo is distinct from true then raise exception 'inconsistent_existing_profile'; end if;
  return new;
 end if;
 insert into public.profiles(id,nombre_usuario,nombre_completo,rol,activo) values(new.id,u,n,'vendedora',true);
 return new;
end $f$;
alter function public.eco_handle_new_user() owner to postgres;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.eco_handle_new_user();

create function public.eco_audit_immutable() returns trigger language plpgsql security invoker set search_path=''
as $f$ begin raise exception 'audit_logs_are_immutable'; end $f$;
alter function public.eco_audit_immutable() owner to postgres;
create trigger audit_no_update_delete before update or delete on public.audit_logs for each row execute function public.eco_audit_immutable();
create trigger audit_no_truncate before truncate on public.audit_logs for each statement execute function public.eco_audit_immutable();

create function private.eco_rate_check(u text,i text,t timestamptz default now()) returns table(allowed boolean,retry_after_seconds integer) language plpgsql security definer set search_path=''
as $f$
declare r integer;
begin
 if u is null or u !~ '^[0-9a-f]{64}$' or i is null or i !~ '^[0-9a-f]{64}$' or t is null then raise exception 'invalid_rate_parameters'; end if;
 select coalesce(max(ceil(extract(epoch from blocked_until-t)::numeric)::integer),0) into r from private.auth_rate_limits where ((dimension='user' and subject_hash=u) or (dimension='ip' and subject_hash=i)) and blocked_until>t;
 return query select r=0,r;
end $f$;
alter function private.eco_rate_check(text,text,timestamptz) owner to postgres;

create function private.eco_rate_failure(u text,i text,t timestamptz default now()) returns table(allowed boolean,retry_after_seconds integer) language plpgsql security definer set search_path=''
as $f$
declare d text; h text; lim integer; r private.auth_rate_limits; retry integer:=0;
begin
 if u is null or u !~ '^[0-9a-f]{64}$' or i is null or i !~ '^[0-9a-f]{64}$' or t is null then raise exception 'invalid_rate_parameters'; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ip:'||i,0));
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('user:'||u,0));
 select coalesce(max(ceil(extract(epoch from blocked_until-t)::numeric)::integer),0) into retry from private.auth_rate_limits where ((dimension='user' and subject_hash=u) or (dimension='ip' and subject_hash=i)) and blocked_until>t;
 if retry>0 then return query select false,retry; return; end if;
 foreach d in array array['ip','user'] loop
  if d='ip' then h:=i; lim:=40; else h:=u; lim:=8; end if;
  insert into private.auth_rate_limits as rate_row(dimension,subject_hash,attempts,window_started_at,block_level,blocked_until,updated_at)
  values(d,h,1,t,0,null,t)
  on conflict(dimension,subject_hash) do update set
   attempts=case when rate_row.window_started_at+interval '15 minutes'<=t then 1 else rate_row.attempts+1 end,
   window_started_at=case when rate_row.window_started_at+interval '15 minutes'<=t then t else rate_row.window_started_at end,
   blocked_until=case when rate_row.window_started_at+interval '15 minutes'<=t then null else rate_row.blocked_until end,
   updated_at=t
  returning * into r;
  if r.attempts>=lim then update private.auth_rate_limits set block_level=least(block_level+1,6),blocked_until=t+least(interval '30 minutes',interval '30 seconds'*power(2.0::double precision,least(block_level,6)::double precision)),updated_at=t where dimension=d and subject_hash=h returning * into r; end if;
  if r.blocked_until>t then retry:=greatest(retry,ceil(extract(epoch from r.blocked_until-t)::numeric)::integer); end if;
 end loop;
 return query select retry=0,retry;
end $f$;
alter function private.eco_rate_failure(text,text,timestamptz) owner to postgres;

create function private.eco_rate_success_user(u text) returns void language plpgsql security definer set search_path=''
as $f$ begin if u is null or u !~ '^[0-9a-f]{64}$' then raise exception 'invalid_user_hash'; end if; perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('user:'||u,0)); delete from private.auth_rate_limits where dimension='user' and subject_hash=u; end $f$;
alter function private.eco_rate_success_user(text) owner to postgres;
create function private.eco_rate_cleanup(t timestamptz default now()) returns integer language plpgsql security definer set search_path=''
as $f$
declare n integer;
begin
 if t is null then raise exception 'invalid_timestamp'; end if;
 with stale as (
  select dimension,subject_hash
  from private.auth_rate_limits
  where updated_at<t-interval '7 days'
    and (blocked_until is null or blocked_until<=t)
  order by dimension,subject_hash
  for update skip locked
 )
 delete from private.auth_rate_limits as rate_limit
 using stale
 where rate_limit.dimension=stale.dimension
   and rate_limit.subject_hash=stale.subject_hash;
 get diagnostics n=row_count;
 return n;
end $f$;
alter function private.eco_rate_cleanup(timestamptz) owner to postgres;

create function public.eco_login_rate_check(u text,i text) returns table(allowed boolean,retry_after_seconds integer) language sql security definer set search_path=''
as $f$ select * from private.eco_rate_check(u,i,now()) $f$;
alter function public.eco_login_rate_check(text,text) owner to postgres;
create function public.eco_login_rate_failure(u text,i text) returns table(allowed boolean,retry_after_seconds integer) language sql security definer set search_path=''
as $f$ select * from private.eco_rate_failure(u,i,now()) $f$;
alter function public.eco_login_rate_failure(text,text) owner to postgres;
create function public.eco_login_rate_success_user(u text) returns void language sql security definer set search_path=''
as $f$ select private.eco_rate_success_user(u) $f$;
alter function public.eco_login_rate_success_user(text) owner to postgres;

create function private.eco_issue_bootstrap_claim(target uuid,expires timestamptz) returns text language plpgsql security definer set search_path=''
as $f$
declare state private.bootstrap_state; token text;
begin
 if target is null or expires is null or expires<=now() or expires>now()+interval '10 minutes' then raise exception 'invalid_claim_parameters'; end if;
 select * into state from private.bootstrap_state where singleton for update;
 if not found or state.status<>'pending' then raise exception 'bootstrap_not_pending'; end if;
 delete from private.bootstrap_claims where consumed_at is null and expires_at<=now();
 if exists(select 1 from private.bootstrap_claims where consumed_at is null) then raise exception 'another_bootstrap_claim_pending'; end if;
 if not exists(select 1 from auth.users where id=target) or not exists(select 1 from public.profiles where id=target and rol='vendedora' and activo) then raise exception 'eligible_auth_seller_required'; end if;
 token:=pg_catalog.encode(extensions.gen_random_bytes(32),'hex');
 insert into private.bootstrap_claims(user_id,secret_hash,expires_at) values(target,extensions.digest(pg_catalog.convert_to(token,'UTF8'),'sha256'),expires);
 return token;
end $f$;
alter function private.eco_issue_bootstrap_claim(uuid,timestamptz) owner to postgres;

create function public.eco_assign_initial_jefa(target uuid,secret text) returns void language plpgsql security definer set search_path='' set row_security=off
as $f$
declare state private.bootstrap_state; claim private.bootstrap_claims;
begin
 if coalesce(auth.role(),'') is distinct from 'service_role' then raise exception 'server_only_operation'; end if;
 if target is null or secret is null or secret !~ '^[0-9a-f]{64}$' then raise exception 'invalid_bootstrap_arguments'; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ecolimpieza.bootstrap.jefa',0));
 select * into state from private.bootstrap_state where singleton for update;
 if not found or state.status<>'pending' then raise exception 'bootstrap_not_pending'; end if;
 if not exists(select 1 from auth.users where id=target) then raise exception 'auth_user_not_found'; end if;
 if exists(select 1 from public.profiles where rol='jefa' and activo) then raise exception 'active_jefa_exists'; end if;
 select * into claim from private.bootstrap_claims where user_id=target and consumed_at is null and expires_at>now() for update;
 if not found or claim.secret_hash is distinct from extensions.digest(pg_catalog.convert_to(secret,'UTF8'),'sha256') then raise exception 'invalid_bootstrap_claim'; end if;
 if not exists(select 1 from public.profiles where id=target and rol='vendedora' and activo) then raise exception 'eligible_seller_required'; end if;
 insert into private.profile_write_capabilities values(pg_catalog.txid_current(),target,'rol','jefa');
 update public.profiles set rol='jefa',updated_at=now() where id=target;
 delete from private.profile_write_capabilities where txid=pg_catalog.txid_current() and profile_id=target and field_name='rol';
 update private.bootstrap_claims set consumed_at=now() where user_id=target;
 update private.bootstrap_state set status='completed',target_user_id=target,completed_at=now() where singleton;
 insert into public.audit_logs(actor_id,affected_user_id,action,details) values(null,target,'initial_jefa_assigned',jsonb_build_object('method','bootstrap'));
end $f$;
alter function public.eco_assign_initial_jefa(uuid,text) owner to postgres;

create function public.eco_set_seller_active(actor uuid,target uuid,active boolean) returns void language plpgsql security definer set search_path='' set row_security=off
as $f$
declare previous boolean; target_role text;
begin
 if coalesce(auth.role(),'') is distinct from 'service_role' or actor is null or target is null or active is null then raise exception 'server_only_or_invalid'; end if;
 if not exists(select 1 from public.profiles where id=actor and rol='jefa' and activo) then raise exception 'active_jefa_required'; end if;
 if actor=target then raise exception 'self_status_change_forbidden'; end if;
 select rol,activo into target_role,previous from public.profiles where id=target for update;
 if not found or target_role<>'vendedora' then raise exception 'seller_target_required'; end if;
 if previous is not distinct from active then return; end if;
 insert into private.profile_write_capabilities values(pg_catalog.txid_current(),target,'activo',active::text);
 update public.profiles set activo=active,updated_at=now() where id=target;
 delete from private.profile_write_capabilities where txid=pg_catalog.txid_current() and profile_id=target and field_name='activo';
 insert into public.audit_logs(actor_id,affected_user_id,action,details) values(actor,target,case when active then 'seller_reactivated' else 'seller_deactivated' end,jsonb_build_object('previous_active',previous,'active',active));
end $f$;
alter function public.eco_set_seller_active(uuid,uuid,boolean) owner to postgres;

create function public.eco_edit_seller_profile(actor uuid,target uuid,full_name text,username text) returns void language plpgsql security definer set search_path='' set row_security=off
as $f$
declare target_role text; clean_name text; clean_username text;
begin
 if coalesce(auth.role(),'') is distinct from 'service_role' or actor is null or target is null or full_name is null or username is null then raise exception 'server_only_or_invalid'; end if;
 if not exists(select 1 from public.profiles where id=actor and rol='jefa' and activo) then raise exception 'active_jefa_required'; end if;
 if actor=target then raise exception 'self_admin_edit_forbidden'; end if;
 clean_name:=pg_catalog.btrim(full_name); clean_username:=pg_catalog.lower(pg_catalog.btrim(username));
 if pg_catalog.char_length(clean_name) not between 2 and 100 then raise exception 'invalid_full_name'; end if;
 if clean_username !~ '^[a-z0-9._-]{3,30}$' then raise exception 'invalid_username'; end if;
 select rol into target_role from public.profiles where id=target for update;
 if not found or target_role<>'vendedora' then raise exception 'seller_target_required'; end if;
 update public.profiles set nombre_completo=clean_name,nombre_usuario=clean_username,updated_at=now() where id=target;
 insert into public.audit_logs(actor_id,affected_user_id,action,details) values(actor,target,'seller_profile_updated',jsonb_build_object('fields',jsonb_build_array('nombre_completo','nombre_usuario')));
end $f$;
alter function public.eco_edit_seller_profile(uuid,uuid,text,text) owner to postgres;

alter table public.profiles enable row level security;
alter table public.audit_logs enable row level security;
alter table private.auth_rate_limits enable row level security;
alter table private.bootstrap_state enable row level security;
alter table private.bootstrap_claims enable row level security;
alter table private.profile_write_capabilities enable row level security;

revoke all on public.profiles,public.audit_logs from public,anon,authenticated,service_role;
revoke all on private.auth_rate_limits,private.bootstrap_state,private.bootstrap_claims,private.profile_write_capabilities from public,anon,authenticated,service_role;
revoke all on schema private from public,anon,authenticated,service_role;
grant select on public.profiles to authenticated,service_role;
grant update(nombre_completo) on public.profiles to authenticated;
grant select on public.audit_logs to authenticated,service_role;
grant usage on schema private to postgres;
grant select,insert,update,delete on private.auth_rate_limits to postgres;
grant select,insert,update on private.bootstrap_state to postgres;
grant select,insert,update,delete on private.bootstrap_claims to postgres;
grant select,insert,delete on private.profile_write_capabilities to postgres;

create policy profiles_select_self_or_jefa on public.profiles for select to authenticated using((id=auth.uid() and activo) or public.eco_is_current_jefa());
create policy profiles_update_self_name on public.profiles for update to authenticated using(id=auth.uid() and activo) with check(id=auth.uid() and activo);
create policy audit_select_jefa on public.audit_logs for select to authenticated using(public.eco_is_current_jefa());

-- REVOKE explícito en todas las funciones de esta migración antes de GRANT.
revoke all on function public.eco_set_updated_at() from public,anon,authenticated,service_role;
revoke all on function public.eco_protect_profile_privileges() from public,anon,authenticated,service_role;
revoke all on function public.eco_is_current_jefa() from public,anon,authenticated,service_role;
revoke all on function public.eco_is_current_active() from public,anon,authenticated,service_role;
revoke all on function public.eco_handle_new_user() from public,anon,authenticated,service_role;
revoke all on function public.eco_audit_immutable() from public,anon,authenticated,service_role;
revoke all on function private.eco_rate_check(text,text,timestamptz) from public,anon,authenticated,service_role;
revoke all on function private.eco_rate_failure(text,text,timestamptz) from public,anon,authenticated,service_role;
revoke all on function private.eco_rate_success_user(text) from public,anon,authenticated,service_role;
revoke all on function private.eco_rate_cleanup(timestamptz) from public,anon,authenticated,service_role;
revoke all on function public.eco_login_rate_check(text,text) from public,anon,authenticated,service_role;
revoke all on function public.eco_login_rate_failure(text,text) from public,anon,authenticated,service_role;
revoke all on function public.eco_login_rate_success_user(text) from public,anon,authenticated,service_role;
revoke all on function private.eco_issue_bootstrap_claim(uuid,timestamptz) from public,anon,authenticated,service_role;
revoke all on function public.eco_assign_initial_jefa(uuid,text) from public,anon,authenticated,service_role;
revoke all on function public.eco_set_seller_active(uuid,uuid,boolean) from public,anon,authenticated,service_role;
revoke all on function public.eco_edit_seller_profile(uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.eco_is_current_jefa() to authenticated;
grant execute on function public.eco_is_current_active() to authenticated;
grant execute on function public.eco_login_rate_check(text,text) to service_role;
grant execute on function public.eco_login_rate_failure(text,text) to service_role;
grant execute on function public.eco_login_rate_success_user(text) to service_role;
grant execute on function private.eco_issue_bootstrap_claim(uuid,timestamptz) to postgres;
grant execute on function public.eco_assign_initial_jefa(uuid,text) to service_role;
grant execute on function public.eco_set_seller_active(uuid,uuid,boolean) to service_role;
grant execute on function public.eco_edit_seller_profile(uuid,uuid,text,text) to service_role;
grant execute on function private.eco_rate_cleanup(timestamptz) to postgres;

-- FUNCTION ACL GUARD
-- (Whitelists the 17 signatures, owner postgres, SECURITY mode/search_path,
-- direct ACL including grant options and effective EXECUTE for app roles.)
do $function_acl_guard$
declare f record; a record; fn oid; owner_oid oid; mode_definer boolean; config text[]; app_role text; total_functions integer;
begin
 for f in select * from (values
  ('public.eco_set_updated_at()',false,null::text),('public.eco_protect_profile_privileges()',true,null::text),
  ('public.eco_is_current_jefa()',true,'authenticated'),('public.eco_is_current_active()',true,'authenticated'),
  ('public.eco_handle_new_user()',true,null::text),('public.eco_audit_immutable()',false,null::text),
  ('private.eco_rate_check(text,text,timestamptz)',true,null::text),('private.eco_rate_failure(text,text,timestamptz)',true,null::text),
  ('private.eco_rate_success_user(text)',true,null::text),('private.eco_rate_cleanup(timestamptz)',true,null::text),
  ('public.eco_login_rate_check(text,text)',true,'service_role'),('public.eco_login_rate_failure(text,text)',true,'service_role'),
  ('public.eco_login_rate_success_user(text)',true,'service_role'),('private.eco_issue_bootstrap_claim(uuid,timestamptz)',true,null::text),
  ('public.eco_assign_initial_jefa(uuid,text)',true,'service_role'),('public.eco_set_seller_active(uuid,uuid,boolean)',true,'service_role'),
  ('public.eco_edit_seller_profile(uuid,uuid,text,text)',true,'service_role')
 ) v(signature,expected_definer,expected_grantee) loop
  fn:=to_regprocedure(f.signature);
  if fn is null then raise exception 'Función esperada ausente: %',f.signature; end if;
  select proowner,prosecdef,proconfig into owner_oid,mode_definer,config from pg_proc where oid=fn;
  if owner_oid<>'postgres'::regrole then raise exception 'Owner incorrecto en %',f.signature; end if;
  if mode_definer is distinct from f.expected_definer then raise exception 'SECURITY mode incorrecto en %',f.signature; end if;
  if not coalesce(config,array[]::text[]) @> array['search_path=""']::text[] then raise exception 'search_path no vacío en %',f.signature; end if;
  for a in select x.grantee,x.grantor,x.privilege_type,x.is_grantable from pg_proc p cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x where p.oid=fn loop
   if a.grantee=owner_oid and a.grantor=owner_oid and a.privilege_type='EXECUTE' and not a.is_grantable then continue; end if;
   if f.expected_grantee is not null and a.grantee=f.expected_grantee::regrole and a.grantor=owner_oid and a.privilege_type='EXECUTE' and not a.is_grantable then continue; end if;
   raise exception 'ACL función inesperada function=% grantee=% privilege=% grantor=% grant_option=%',f.signature,case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,case when a.grantor=0 then 'PUBLIC' else pg_get_userbyid(a.grantor) end,a.is_grantable;
  end loop;
  foreach app_role in array array['anon','authenticated','service_role'] loop
   if app_role='anon' and has_function_privilege(app_role,fn,'EXECUTE') then raise exception 'EXECUTE inesperado anon: %',f.signature; end if;
   if app_role is distinct from f.expected_grantee and has_function_privilege(app_role,fn,'EXECUTE') then raise exception 'EXECUTE inesperado role=% function=%',app_role,f.signature; end if;
   if app_role=f.expected_grantee and not has_function_privilege(app_role,fn,'EXECUTE') then raise exception 'EXECUTE esperado ausente role=% function=%',app_role,f.signature; end if;
  end loop;
 end loop;
 select count(*) into total_functions from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','private') and p.proname like 'eco_%';
 if total_functions<>17 then raise exception 'Cantidad de funciones eco_* inesperada: %',total_functions; end if;
end
$function_acl_guard$;

-- TABLE ACL GUARD
-- Expected direct grants: profiles SELECT auth/service; audit SELECT auth/service;
-- profile fullname UPDATE column auth; private tables owner only.
do $table_acl_guard$
declare a record; obj record; app_role text; priv text; col record; expected boolean;
begin
 for a in select c.relname,x.grantee,x.grantor,x.privilege_type,x.is_grantable from pg_class c join pg_namespace n on n.oid=c.relnamespace cross join lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) x
  where (n.nspname='public' and c.relname in ('profiles','audit_logs')) or (n.nspname='private' and c.relname in ('auth_rate_limits','bootstrap_state','bootstrap_claims','profile_write_capabilities')) loop
  if a.grantee='postgres'::regrole and a.grantor='postgres'::regrole then continue; end if;
  if a.grantor='postgres'::regrole and not a.is_grantable and exists(select 1 from (values
    ('profiles','authenticated','SELECT'),('profiles','service_role','SELECT'),('audit_logs','authenticated','SELECT'),('audit_logs','service_role','SELECT')
  ) q(tbl,grantee,privilege) join pg_roles r on r.rolname=q.grantee where q.tbl=a.relname and r.oid=a.grantee and q.privilege=a.privilege_type) then continue; end if;
  raise exception 'ACL tabla inesperada table=% grantee=% privilege=% grantor=% grant_option=%',a.relname,case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,pg_get_userbyid(a.grantor),a.is_grantable;
 end loop;
 for a in select c.relname,att.attname,x.grantee,x.grantor,x.privilege_type,x.is_grantable from pg_class c join pg_namespace n on n.oid=c.relnamespace join pg_attribute att on att.attrelid=c.oid and att.attnum>0 and not att.attisdropped cross join lateral aclexplode(coalesce(att.attacl,array[]::aclitem[])) x
  where n.nspname in ('public','private') and c.relname in ('profiles','audit_logs','auth_rate_limits','bootstrap_state','bootstrap_claims','profile_write_capabilities') loop
  if a.grantee='postgres'::regrole and a.grantor='postgres'::regrole then continue; end if;
  if a.relname='profiles' and a.attname='nombre_completo' and a.grantee='authenticated'::regrole and a.grantor='postgres'::regrole and a.privilege_type='UPDATE' and not a.is_grantable then continue; end if;
  raise exception 'ACL columna inesperada table=% column=% grantee=% privilege=% grant_option=%',a.relname,a.attname,case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,a.is_grantable;
 end loop;
 for obj in select * from (values ('public.profiles'::regclass),('public.audit_logs'::regclass),('private.auth_rate_limits'::regclass),('private.bootstrap_state'::regclass),('private.bootstrap_claims'::regclass),('private.profile_write_capabilities'::regclass)) v(rel) loop
  foreach app_role in array array['anon','authenticated','service_role'] loop
   foreach priv in array array['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'] loop
    select exists(select 1 from (values ('public.profiles'::regclass,'authenticated','SELECT'),('public.profiles'::regclass,'service_role','SELECT'),('public.audit_logs'::regclass,'authenticated','SELECT'),('public.audit_logs'::regclass,'service_role','SELECT')) e(rel,grantee,privilege) where e.rel=obj.rel and e.grantee=app_role and e.privilege=priv) into expected;
    if has_table_privilege(app_role,obj.rel,priv) is distinct from expected then raise exception 'Privilegio efectivo tabla inesperado role=% table=% privilege=% expected=%',app_role,obj.rel,priv,expected; end if;
   end loop;
  end loop;
 end loop;
 if current_setting('server_version_num')::integer>=170000 then
  foreach app_role in array array['anon','authenticated','service_role'] loop
   if has_table_privilege(app_role,'public.profiles','MAINTAIN') or has_table_privilege(app_role,'public.audit_logs','MAINTAIN') or has_table_privilege(app_role,'private.auth_rate_limits','MAINTAIN') or has_table_privilege(app_role,'private.bootstrap_state','MAINTAIN') or has_table_privilege(app_role,'private.bootstrap_claims','MAINTAIN') or has_table_privilege(app_role,'private.profile_write_capabilities','MAINTAIN') then raise exception 'MAINTAIN inesperado para %',app_role; end if;
  end loop;
 end if;
 for col in select attname from pg_attribute where attrelid='public.profiles'::regclass and attnum>0 and not attisdropped loop
  if has_column_privilege('authenticated','public.profiles',col.attname,'UPDATE') is distinct from (col.attname='nombre_completo') then raise exception 'UPDATE columna inesperado authenticated profiles.%',col.attname; end if;
  if has_column_privilege('service_role','public.profiles',col.attname,'UPDATE') then raise exception 'UPDATE columna inesperado service_role profiles.%',col.attname; end if;
 end loop;
end
$table_acl_guard$;

-- RLS guard: seis tablas y exactamente tres policies, con expresiones verificadas.
do $rls_guard$
declare t record; policy_count integer; p record;
begin
 for t in select * from (values ('public','profiles'),('public','audit_logs'),('private','auth_rate_limits'),('private','bootstrap_state'),('private','bootstrap_claims'),('private','profile_write_capabilities')) v(s,n) loop
  if not exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=t.s and c.relname=t.n and c.relrowsecurity and not c.relforcerowsecurity) then raise exception 'RLS/FORCE incorrecto en %.%',t.s,t.n; end if;
 end loop;
 select count(*) into policy_count from pg_policies where schemaname='public' and tablename='profiles';
 if policy_count<>2 then raise exception 'profiles requiere dos policies, encontradas %',policy_count; end if;
 select count(*) into policy_count from pg_policies where schemaname='public' and tablename='audit_logs';
 if policy_count<>1 then raise exception 'audit_logs requiere una policy, encontrada %',policy_count; end if;
 if exists(select 1 from pg_policies where schemaname='private' and tablename in ('auth_rate_limits','bootstrap_state','bootstrap_claims','profile_write_capabilities')) then raise exception 'Policies no permitidas en private'; end if;
 for p in select * from pg_policies where (schemaname='public' and tablename in ('profiles','audit_logs')) loop
  if p.permissive<>'PERMISSIVE' or p.roles<>array['authenticated']::name[] then raise exception 'Roles/permissive incorrectos en policy %',p.policyname; end if;
  if p.policyname='profiles_select_self_or_jefa' then
   if p.tablename<>'profiles' or p.cmd<>'SELECT' or regexp_replace(lower(p.qual),'[[:space:]]','','g') is distinct from '((id=auth.uid())andactivo)orpublic.eco_is_current_jefa()' or p.with_check is not null then raise exception 'Definición incorrecta profiles_select_self_or_jefa'; end if;
  elsif p.policyname='profiles_update_self_name' then
   if p.tablename<>'profiles' or p.cmd<>'UPDATE' or regexp_replace(lower(p.qual),'[[:space:]]','','g') is distinct from '((id=auth.uid())andactivo)' or regexp_replace(lower(p.with_check),'[[:space:]]','','g') is distinct from '((id=auth.uid())andactivo)' then raise exception 'Definición incorrecta profiles_update_self_name'; end if;
  elsif p.policyname='audit_select_jefa' then
   if p.tablename<>'audit_logs' or p.cmd<>'SELECT' or regexp_replace(lower(p.qual),'[[:space:]]','','g') is distinct from 'public.eco_is_current_jefa()' or p.with_check is not null then raise exception 'Definición incorrecta audit_select_jefa'; end if;
  else raise exception 'Policy inesperada %.%',p.tablename,p.policyname;
  end if;
 end loop;
end
$rls_guard$;

commit;
