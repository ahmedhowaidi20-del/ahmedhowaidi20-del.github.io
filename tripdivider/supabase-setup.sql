-- TripDivider: run this whole file once in Supabase
-- Dashboard → SQL Editor → New query → paste → Run
--
-- How access works
--  • Every trip has a unique name (never reusable, even after the trip is deleted) and a password.
--  • Passwords are stored only as bcrypt hashes.
--  • The tables are locked (RLS on, no policies), so the public key can't read them directly.
--    The page can only call the functions below.
--  • Joining with name + password gives the phone a session token; every other call needs that token.
--  • 5 wrong passwords in a row lock that trip's login for 5 minutes.
--  • Changing the password signs out every other phone.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.tripdivider_names (
  name_key    text primary key,              -- lower-cased, trimmed name; rows are never deleted
  created_at  timestamptz not null default now()
);

create table if not exists public.tripdivider_trips (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  name_key      text not null unique references public.tripdivider_names(name_key),
  pass_hash     text not null,
  data          jsonb not null,
  version       int  not null default 1,
  failed_logins int  not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists public.tripdivider_sessions (
  token       uuid primary key default gen_random_uuid(),
  trip_id     uuid not null references public.tripdivider_trips(id) on delete cascade,
  created_at  timestamptz not null default now()
);
create index if not exists tripdivider_sessions_trip on public.tripdivider_sessions(trip_id);

alter table public.tripdivider_names    enable row level security;
alter table public.tripdivider_trips    enable row level security;
alter table public.tripdivider_sessions enable row level security;
revoke all on public.tripdivider_names, public.tripdivider_trips, public.tripdivider_sessions from anon, authenticated;

create or replace function public.td_name_key(p_name text)
returns text language sql immutable as $$
  select lower(regexp_replace(btrim(coalesce(p_name, '')), '\s+', ' ', 'g'));
$$;

-- Create a trip → {ok, id, token, version} | {ok:false, error:'bad_name'|'weak_password'|'name_taken'}
create or replace function public.td_create_trip(p_name text, p_password text, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare k text := td_name_key(p_name); n text := regexp_replace(btrim(coalesce(p_name, '')), '\s+', ' ', 'g');
        got text; tid uuid; tok uuid;
begin
  if length(n) < 3 or length(n) > 40 then return jsonb_build_object('ok', false, 'error', 'bad_name'); end if;
  if length(coalesce(p_password, '')) < 6 then return jsonb_build_object('ok', false, 'error', 'weak_password'); end if;
  if octet_length(p_data::text) > 1000000 then raise exception 'Trip is too large'; end if;

  insert into tripdivider_names (name_key) values (k) on conflict do nothing returning name_key into got;
  if got is null then return jsonb_build_object('ok', false, 'error', 'name_taken'); end if;

  insert into tripdivider_trips (name, name_key, pass_hash, data)
  values (n, k, crypt(p_password, gen_salt('bf', 10)), jsonb_set(p_data, '{name}', to_jsonb(n)))
  returning id into tid;
  insert into tripdivider_sessions (trip_id) values (tid) returning token into tok;
  return jsonb_build_object('ok', true, 'id', tid, 'token', tok, 'version', 1, 'name', n);
end;
$$;

-- Join with name + password → {ok, id, token, data, version, updated_at} | {ok:false, error:'wrong'|'locked'}
create or replace function public.td_join_trip(p_name text, p_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare t tripdivider_trips; tok uuid;
begin
  select * into t from tripdivider_trips where name_key = td_name_key(p_name) for update;
  if not found then
    perform pg_sleep(0.3);                                   -- same feel as a wrong password
    return jsonb_build_object('ok', false, 'error', 'wrong');
  end if;
  if t.locked_until is not null and t.locked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'locked', 'seconds', ceil(extract(epoch from t.locked_until - now())));
  end if;
  if t.pass_hash <> crypt(coalesce(p_password, ''), t.pass_hash) then
    update tripdivider_trips
       set failed_logins = case when failed_logins + 1 >= 5 then 0 else failed_logins + 1 end,
           locked_until  = case when failed_logins + 1 >= 5 then now() + interval '5 minutes' else locked_until end
     where id = t.id;
    return jsonb_build_object('ok', false, 'error', 'wrong');
  end if;
  update tripdivider_trips set failed_logins = 0, locked_until = null where id = t.id;
  insert into tripdivider_sessions (trip_id) values (t.id) returning token into tok;
  return jsonb_build_object('ok', true, 'id', t.id, 'token', tok, 'data', t.data, 'version', t.version, 'updated_at', t.updated_at);
end;
$$;

-- One trip by session token → {id, data, version, updated_at} or null (signed out / deleted)
create or replace function public.td_get_trip(p_token uuid)
returns jsonb language sql security definer set search_path = public as $$
  select jsonb_build_object('id', t.id, 'data', t.data, 'version', t.version, 'updated_at', t.updated_at)
  from tripdivider_sessions s join tripdivider_trips t on t.id = s.trip_id
  where s.token = p_token;
$$;

-- Several trips by token (for "My trips") → array; invalid tokens are left out
create or replace function public.td_get_trips(p_tokens uuid[])
returns jsonb language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('token', s.token, 'id', t.id, 'data', t.data, 'version', t.version, 'updated_at', t.updated_at)), '[]'::jsonb)
  from tripdivider_sessions s join tripdivider_trips t on t.id = s.trip_id
  where s.token = any(p_tokens[1:200]);
$$;

-- Save → {ok:true, version} | {ok:false, conflict:true} | {ok:false, signed_out:true}
-- Only succeeds if p_version matches, so two phones editing at once never overwrite each other.
create or replace function public.td_save_trip(p_token uuid, p_data jsonb, p_version int)
returns jsonb language plpgsql security definer set search_path = public as $$
declare tid uuid; v int;
begin
  if octet_length(p_data::text) > 1000000 then raise exception 'Trip is too large'; end if;
  select trip_id into tid from tripdivider_sessions where token = p_token;
  if tid is null then return jsonb_build_object('ok', false, 'signed_out', true); end if;
  update tripdivider_trips
     set data = jsonb_set(p_data, '{name}', to_jsonb(name)), version = version + 1, updated_at = now()
   where id = tid and version = p_version
  returning version into v;
  if v is null then return jsonb_build_object('ok', false, 'conflict', true); end if;
  return jsonb_build_object('ok', true, 'version', v);
end;
$$;

-- Change password (needs the current one) → {ok, token} | {ok:false, error:'wrong'|'weak_password'|'signed_out'}
-- Signs out every other phone; this phone gets a fresh token.
create or replace function public.td_change_password(p_token uuid, p_old text, p_new text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare t tripdivider_trips; tok uuid;
begin
  select tr.* into t from tripdivider_sessions s join tripdivider_trips tr on tr.id = s.trip_id where s.token = p_token;
  if not found then return jsonb_build_object('ok', false, 'error', 'signed_out'); end if;
  if t.pass_hash <> crypt(coalesce(p_old, ''), t.pass_hash) then return jsonb_build_object('ok', false, 'error', 'wrong'); end if;
  if length(coalesce(p_new, '')) < 6 then return jsonb_build_object('ok', false, 'error', 'weak_password'); end if;
  update tripdivider_trips set pass_hash = crypt(p_new, gen_salt('bf', 10)) where id = t.id;
  delete from tripdivider_sessions where trip_id = t.id;
  insert into tripdivider_sessions (trip_id) values (t.id) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok);
end;
$$;

-- Sign this phone out of a trip
create or replace function public.td_leave_trip(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from tripdivider_sessions where token = p_token;
$$;

-- Delete a trip for everyone (needs the password again). The name stays reserved forever.
create or replace function public.td_delete_trip(p_token uuid, p_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare t tripdivider_trips;
begin
  select tr.* into t from tripdivider_sessions s join tripdivider_trips tr on tr.id = s.trip_id where s.token = p_token;
  if not found then return jsonb_build_object('ok', false, 'error', 'signed_out'); end if;
  if t.pass_hash <> crypt(coalesce(p_password, ''), t.pass_hash) then return jsonb_build_object('ok', false, 'error', 'wrong'); end if;
  delete from tripdivider_trips where id = t.id;
  return jsonb_build_object('ok', true);
end;
$$;

-- Only the functions above are callable from the page (touches TripDivider's functions only)
revoke execute on function public.td_name_key(text)                    from public, anon, authenticated;
revoke execute on function public.td_create_trip(text, text, jsonb)    from public;
revoke execute on function public.td_join_trip(text, text)             from public;
revoke execute on function public.td_get_trip(uuid)                    from public;
revoke execute on function public.td_get_trips(uuid[])                 from public;
revoke execute on function public.td_save_trip(uuid, jsonb, int)       from public;
revoke execute on function public.td_change_password(uuid, text, text) from public;
revoke execute on function public.td_leave_trip(uuid)                  from public;
revoke execute on function public.td_delete_trip(uuid, text)           from public;
grant execute on function public.td_create_trip(text, text, jsonb)     to anon, authenticated;
grant execute on function public.td_join_trip(text, text)              to anon, authenticated;
grant execute on function public.td_get_trip(uuid)                     to anon, authenticated;
grant execute on function public.td_get_trips(uuid[])                  to anon, authenticated;
grant execute on function public.td_save_trip(uuid, jsonb, int)        to anon, authenticated;
grant execute on function public.td_change_password(uuid, text, text)  to anon, authenticated;
grant execute on function public.td_leave_trip(uuid)                   to anon, authenticated;
grant execute on function public.td_delete_trip(uuid, text)            to anon, authenticated;
