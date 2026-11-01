-- Run as database owner after reset_and_secure.sql. Bootstrap only when the
-- sole active mapped member is the owner; never put passwords here.
-- This migration preserves all existing app data and memberships.
begin;
create table public.askback_owner (
  singleton boolean primary key default true check (singleton),
  user_id uuid not null unique references auth.users(id) on delete restrict
);
alter table public.askback_owner enable row level security;
revoke all on public.askback_owner from public, anon, authenticated;
-- Refuse to guess an owner in a project with multiple active members.
do $$ begin
  if (select count(*) from public.askback_access a join public.members m on m.id=a.member_id where m.active) <> 1 then
    raise exception 'Expected one active mapped member; designate the owner explicitly before applying';
  end if;
  insert into public.askback_owner (user_id)
    select a.user_id from public.askback_access a join public.members m on m.id=a.member_id where m.active;
end $$;
do $$ begin
  if not exists (select 1 from public.askback_owner o join public.askback_access a on a.user_id=o.user_id join public.members m on m.id=a.member_id join auth.users u on u.id=o.user_id where m.active and u.email_confirmed_at is not null) then
    raise exception 'The designated owner must already be a confirmed active member';
  end if;
end $$;

create table public.askback_join_requests (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 60),
  status text not null check (status in ('pending','approved','rejected','removed')),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);
alter table public.askback_join_requests enable row level security;
revoke all on public.askback_join_requests from public, anon, authenticated;

create function public.askback_session_valid() returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from auth.users u join auth.sessions s on s.user_id=u.id
    where u.id=auth.uid() and u.email_confirmed_at is not null
      and s.id::text=auth.jwt()->>'session_id')
$$;
create function public.askback_is_owner() returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select public.askback_session_valid() and exists (
    select 1 from public.askback_owner o join public.askback_access a on a.user_id=o.user_id
    join public.members m on m.id=a.member_id where o.user_id=auth.uid() and m.active)
$$;
create function public.askback_request_status() returns text language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.askback_session_valid() then raise exception 'A confirmed active session is required' using errcode='42501'; end if;
  if exists (select 1 from public.askback_access a join public.members m on m.id=a.member_id where a.user_id=auth.uid() and m.active) then return 'approved'; end if;
  return coalesce((select r.status from public.askback_join_requests r where r.user_id=auth.uid()), 'none');
end $$;
create function public.askback_submit_join_request(display_name text) returns text language plpgsql security definer set search_path = pg_catalog as $$
declare clean_name text := btrim(display_name);
begin
  if not public.askback_session_valid() then raise exception 'A confirmed active session is required' using errcode='42501'; end if;
  if clean_name is null or char_length(clean_name) < 1 or char_length(clean_name) > 60 or clean_name ~ '[[:cntrl:]]' or lower(clean_name) in ('__proto__','constructor','prototype') then raise exception 'Enter a valid display name (1–60 characters)'; end if;
  if exists (select 1 from public.askback_access where user_id=auth.uid()) then raise exception 'This account is already a member'; end if;
  insert into public.askback_join_requests (user_id, display_name, status) values (auth.uid(), clean_name, 'pending') on conflict (user_id) do nothing;
  return (select status from public.askback_join_requests where user_id=auth.uid());
end $$;
create function public.askback_pending_requests() returns table(user_id uuid, display_name text, email text, requested_at timestamptz) language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.askback_is_owner() then raise exception 'Owner access required' using errcode='42501'; end if;
  return query select r.user_id, r.display_name, u.email::text, r.created_at from public.askback_join_requests r join auth.users u on u.id=r.user_id where r.status='pending' order by r.created_at;
end $$;
create function public.askback_managed_members() returns table(user_id uuid, display_name text, email text) language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.askback_is_owner() then raise exception 'Owner access required' using errcode='42501'; end if;
  return query select a.user_id, m.name::text, u.email::text from public.askback_access a join public.members m on m.id=a.member_id join auth.users u on u.id=a.user_id where m.active and not exists (select 1 from public.askback_owner o where o.user_id=a.user_id) order by m.name;
end $$;
create function public.askback_decide_request(applicant uuid, approve boolean) returns void language plpgsql security definer set search_path = pg_catalog as $$
declare req public.askback_join_requests%rowtype; group_id_value public.groups.id%type; member_id_value public.members.id%type;
begin
  if not public.askback_is_owner() then raise exception 'Owner access required' using errcode='42501'; end if;
  if approve is null then raise exception 'Decision required'; end if;
  select * into req from public.askback_join_requests r where r.user_id=applicant for update;
  if not found or req.status <> 'pending' then raise exception 'Request is no longer pending'; end if;
  if exists (select 1 from public.askback_owner where user_id=applicant) then raise exception 'Cannot change owner access'; end if;
  if approve then
    if not exists (select 1 from auth.users u where u.id=applicant and u.email_confirmed_at is not null) then raise exception 'Applicant email is not confirmed'; end if;
    select id into strict group_id_value from public.groups where name='AskBack Study Group';
    if exists (select 1 from public.members m where m.group_id=group_id_value and lower(m.name)=lower(req.display_name)) then raise exception 'A member already uses that display name'; end if;
    insert into public.members (group_id, name, active) values (group_id_value, req.display_name, true) returning id into member_id_value;
    insert into public.askback_access (user_id, member_id) values (applicant, member_id_value);
    update public.askback_join_requests set status='approved', decided_at=now() where user_id=applicant;
  else
    delete from public.askback_access where user_id=applicant;
    delete from auth.sessions where user_id=applicant;
    update public.askback_join_requests set status='rejected', decided_at=now() where user_id=applicant;
  end if;
end $$;
create function public.askback_remove_member(target uuid) returns void language plpgsql security definer set search_path = pg_catalog as $$
declare member_id_value public.members.id%type; member_name text;
begin
  if not public.askback_is_owner() then raise exception 'Owner access required' using errcode='42501'; end if;
  if exists (select 1 from public.askback_owner where user_id=target) then raise exception 'Cannot remove the owner'; end if;
  select a.member_id, m.name into member_id_value, member_name from public.askback_access a join public.members m on m.id=a.member_id where a.user_id=target for update of a;
  if not found then raise exception 'Member has already been removed'; end if;
  delete from public.askback_access where user_id=target;
  update public.members set active=false where id=member_id_value;
  delete from auth.sessions where user_id=target;
  insert into public.askback_join_requests(user_id, display_name, status, decided_at) values (target, member_name, 'removed', now())
    on conflict (user_id) do update set status='removed', decided_at=now();
end $$;
revoke all on function public.askback_session_valid(), public.askback_is_owner(), public.askback_request_status(), public.askback_submit_join_request(text), public.askback_pending_requests(), public.askback_managed_members(), public.askback_decide_request(uuid,boolean), public.askback_remove_member(uuid) from public, anon;
grant execute on function public.askback_session_valid(), public.askback_is_owner(), public.askback_request_status(), public.askback_submit_join_request(text), public.askback_pending_requests(), public.askback_managed_members(), public.askback_decide_request(uuid,boolean), public.askback_remove_member(uuid) to authenticated;
commit;
