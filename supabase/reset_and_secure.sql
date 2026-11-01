-- ONE-TIME, DESTRUCTIVE migration. Read SECURITY-RESET.md first.
-- Run as the project database owner in the Supabase SQL editor, in one execution.
-- Replace NULL below with the UUID of the NEW confirmed owner Auth user, e.g.
-- '00000000-0000-0000-0000-000000000000'::uuid. Never put a password here.
-- This transaction intentionally aborts on an unfamiliar schema. Do not bypass
-- its checks until all related data, permissions, triggers and functions are audited.

begin;
create temporary table askback_reset_config (owner_id uuid, owner_name text not null) on commit drop;
insert into askback_reset_config values (NULL, 'Owner');

do $$
declare unknown_tables text; unexpected_fks text; group_count integer; owner_uuid uuid;
begin
  select owner_id into owner_uuid from askback_reset_config;
  if not exists (select 1 from auth.users where id = owner_uuid and email_confirmed_at is not null and encrypted_password is not null and encrypted_password <> '') then
    raise exception 'Create and confirm the new owner Auth user first, and set owner_id in the script.';
  end if;
  select count(*) into group_count from public.groups where name = 'AskBack Study Group';
  if group_count <> 1 then raise exception 'Expected exactly one AskBack Study Group; inspect schema/data before continuing.'; end if;
  if to_regclass('public.askback_access') is not null then
    raise exception 'askback_access already exists; this is a one-time reset, not a repeatable migration.';
  end if;
  -- Unknown tables might contain history or be affected by CASCADE. Fail closed.
  select string_agg(quote_ident(c.relname), ', ') into unknown_tables
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p')
      and c.relname not in ('groups', 'subjects', 'members', 'goals', 'questions', 'question_subjects', 'study_logs');
  if unknown_tables is not null then raise exception 'Unreviewed public tables: %. Audit and adapt this migration first.', unknown_tables; end if;
  select string_agg(format('%s -> %s', conrelid::regclass, confrelid::regclass), ', ') into unexpected_fks
    from pg_constraint where contype = 'f'
      and confrelid in (select oid from pg_class where relnamespace = 'public'::regnamespace and relname in ('members','goals','questions','question_subjects','study_logs'))
      and conrelid not in (select oid from pg_class where relnamespace = 'public'::regnamespace and relname in ('members','goals','questions','question_subjects','study_logs'));
  if unexpected_fks is not null then raise exception 'Unreviewed foreign-key dependencies: %', unexpected_fks; end if;
end $$;

-- Remove every legacy public-table privilege and RLS policy before granting a
-- narrow set below. Existing open/permissive policies must not be combined.
revoke all privileges on all tables in schema public from public, anon, authenticated;
revoke all privileges on all sequences in schema public from public, anon, authenticated;
do $$
declare policy_row record; f record;
begin
  for policy_row in select schemaname, tablename, policyname from pg_policies where schemaname = 'public' loop
    execute format('drop policy %I on %I.%I', policy_row.policyname, policy_row.schemaname, policy_row.tablename);
  end loop;
  -- Remove client execution of legacy public functions (except extension-owned
  -- functions); otherwise an old SECURITY DEFINER function could bypass RLS.
  for f in select p.oid::regprocedure as signature from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prokind in ('f','p')
      and not exists (select 1 from pg_depend d where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')
  loop execute format('revoke all on routine %s from public, anon, authenticated', f.signature); end loop;
end $$;

-- No CASCADE: unexpected dependencies must fail the transaction rather than
-- silently delete unrelated configuration. Includes inactive former members.
do $$
begin
  if to_regclass('public.study_logs') is not null then
    execute 'truncate table public.question_subjects, public.questions, public.goals, public.study_logs, public.members restart identity';
  else
    execute 'truncate table public.question_subjects, public.questions, public.goals, public.members restart identity';
  end if;
end $$;

-- Derive member_id's type from the existing schema rather than assuming UUID.
create table public.askback_access as select id as member_id from public.members with no data;
alter table public.askback_access alter column member_id set not null;
alter table public.askback_access add column user_id uuid not null primary key references auth.users(id) on delete cascade;
alter table public.askback_access add constraint askback_access_member_unique unique (member_id);
alter table public.askback_access add constraint askback_access_member_fk foreign key (member_id) references public.members(id) on delete cascade;
alter table public.askback_access enable row level security;
revoke all on public.askback_access from public, anon, authenticated;

do $$
declare owner_member public.members.id%type; group_id_value public.groups.id%type;
begin
  select id into strict group_id_value from public.groups where name = 'AskBack Study Group';
  insert into public.members (group_id, name, active)
    select group_id_value, owner_name, true from askback_reset_config returning id into owner_member;
  insert into public.askback_access (user_id, member_id)
    select owner_id, owner_member from askback_reset_config;
end $$;

-- These functions query the live authorization mapping, not JWT user metadata.
-- Revoking a mapping takes effect on the next database request even if the JWT
-- has not yet expired. They only expose the caller's own membership.
create function public.askback_current_member() returns table(name text)
language sql stable security definer set search_path = pg_catalog as $$
  select m.name::text from public.askback_access a join public.members m on m.id = a.member_id
  where a.user_id = auth.uid() and m.active = true
    and exists (select 1 from auth.sessions sess where sess.id::text = auth.jwt()->>'session_id' and sess.user_id = a.user_id)
$$;
create function public.askback_own_member(member text) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.askback_access a join public.members m on m.id = a.member_id
    where a.user_id = auth.uid() and m.active = true and m.id::text = $1
      and exists (select 1 from auth.sessions sess where sess.id::text = auth.jwt()->>'session_id' and sess.user_id = a.user_id))
$$;
create function public.askback_in_group(group_id text) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.askback_access a join public.members m on m.id = a.member_id
    where a.user_id = auth.uid() and m.active = true and m.group_id::text = $1
      and exists (select 1 from auth.sessions sess where sess.id::text = auth.jwt()->>'session_id' and sess.user_id = a.user_id))
$$;
revoke all on function public.askback_current_member() from public, anon;
revoke all on function public.askback_own_member(text) from public, anon;
revoke all on function public.askback_in_group(text) from public, anon;
grant execute on function public.askback_current_member(), public.askback_own_member(text), public.askback_in_group(text) to authenticated;

alter table public.groups enable row level security;
alter table public.subjects enable row level security;
alter table public.members enable row level security;
alter table public.goals enable row level security;
alter table public.questions enable row level security;
alter table public.question_subjects enable row level security;
-- If legacy study_logs exists it remains inaccessible until explicitly designed.
do $$ begin if to_regclass('public.study_logs') is not null then execute 'alter table public.study_logs enable row level security'; end if; end $$;

grant select on public.groups, public.subjects, public.members, public.goals, public.questions, public.question_subjects to authenticated;
grant insert, delete on public.goals to authenticated;
grant update (goal, completed) on public.goals to authenticated;
grant insert on public.questions, public.question_subjects to authenticated;
grant update (answer, status, answered_at) on public.questions to authenticated;
-- Identity/serial columns, if any, need sequence access for inserts.
grant usage, select on all sequences in schema public to authenticated;

create policy groups_read on public.groups for select to authenticated using (public.askback_in_group(id::text));
create policy subjects_read on public.subjects for select to authenticated using (public.askback_in_group(group_id::text));
create policy members_read on public.members for select to authenticated using (public.askback_in_group(group_id::text));
create policy goals_read on public.goals for select to authenticated using (public.askback_in_group(group_id::text));
create policy goals_insert on public.goals for insert to authenticated with check (public.askback_in_group(group_id::text) and public.askback_own_member(member_id::text));
create policy goals_update on public.goals for update to authenticated using (public.askback_own_member(member_id::text) and public.askback_in_group(group_id::text)) with check (public.askback_own_member(member_id::text) and public.askback_in_group(group_id::text));
create policy goals_delete on public.goals for delete to authenticated using (public.askback_own_member(member_id::text) and public.askback_in_group(group_id::text));
create policy questions_read on public.questions for select to authenticated using (public.askback_in_group(group_id::text) and (public.askback_own_member(creator_id::text) or public.askback_own_member(recipient_id::text)));
create policy questions_insert on public.questions for insert to authenticated with check (
  public.askback_in_group(group_id::text) and public.askback_own_member(creator_id::text)
  and exists (select 1 from public.members m where m.id = recipient_id and m.group_id = questions.group_id and m.active = true)
);
create policy questions_update on public.questions for update to authenticated using (public.askback_in_group(group_id::text) and public.askback_own_member(recipient_id::text)) with check (public.askback_in_group(group_id::text) and public.askback_own_member(recipient_id::text));
create policy question_subjects_read on public.question_subjects for select to authenticated using (exists (select 1 from public.questions q where q.id = question_subjects.question_id));
create policy question_subjects_insert on public.question_subjects for insert to authenticated with check (
  exists (select 1 from public.questions q join public.subjects s on s.id = question_subjects.subject_id and s.group_id = q.group_id
    where q.id = question_subjects.question_id and public.askback_own_member(q.creator_id::text))
);
commit;
