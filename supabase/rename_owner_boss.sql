-- Rename only the mapped owner profile; the account and permissions are unchanged.
-- Safe to rerun if the profile has already been renamed.
update public.members m
set name = 'Boss'
from public.askback_access a
join public.askback_owner o on o.user_id = a.user_id
where m.id = a.member_id and m.name = 'Owner';
