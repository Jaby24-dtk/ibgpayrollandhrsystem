-- Link a sign-up to its employee record only after the email is confirmed
-- (security fix, 2026-11-06)
--
-- Problem: on_auth_user_created linked employees.user_id at sign-up time,
-- before the email was confirmed. Anyone who knew an unregistered employee's
-- email could sign up first and claim that record; they could not log in, but
-- the real employee could no longer register. (Checked 2026-11-06: 0 records
-- linked to unconfirmed accounts — not exploited.)
--
-- Fix: link only when the account has a confirmed email — on insert (if the
-- provider confirms immediately) or when email_confirmed_at is first set.

create or replace function public.link_employee_on_login() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.email_confirmed_at is not null then
    begin
      update public.employees set user_id = new.id
      where lower(email) = lower(new.email) and user_id is null;
    exception when others then null; -- never block sign-up
    end;
  end if;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert or update of email_confirmed_at on auth.users
  for each row execute function public.link_employee_on_login();

revoke execute on function public.link_employee_on_login() from public, anon, authenticated;
