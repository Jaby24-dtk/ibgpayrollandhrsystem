-- Adds a read-only 'viewer' role: full company-wide SELECT access on
-- employees/attendance/leaves/claims/payroll, matching admin's read scope,
-- with zero write path. Purely additive — does not touch existing
-- admin (is_admin()) or per-employee policies, since Postgres RLS
-- policies are permissive (OR'd together).

create or replace function is_viewer()
returns boolean
language sql
security definer
as $$
  select exists (
    select 1 from employees
    where user_id = auth.uid() and role = 'viewer'
  );
$$;

create policy "Viewer reads all employees" on employees for select using (is_viewer());
create policy "Viewer reads all attendance" on attendance for select using (is_viewer());
create policy "Viewer reads all leaves" on leaves for select using (is_viewer());
create policy "Viewer reads all claims" on claims for select using (is_viewer());
create policy "Viewer reads all payroll" on payroll for select using (is_viewer());
