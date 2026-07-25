-- The employee self-service write policies (file own leave/claim, log own
-- attendance) only checked that emp_id belongs to the caller's own employee
-- record — they never checked role. Since a viewer has their own employees
-- row too, this let a viewer bypass the UI-hidden buttons and write via a
-- direct API call. Tighten each policy to exclude viewer explicitly.

alter policy "Employee inserts own attendance" on attendance
  with check (
    emp_id = (select employees.id from employees where employees.user_id = auth.uid())
    and not is_viewer()
  );

alter policy "Employee updates own attendance" on attendance
  using (
    emp_id = (select employees.id from employees where employees.user_id = auth.uid())
    and not is_viewer()
  );

alter policy "Employee files own claim" on claims
  with check (
    emp_id in (select employees.id from employees where employees.user_id = auth.uid())
    and not is_viewer()
  );

alter policy "Employee files own leave" on leaves
  with check (
    emp_id in (select employees.id from employees where employees.user_id = auth.uid())
    and not is_viewer()
  );
