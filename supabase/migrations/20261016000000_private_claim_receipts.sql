-- Claim receipts are confidential (employee expenses, sometimes IDs/bank slips).
-- Make the bucket private and replace whatever ad-hoc policies it had with
-- explicit ones: employees upload/read only their own folder, admins and
-- viewers read everything. The app now opens receipts via 2-minute signed links.

insert into storage.buckets (id, name, public)
values ('claims-receipts', 'claims-receipts', false)
on conflict (id) do update set public = false;

-- Drop any earlier policies that mention this bucket (names were never tracked
-- in migrations, so match on the policy text).
do $$
declare p record;
begin
  for p in
    select policyname from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and (coalesce(qual, '') || coalesce(with_check, '')) like '%claims-receipts%'
  loop
    execute format('drop policy %I on storage.objects', p.policyname);
  end loop;
end $$;

-- Paths are receipts/<emp_id>/<file>.
create policy "Claim receipts: employee uploads own"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'claims-receipts'
    and (storage.foldername(name))[1] = 'receipts'
    and (storage.foldername(name))[2] in (select id::text from employees where user_id = auth.uid())
    and not is_viewer()
  );

create policy "Claim receipts: read own, admins and viewers read all"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'claims-receipts'
    and (
      is_admin()
      or is_viewer()
      or (storage.foldername(name))[2] in (select id::text from employees where user_id = auth.uid())
    )
  );
