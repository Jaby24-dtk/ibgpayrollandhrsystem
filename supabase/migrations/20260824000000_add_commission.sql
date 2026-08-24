-- Sales employees earn commission on top of basic salary/allowances, but
-- there was no column to record it, so payslips could never show a
-- Commission line. Additive, defaults to 0 for all existing rows.

alter table payroll add column if not exists commission numeric not null default 0;
