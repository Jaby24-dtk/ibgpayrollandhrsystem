-- Per-employee pay frequency (monthly end/start, or semi-monthly) and the
-- corresponding payroll period key. Both additive with safe defaults —
-- existing employees default to monthly_end (today's only behavior),
-- existing payroll rows default to period='full' (unaffected).

alter table employees add column pay_frequency text not null default 'monthly_end';
alter table payroll add column period text not null default 'full';
