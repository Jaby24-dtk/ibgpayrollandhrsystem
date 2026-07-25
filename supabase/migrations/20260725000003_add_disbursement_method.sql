-- Records HOW a payroll was actually released (Wise vs manual bank
-- transfer/cash/e-wallet), so bank-channel employees aren't forced through
-- Wise when the admin actually paid them another way. Nullable/additive.

alter table payroll add column disbursement_method text;
alter table payroll add column disbursement_note text;
