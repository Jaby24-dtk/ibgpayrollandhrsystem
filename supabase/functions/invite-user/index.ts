// Admin-triggered invite: sends a Supabase Auth invite email so the recipient
// sets their own password. Caller must be authenticated AND have role='admin'
// in the employees table. Service role key never leaves this function.
import { createClient } from 'jsr:@supabase/supabase-js@2';

const ALLOWED_ORIGIN = 'https://payrollandhrsystem.ibgctasia.com';
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Headers': 'authorization, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  const authHeader = req.headers.get('Authorization');
  if (!authHeader) return json({ error: 'Missing Authorization header' }, 401);

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

  // Client scoped to the caller's own JWT — used only to verify identity + role.
  const callerClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });

  const { data: userData, error: userErr } = await callerClient.auth.getUser();
  if (userErr || !userData?.user) return json({ error: 'Invalid or expired session' }, 401);

  const { data: callerEmp, error: empErr } = await callerClient
    .from('employees')
    .select('role')
    .eq('user_id', userData.user.id)
    .maybeSingle();

  if (empErr) return json({ error: 'Could not verify caller role' }, 500);
  if (!callerEmp || callerEmp.role !== 'admin') return json({ error: 'Admin access required' }, 403);

  let body: { email?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: 'A valid email is required' }, 400);
  }
  const password = body.password;
  if (password !== undefined && password.length < 8) {
    return json({ error: 'Password must be at least 8 characters' }, 400);
  }

  // Service-role client — only place the secret key is used, never returned to caller.
  const adminClient = createClient(supabaseUrl, serviceKey);

  if (password) {
    // Set a password directly — no email sent, so this isn't subject to the
    // project's (often very low, free-tier) email-sending rate limit.
    const { error: createErr } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (!createErr) return json({ ok: true, mode: 'created' });

    const alreadyExists = /already.*registered|already.*exists/i.test(createErr.message);
    if (!alreadyExists) return json({ error: createErr.message }, 400);

    // Existing auth user for this email — update their password instead.
    const { data: list, error: listErr } = await adminClient.auth.admin.listUsers({ perPage: 1000 });
    if (listErr) return json({ error: listErr.message }, 500);
    const existing = list.users.find((u) => (u.email || '').toLowerCase() === email);
    if (!existing) return json({ error: 'Could not locate existing account for this email' }, 500);

    const { error: updateErr } = await adminClient.auth.admin.updateUserById(existing.id, {
      password,
      email_confirm: true,
    });
    if (updateErr) return json({ error: updateErr.message }, 400);
    return json({ ok: true, mode: 'updated' });
  }

  const { error: inviteErr } = await adminClient.auth.admin.inviteUserByEmail(email, {
    redirectTo: ALLOWED_ORIGIN + '/',
  });
  if (inviteErr) return json({ error: inviteErr.message }, 400);
  return json({ ok: true, mode: 'invited' });
});
