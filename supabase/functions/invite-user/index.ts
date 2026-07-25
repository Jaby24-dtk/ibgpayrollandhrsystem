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

  let body: { email?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: 'A valid email is required' }, 400);
  }

  // Service-role client — only place the secret key is used, never returned to caller.
  const adminClient = createClient(supabaseUrl, serviceKey);
  const { error: inviteErr } = await adminClient.auth.admin.inviteUserByEmail(email, {
    redirectTo: ALLOWED_ORIGIN + '/',
  });

  if (inviteErr) return json({ error: inviteErr.message }, 400);
  return json({ ok: true });
});
