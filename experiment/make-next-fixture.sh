#!/bin/bash
# Regenerates the Next.js test fixture locally. The [id] bracket directories
# are NOT committed because they break zip extraction on Windows
# ("invalid characters"). Run this before the Next integration discovery test.
set -e
root="$(dirname "$0")/next-app"
mkdir -p "$root/app/api/users/[id]" "$root/app/api/admin/reports" "$root/app/api/health" "$root/pages/api/legacy"

cat > "$root/app/api/users/[id]/route.ts" <<'TS'
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await db.users.findById(params.id);
  return Response.json(user); // no ownership check
}
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.users.delete(params.id);
  return Response.json({ ok: true });
}
TS
cat > "$root/app/api/users/[id]/actions.ts" <<'TS'
'use server';
export async function updateProfile(formData: FormData) { /* ... */ }
TS
cat > "$root/app/api/admin/reports/route.ts" <<'TS'
export async function GET() { return Response.json(await db.reports.all()); }
TS
cat > "$root/app/api/health/route.ts" <<'TS'
export async function GET() { return Response.json({ ok: true }); }
TS
cat > "$root/pages/api/legacy/login.ts" <<'TS'
export default function handler(req, res) { res.json({ token: 'x' }); }
TS
cat > "$root/pages/api/webhook.ts" <<'TS'
export default function handler(req, res) { res.json({ received: true }); }
TS
echo "next-app fixture regenerated at $root"
