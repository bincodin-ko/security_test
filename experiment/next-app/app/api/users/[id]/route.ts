// App Router route handler with dynamic segment
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await db.users.findById(params.id);
  return Response.json(user); // no ownership check
}
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.users.delete(params.id);
  return Response.json({ ok: true });
}
