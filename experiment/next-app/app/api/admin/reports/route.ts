export async function GET() {
  return Response.json(await db.reports.all()); // no role check
}
