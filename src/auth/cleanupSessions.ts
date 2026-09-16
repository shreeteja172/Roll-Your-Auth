import { db } from "../prisma/db";

export async function cleanupExpiredSessions() {
  const sessions = await db.orm.public!.Session!.all();

  const now = new Date();

  for (const session of sessions) {
    const expiresAt = new Date(session.expiresAt as string | number | Date);

    if (expiresAt <= now) {
      await db.orm
        .public!.Session!.where({
          id: session.id,
        })
        .delete();
    }
  }
}
