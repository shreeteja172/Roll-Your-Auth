import { db } from "../prisma/db";

export async function cleanupOtps() {
  const publicDb = db.orm.public;

  if (!publicDb?.Otp) {
    throw new Error("Public database client is unavailable");
  }

  const otps = await publicDb.Otp.all();

  const now = Date.now();

  for (const otp of otps) {
    const expired = new Date(String(otp.expiresAt)).getTime() <= now;

    const consumed = Boolean(otp.consumedAt);

    if (expired || consumed) {
      await publicDb.Otp.where({ id: otp.id }).delete();
    }
  }
}
