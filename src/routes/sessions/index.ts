import { Router } from "express";
import { requireAuth } from "../../auth/requireAuth";
import { db } from "../../prisma/db";
import { hashSessionToken } from "../../auth/session";

const router: Router = Router();

router.get("/sessions", requireAuth, async (req, res) => {
  const userId = req.user!.id;

  const sessions = await db.orm.public!.Session!.where({ userId }).all();

  res.json({
    sessions: sessions.map((session) => ({
      id: session.id,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
    })),
  });
});

router.delete("/sessions/:id", requireAuth, async (req, res) => {
  const userId = req.user!.id;
  const sessionId = req.params.id;

  const deleted = await db.orm
    .public!.Session!.where({
      id: sessionId,
      userId,
    })
    .delete();

  res.json({
    message: "Session revoked successfully",
  });
});

router.delete("/sessions/others", requireAuth, async (req, res) => {
  const userId = req.user!.id;
  const currentToken = req.cookies.session;
  const currentTokenHash = hashSessionToken(currentToken);

  if (!currentTokenHash) {
    return res.status(400).json({
      message: "Invalid session token",
    });
  }

  const sessions = await db.orm
    .public!.Session!.where({
      userId,
    })
    .all();

  for (const session of sessions) {
    if (session.tokenHash !== currentTokenHash) {
      await db.orm
        .public!.Session!.where({
          id: session.id,
        })
        .delete();
    }
  }

  return res.json({
    message: "Other sessions revoked successfully",
  });
});

export default router;
