import { Router } from "express";
import { requireAuth } from "../../auth/requireAuth";
import { db } from "../../prisma/db";

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
router.delete("/sessions/:id", requireAuth, async (req, res) => {
  const userId = req.user!.id;
  const sessionId = req.params.id;

  const deleted = await db.orm
    .public!.Session!.where({
      id: sessionId,
      userId,
    })
    .delete();

  if (!deleted) {
    return res.status(404).json({
      message: "Session not found",
    });
  }

  return res.json({
    message: "Session revoked successfully",
  });
});

export default router;
