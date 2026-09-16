import { Router } from "express";
import { cleanupExpiredSessions } from "../../auth/cleanupSessions";

const router: Router = Router();

router.delete("/sessions/expired", async (req, res) => {
  try {
    await cleanupExpiredSessions();

    return res.status(200).json({
      message: "Expired sessions cleaned up",
    });
  } catch (error) {
    console.error("Session cleanup error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
