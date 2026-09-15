import { Router } from "express";
import { db } from "../../prisma/db";
import { requireAuth } from "../../auth/requireAuth";

const router: Router = Router();
// console.log("LOGOUT-ALL ROUTER LOADED");
router.post("/logout-all", requireAuth, async (req, res) => {
  try {
    const user = req.user;

    if (!user) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    const userId = user.id;

    await db.orm.public!.Session!.where({ userId }).delete();

    res.clearCookie("session", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    return res.status(200).json({
      message: "Logged out from all devices",
    });
  } catch (error) {
    console.error("Logout all error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});


export default router;
