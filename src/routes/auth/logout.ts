import { Router } from "express";
import { db } from "../../prisma/db";
import { hashSessionToken } from "../../auth/session";

const router: Router = Router();

router.post("/logout", async (req, res) => {
  try {
    const sessionToken = req.cookies?.session;

    if (sessionToken) {
      const tokenHash = hashSessionToken(sessionToken);

      await db.orm.public!.Session!.where({ tokenHash }).delete();
    }

    res.clearCookie("session", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    return res.status(200).json({
      message: "Logout successful",
    });
  } catch (error) {
    console.error("Logout error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
