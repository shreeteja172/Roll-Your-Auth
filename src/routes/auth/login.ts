import { Router } from "express";
import { db } from "../../prisma/db";
import { verifyPassword } from "../../auth/password";
import {
  generateSessionToken,
  hashSessionToken,
  getSessionExpiry,
} from "../../auth/session";
import { requireAuth } from "../../auth/requireAuth";
import { loginSchema } from "../../validation/auth";
import { sessionCookieOptions } from "../../auth/cookie";

const router: Router = Router();

router.post("/login", async (req, res) => {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid login data",
        errors: result.error.flatten().fieldErrors,
      });
    }

    const { email, password } = result.data;

    const publicDb = db.orm.public;
    if (!publicDb?.User || !publicDb?.Session) {
      throw new Error("Public database client is unavailable");
    }
    const user = await publicDb.User.where({ email }).first();

    if (!user || typeof user.passwordHash !== "string") {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const passwordMatch = await verifyPassword(password, user.passwordHash);

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    if (!user.emailVerified) {
      return res.status(403).json({
        message: "Please verify your email before logging in",
      });
    }

    // cryptographically secure session token forr the user
    const sessionToken = generateSessionToken();

    // store only the hash in the db
    const tokenHash = hashSessionToken(sessionToken);

    // session expires in 7 days
    const expiresAt = getSessionExpiry();

    const session = await db.orm.public!.Session!.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        lastUsedAt: new Date(),
      },
    });

    res.cookie("session", sessionToken, {
      ...sessionCookieOptions,
      expires: new Date(expiresAt),
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;

router.get("/test-auth", requireAuth, (req, res) => {
  const authenticatedRequest = req as typeof req & {
    user: {
      id: string;
      email: string;
    };
    session: {
      id: string;
      userId: string;
      expiresAt: unknown;
    };
  };

  return res.status(200).json({
    message: "Authentication works!",
    user: authenticatedRequest.user,
  });
});
