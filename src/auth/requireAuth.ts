import type { Request, Response, NextFunction } from "express";
import { db } from "../prisma/db";
import { hashSessionToken } from "./session";

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const sessionToken = req.cookies?.session;
    console.log("SESSION TOKEN:", sessionToken);
    if (!sessionToken) {
      return res.status(401).json({
        message: "Not authenticated",
      });
    }

    const tokenHash = hashSessionToken(sessionToken);
    console.log("HASHED TOKEN:", tokenHash);

    const session = await db.orm.public!.Session!.where({ tokenHash }).first();
    console.log("SESSION:", session);

    if (!session) {
      return res.status(401).json({
        message: "Invalid session",
      });
    }

    if (new Date(session.expiresAt as string | number | Date) <= new Date()) {
      return res.status(401).json({
        message: "Session expired",
      });
    }

    const user = await db.orm
      .public!.User!.where({ id: session.userId })
      .first();

    if (!user) {
      return res.status(401).json({
        message: "User not found",
      });
    }

    const authenticatedRequest = req as Request & {
      user: {
        id: typeof user.id;
        email: typeof user.email;
      };
      session: typeof session;
    };

    authenticatedRequest.user = {
      id: user.id,
      email: user.email,
    };

    authenticatedRequest.session = session;

    next();
  } catch (error) {
    console.error("Auth middleware error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}


