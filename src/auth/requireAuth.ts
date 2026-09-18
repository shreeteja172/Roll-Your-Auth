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
    // console.log("SESSION TOKEN:", sessionToken);
    if (!sessionToken || typeof sessionToken !== "string") {
      return res.status(401).json({
        message: "Not authenticated",
      });
    }

    const tokenHash = hashSessionToken(sessionToken);
    // console.log("HASHED TOKEN:", tokenHash);

    const session = await db.orm.public!.Session!.where({ tokenHash }).first();
    // console.log("SESSION:", session);

    if (!session) {
      return res.status(401).json({
        message: "Invalid session",
      });
    }

    if (new Date(session.expiresAt as string | number | Date) <= new Date()) {
      await db.orm.public!.Session!.where({ id: session.id }).delete();

      return res.status(401).json({
        message: "Session expired",
      });
    }

    const user = await db.orm
      .public!.User!.where({ id: session.userId })
      .first();

    if (!user) {
      await db.orm.public!.Session!.where({ id: session.id }).delete();

      return res.status(401).json({
        message: "Authentication required",
      });
    }

    if (typeof user.id !== "string" || typeof user.email !== "string") {
      return res.status(500).json({
        message: "Invalid user data",
      });
    }

    const now = new Date();

    const lastUsedAt = session.lastUsedAt
      ? new Date(session.lastUsedAt as string | number | Date)
      : null;

    const shouldUpdateLastUsed =
      !lastUsedAt || now.getTime() - lastUsedAt.getTime() >= 5 * 60 * 1000;

    if (shouldUpdateLastUsed) {
      await db.orm.public!.Session!.where({ id: session.id }).update({
        lastUsedAt: now,
      });
    }
    req.user = {
      id: user.id,
      email: user.email,
    };

    req.session = {
      id: String(session.id),
      userId: String(session.userId),
      tokenHash: String(session.tokenHash),
      expiresAt: session.expiresAt as string | Date,
    };
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
