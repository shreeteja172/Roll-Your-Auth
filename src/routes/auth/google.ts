import { Router } from "express";
import axios from "axios";
import crypto from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { db } from "../../prisma/db";
import {
  generateSessionToken,
  hashSessionToken,
  getSessionExpiry,
} from "../../auth/session";
import { sessionCookieOptions } from "../../auth/cookie";

const router: Router = Router();

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI!;

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);

router.get("/google", (_req, res) => {
  const state = crypto.randomBytes(32).toString("hex");

  res.cookie("oauth_state", state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 10 * 60 * 1000,
  });

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state,
  });

  return res.redirect(`${GOOGLE_AUTH_URL}?${params.toString()}`);
});

router.get("/google/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (typeof code !== "string" || typeof state !== "string") {
      return res.status(400).json({
        message: "Invalid OAuth callback",
      });
    }

    const savedState = req.cookies.oauth_state;

    if (!savedState || savedState !== state) {
      return res.status(400).json({
        message: "Invalid OAuth state",
      });
    }

    res.clearCookie("oauth_state");

    const tokenResponse = await axios.post(
      GOOGLE_TOKEN_URL,
      new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );

    const tokens = tokenResponse.data;

    if (typeof tokens.id_token !== "string") {
      return res.status(401).json({
        message: "Google did not return an ID token",
      });
    }

    const { payload } = await jwtVerify(tokens.id_token, GOOGLE_JWKS, {
      issuer: "https://accounts.google.com",
      audience: GOOGLE_CLIENT_ID,
    });

    const googleId = payload.sub;
    const email = payload.email;
    const emailVerified = payload.email_verified;

    if (
      typeof googleId !== "string" ||
      typeof email !== "string" ||
      emailVerified !== true
    ) {
      return res.status(401).json({
        message: "Invalid Google account",
      });
    }

    const publicDb = db.orm.public;

    if (!publicDb?.User || !publicDb?.OAuthAccount || !publicDb?.Session) {
      throw new Error("Public database client is unavailable");
    }

    let oauthAccount = await publicDb.OAuthAccount.where({
      provider: "google",
      providerAccountId: googleId,
    }).first();

    let user;

    if (oauthAccount) {
      user = await publicDb.User.where({ id: oauthAccount.userId }).first();

      if (!user) {
        return res.status(401).json({
          message: "OAuth account is not linked to a valid user",
        });
      }
    } else {
      user = await publicDb.User.where({ email }).first();

      if (!user) {
        user = await publicDb.User.create({
          email,
          emailVerified: true,
          passwordHash: null,
        });
      } else if (!user.emailVerified) {
        await publicDb.User.where({ id: user.id }).update({
          emailVerified: true,
        });
      }

      oauthAccount = await publicDb.OAuthAccount.create({
        userId: user.id,
        provider: "google",
        providerAccountId: googleId,
      });
    }

    const sessionToken = generateSessionToken();
    const tokenHash = hashSessionToken(sessionToken);
    const expiresAt = getSessionExpiry();

    await publicDb.Session.create({
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
      message: "Google login successful",
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Google OAuth error:", error);

    return res.status(500).json({
      message: "Google authentication failed",
    });
  }
});

export default router;
