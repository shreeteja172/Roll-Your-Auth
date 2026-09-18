import { Temporal } from "@js-temporal/polyfill";

globalThis.Temporal = Temporal as unknown as typeof globalThis.Temporal;

import express from "express";
import registerRouter from "./routes/auth/register";
import loginRouter from "./routes/auth/login";
import cookieParser from "cookie-parser";
import meRouter from "./routes/auth/me";
import logoutRouter from "./routes/auth/logout";
import logoutAllRouter from "./routes/auth/logout-all";
import sessionsRouter from "./routes/sessions";
import { cleanupExpiredSessions } from "./auth/cleanupSessions";
import verifyEmailRouter from "./routes/auth/verify-email";
import resendVerificationRouter from "./routes/auth/resend-verification";
import forgotPasswordRouter from "./routes/auth/forgot-password";
import resetPasswordRouter from "./routes/auth/reset-password";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/auth", registerRouter);
app.use("/auth", loginRouter);
app.use("/auth", meRouter);
app.use("/auth", logoutRouter);
app.use("/auth", logoutAllRouter);
app.use("/auth", sessionsRouter);
app.use("/auth", verifyEmailRouter);
app.use("/auth", resendVerificationRouter);
app.use("/auth", forgotPasswordRouter);
app.use("/auth", resetPasswordRouter);

app.listen(3000, async () => {
  console.log("Server running on port 3000");

  try {
    await cleanupExpiredSessions();
  } catch (error) {
    console.error("Initial session cleanup failed:", error);
  }
});

setInterval(
  async () => {
    try {
      await cleanupExpiredSessions();
    } catch (error) {
      console.error("Session cleanup failed:", error);
    }
  },
  60 * 60 * 1000,
);
