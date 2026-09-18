import { Router } from "express";
import { db } from "../../prisma/db";
import { verifyOtp } from "../../utils/otp";
import { hashPassword } from "../../auth/password";
import { resetPasswordSchema } from "../../validation/auth";

const router: Router = Router();

router.post("/reset-password", async (req, res) => {
  try {
    const result = resetPasswordSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid password reset data",
        errors: result.error.flatten().fieldErrors,
      });
    }

    const { email, code, newPassword } = result.data;

    const publicDb = db.orm.public;

    if (!publicDb?.User || !publicDb?.Otp || !publicDb?.Session) {
      throw new Error("Public database client is unavailable");
    }

    const user = await publicDb.User.first({ email });

    if (!user) {
      return res.status(400).json({
        message: "Invalid password reset request",
      });
    }

    const otps = await publicDb.Otp.where({
      userId: user.id,
      purpose: "PASSWORD_RESET",
    }).all();

    const latestOtp = otps
      .filter((otp) => !otp.consumedAt)
      .sort(
        (a, b) =>
          new Date(String(b.createdAt)).getTime() -
          new Date(String(a.createdAt)).getTime(),
      )[0];

    if (!latestOtp) {
      return res.status(400).json({
        message: "No active password reset OTP found",
      });
    }

    if (new Date(String(latestOtp.expiresAt)).getTime() <= Date.now()) {
      await publicDb.Otp.where({ id: latestOtp.id }).update({
        consumedAt: new Date(),
      });

      return res.status(400).json({
        message: "OTP has expired",
      });
    }
    if (Number(latestOtp.attempts) >= 5) {
      await publicDb.Otp.where({ id: latestOtp.id }).update({
        consumedAt: new Date(),
      });

      return res.status(400).json({
        message: "Too many invalid OTP attempts",
      });
    }

    if (Number(latestOtp.attempts) >= 5) {
      await publicDb.Otp.where({ id: latestOtp.id }).update({
        consumedAt: new Date(),
      });

      return res.status(400).json({
        message: "Too many invalid OTP attempts",
      });
    }

    const valid = await verifyOtp(String(code), String(latestOtp.codeHash));

    if (!valid) {
      const newAttempts = Number(latestOtp.attempts) + 1;

      await publicDb.Otp.where({ id: latestOtp.id }).update({
        attempts: newAttempts,
        ...(newAttempts >= 5 ? { consumedAt: new Date() } : {}),
      });

      return res.status(400).json({
        message:
          newAttempts >= 5 ? "Too many invalid OTP attempts" : "Invalid OTP",
      });
    }

    const passwordHash = await hashPassword(newPassword);

    await publicDb.User.where({ id: user.id }).update({
      passwordHash,
    });

    await publicDb.Otp.where({ id: latestOtp.id }).update({
      consumedAt: new Date(),
    });

    await publicDb.Session.where({ userId: user.id }).delete();

    return res.status(200).json({
      message: "Password reset successfully",
    });
  } catch (error) {
    console.error("Reset password error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
