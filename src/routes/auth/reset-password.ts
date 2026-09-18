import { Router } from "express";
import { db } from "../../prisma/db";
import { verifyOtp } from "../../utils/otp";
import { hashPassword } from "../../auth/password";

const router: Router = Router();

router.post("/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({
        message: "Email, OTP and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters",
      });
    }

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
      .filter((otp: any) => !otp.consumedAt)
      .sort(
        (a: any, b: any) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      )[0];

    if (!latestOtp) {
      return res.status(400).json({
        message: "No active password reset OTP found",
      });
    }

    if (new Date(String(latestOtp.expiresAt)).getTime() < Date.now()) {
      return res.status(400).json({
        message: "OTP has expired",
      });
    }

    const valid = await verifyOtp(String(code), String(latestOtp.codeHash));

    if (!valid) {
      return res.status(400).json({
        message: "Invalid OTP",
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
