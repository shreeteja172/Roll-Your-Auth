import { Router } from "express";
import { db } from "../../prisma/db";
import { verifyOtp } from "../../utils/otp";

const router: Router = Router();

router.post("/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({
        message: "Email and OTP are required",
      });
    }

    const publicDb = db.orm.public as any;

    if (!publicDb?.User || !publicDb?.Otp) {
      throw new Error("Public database client is unavailable");
    }

    const user = await publicDb.User.first({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.emailVerified) {
      return res.status(400).json({
        message: "Email is already verified",
      });
    }

    const otp = await publicDb.Otp.where({
      userId: user.id,
      purpose: "EMAIL_VERIFY",
    }).all();

    const latestOtp = otp
      .filter((item: { consumedAt: any }) => !item.consumedAt)
      .sort(
        (a: { createdAt: number }, b: { createdAt: number }) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      )[0];

    if (!latestOtp) {
      return res.status(400).json({
        message: "No active verification OTP found",
      });
    }

    if (new Date(latestOtp.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({
        message: "OTP has expired",
      });
    }

    const valid = await verifyOtp(code, latestOtp.codeHash);

    if (!valid) {
      return res.status(400).json({
        message: "Invalid OTP",
      });
    }

    await publicDb.User.where({ id: user.id }).update({
      emailVerified: true,
    });

    await publicDb.Otp.where({ id: latestOtp.id }).update({
      consumedAt: new Date(),
    });

    return res.status(200).json({
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Email verification error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
