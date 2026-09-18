import { Router } from "express";
import { db } from "../../prisma/db";
import { generateOtp, hashOtp } from "../../utils/otp";
import { sendPasswordResetEmail } from "../../email/sendVerificationEmail";
import { forgotPasswordSchema } from "../../validation/auth";

const router: Router = Router();

router.post("/forgot-password", async (req, res) => {
  try {
    const result = forgotPasswordSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid email",
        errors: result.error.flatten().fieldErrors,
      });
    }

    const { email } = result.data;

    const publicDb = db.orm.public;

    if (!publicDb?.User || !publicDb?.Otp) {
      throw new Error("Public database client is unavailable");
    }

    const user = await publicDb.User.first({ email });

    if (!user) {
      return res.status(200).json({
        message: "If an account exists, a password reset OTP has been sent",
      });
    }

    const existingOtps = await publicDb.Otp.where({
      userId: user.id,
      purpose: "PASSWORD_RESET",
    }).all();

    const latestOtp = existingOtps
      .filter((otp) => !otp.consumedAt)
      .sort(
        (a, b) =>
          new Date(b.createdAt as string | number | Date).getTime() -
          new Date(a.createdAt as string | number | Date).getTime(),
      )[0];

    if (latestOtp) {
      const createdAt = new Date(latestOtp.createdAt as string | number | Date);

      const secondsSinceCreation = (Date.now() - createdAt.getTime()) / 1000;

      if (secondsSinceCreation < 60) {
        return res.status(200).json({
          message: "If an account exists, a password reset OTP has been sent",
        });
      }
    }

    const otp = generateOtp();
    const codeHash = await hashOtp(otp);

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await publicDb.Otp.create({
      userId: user.id,
      codeHash,
      purpose: "PASSWORD_RESET",
      expiresAt,
    });

    await sendPasswordResetEmail(email, otp);

    return res.status(200).json({
      message: "If an account exists, a password reset OTP has been sent",
    });
  } catch (error) {
    console.error("Forgot password error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
