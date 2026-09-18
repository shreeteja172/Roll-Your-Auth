import { Router } from "express";
import { db } from "../../prisma/db";
import { generateOtp, hashOtp } from "../../utils/otp";
import { sendVerificationEmail } from "../../email/sendVerificationEmail";

const router: Router = Router();

router.post("/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const publicDb = db.orm.public;

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

    const existingOtps = await publicDb.Otp.where({
      userId: user.id,
      purpose: "EMAIL_VERIFY",
    }).all();

    const latestOtp = existingOtps
      .filter((otp: any) => !otp.consumedAt)
      .sort(
        (a: any, b: any) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      )[0];

    // not to request again the otp
    if (latestOtp) {
      const elapsed =
        Date.now() -
        new Date(latestOtp.createdAt as string | number | Date).getTime();

      if (elapsed < 60 * 1000) {
        const remaining = Math.ceil((60 * 1000 - elapsed) / 1000);

        return res.status(429).json({
          message: `Please wait ${remaining} seconds before requesting another OTP`,
        });
      }
    }
    for (const otp of existingOtps) {
      if (!otp.consumedAt) {
        await publicDb.Otp.where({ id: otp.id }).update({
          consumedAt: new Date(),
        });
      }
    }
    const otp = generateOtp();
    const codeHash = await hashOtp(otp);

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await publicDb.Otp.create({
      userId: user.id,
      codeHash,
      purpose: "EMAIL_VERIFY",
      expiresAt,
    });

    // console.log("NEW EMAIL VERIFICATION OTP:", otp);
    await sendVerificationEmail(email, otp);

    return res.status(200).json({
      message: "Verification OTP sent successfully",
    });
  } catch (error) {
    console.error("Resend verification error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
