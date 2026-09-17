import { Router } from "express";
import { db } from "../../prisma/db";
import { hashPassword } from "../../auth/password";
import { generateOtp, hashOtp } from "../../utils/otp";

const router: Router = Router();

router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    const publicDb = db.orm.public;

    if (!publicDb?.User) {
      throw new Error("Public database client is unavailable");
    }

    const existingUser = await publicDb.User.first({ email });

    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
      });
    }

    const passwordHash = await hashPassword(password);

    // console.log("REGISTER PASSWORD:", password);
    // console.log("GENERATED HASH:", passwordHash);

    const user = await publicDb.User.create({
      email,
      passwordHash,
    });

    const otp = generateOtp();
    const codeHash = await hashOtp(otp);

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await publicDb!.Otp!.create({
      userId: user.id,
      codeHash,
      purpose: "EMAIL_VERIFY",
      expiresAt,
    });

    console.log("EMAIL VERIFICATION OTP:", otp);

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
