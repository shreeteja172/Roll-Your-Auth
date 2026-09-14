import { Router } from "express";
import { db } from "../../prisma/db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { verifyPassword } from "../../auth/password";

const router: Router = Router();

router.post("/login", async (req, res) => {
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

    const user = await publicDb.User.where({ email }).first();

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }
    // console.log("Res", user);

    // console.log("LOGIN PASSWORD:", password);
    // console.log("STORED HASH:", user.passwordHash);
    if (typeof user.passwordHash !== "string") {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const passwordMatch = await verifyPassword(password, user.passwordHash);

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET!,
      {
        expiresIn: "1h",
      },
    );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
