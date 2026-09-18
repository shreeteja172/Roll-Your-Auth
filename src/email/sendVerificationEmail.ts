import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendVerificationEmail(email: string, otp: string) {
  return sendOtpEmail(
    email,
    otp,
    "Verify your RollYourAuth email",
    "Email verification code",
  );
}

export async function sendPasswordResetEmail(email: string, otp: string) {
  return sendOtpEmail(
    email,
    otp,
    "Reset your RollYourAuth password",
    "Password reset code",
  );
}

async function sendOtpEmail(
  email: string,
  otp: string,
  subject: string,
  heading: string,
) {
  const { data, error } = await resend.emails.send({
    from: "RollYourAuth <auth@shreeteja.me>",
    to: [email],
    subject,
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>${heading}</h2>

        <p>Your one-time code is:</p>

        <h1 style="letter-spacing: 6px;">
          ${otp}
        </h1>

        <p>This code expires in 10 minutes.</p>

        <p>If you didn't request this, you can safely ignore this email.</p>
      </div>
    `,
  });

  if (error) {
    throw new Error(error.message);
  }

  return data;
}
