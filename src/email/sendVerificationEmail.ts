import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendVerificationEmail(email: string, otp: string) {
  const { data, error } = await resend.emails.send({
    from: "RollYourAuth <auth@shreeteja.me>",
    to: [email],
    subject: "Verify your RollYourAuth email",
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Verify your email</h2>

        <p>Your RollYourAuth verification code is:</p>

        <h1 style="letter-spacing: 6px;">
          ${otp}
        </h1>

        <p>This code expires in 10 minutes.</p>

        <p>If you didn't create this account, you can ignore this email.</p>
      </div>
    `,
  });

  if (error) {
    throw new Error(error.message);
  }

  return data;
}
