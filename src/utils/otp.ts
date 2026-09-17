import argon2 from "argon2";
import { randomInt } from "crypto";

export function generateOtp(): string {
  return randomInt(100000, 1000000).toString();
}

export async function hashOtp(otp: string): Promise<string> {
  return argon2.hash(otp);
}

export async function verifyOtp(otp: string, hash: string): Promise<boolean> {
  return argon2.verify(hash, otp);
}
