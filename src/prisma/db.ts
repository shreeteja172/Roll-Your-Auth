import "dotenv/config";
import postgres from "@prisma/orm-postgres/runtime";
import { readFileSync } from "node:fs";

const contractJson = JSON.parse(
  readFileSync(new URL("./schema.json", import.meta.url), "utf8"),
);
type Contract = typeof contractJson;

export const db = postgres<Contract>({
  contractJson,
  url: process.env["DATABASE_URL"]!,
});
