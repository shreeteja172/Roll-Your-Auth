import "dotenv/config";

import { definePrismaConfig, type PrismaConfig } from "prisma/config";
import { defineConfig as ormConfig } from "@prisma/orm-postgres/config";

const config: PrismaConfig = definePrismaConfig({
  orm: ormConfig({
    contract: "./src/prisma/schema.prisma",
    db: {
      connection: process.env.DATABASE_URL!,
    },
  }),

  skills: {
    agents: ["claude", "cursor", "agents", "devin"],
  },
});

export default config;