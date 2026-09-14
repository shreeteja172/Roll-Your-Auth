import { Temporal } from "@js-temporal/polyfill";

globalThis.Temporal = Temporal as unknown as typeof globalThis.Temporal;

import express from "express";
import registerRouter from "./routes/auth/register";
import loginRouter from "./routes/auth/login";
import cookieParser from "cookie-parser";
import meRouter from "./routes/auth/me";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/auth", registerRouter);
app.use("/auth", loginRouter);
app.use("/auth", meRouter);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
