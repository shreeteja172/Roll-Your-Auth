import { Temporal } from "@js-temporal/polyfill";

globalThis.Temporal = Temporal as unknown as typeof globalThis.Temporal;

import express from "express";
import registerRouter from "./routes/auth/register";
import loginRouter from "./routes/auth/login";

const app = express();

app.use(express.json());

app.use("/auth", registerRouter);
app.use("/auth", loginRouter);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
