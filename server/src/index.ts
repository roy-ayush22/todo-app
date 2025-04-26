import express from "express";
import z from "zod";
import * as bcrypt from "bcrypt-ts";
import { PrismaClient } from "@prisma/client";
const client = new PrismaClient();
const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
  const requiredBody = z.object({
    username: z.string().min(3).max(80),
    email: z.string().min(5).max(50).email(),
    password: z
      .string()
      .min(6)
      .max(40)
      .regex(/[a-z]/, "password must contain lower case alphabet")
      .regex(/[A-Z]/, "password must contain upper case alphabet")
      .regex(/[!@#$%^&*()_<>?:]/, "password must contain a special character"),
  });

  const parseData = requiredBody.safeParse(req.body);
  if (!parseData.success) {
    res.json({
      message: "invalid format",
    });
    return;
  }

  const { username, email, password } = parseData.data;

  const hashedPassword = await bcrypt.hash(password, 5);
  console.log(hashedPassword);

  await client.user.create({
    data: {
      username,
      email,
      password: hashedPassword,
    },
  });
  res.json({
    message: "user created successfully",
  });
  console.log("reached");
});

const main = () => {
  app.listen(3000);
  console.log("server running on port 3000");
};

main();
