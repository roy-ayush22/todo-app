import express from "express";
import z from "zod";
import * as bcrypt from "bcrypt-ts";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import JWT_SECRET from "./config.js";

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

  try {
    const user = await client.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });
    console.log("user created");
    res.json({
      message: "user created successfully",
      userId: user.id,
    });
  } catch (error) {
    res.json({
      message: "user already exists",
    });
  }
});

app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await client.user.findFirst({
      where: {
        email,
      },
    });
    if (!user) {
      res.json({
        message: "user not signed up",
      });
    } else {
      const matchPassword = await bcrypt.compare(password, user.password);
      if (matchPassword) {
        const token = jwt.sign(
          {
            id: user.id.toString(),
          },
          JWT_SECRET
        );
        res.json({
          token,
        });
      } else {
        res.json({
          message: "invalid password",
        });
      }
    }
  } catch (error) {
    res.json({
      message: "server error",
    });
  }
});

app.get("/user", (req, res) => {
  res.json({
    message: "welcome to protected route",
  });
});

const main = () => {
  app.listen(3000);
  console.log("server running on port 3000");
};

main();
