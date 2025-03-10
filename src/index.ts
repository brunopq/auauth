import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import { zValidator } from "@hono/zod-validator"
import { z } from "zod"

import { verifyPassword } from "./hashing.js"

import { authGuard } from "./middlewares/authGuard.js"
import { getUser } from "./middlewares/getUser.js"
import { jwtMiddleware, makeJwt } from "./utils/jwt.js"

import UserService, { createUserSchema } from "./services/UserService.js"

const app = new Hono()

const loginSchema = z.object({
  username: z.string(),
  password: z.string(),
})

app.post("/login", zValidator("json", loginSchema), async (c) => {
  const { username, password } = c.req.valid("json")

  const userInfo = await UserService.findByName(username)

  if (!userInfo) {
    throw new HTTPException(401, { message: "Invalid credentials" })
  }

  const userPawssordValid = verifyPassword(password, userInfo.passwordHash)

  if (!userPawssordValid) {
    throw new HTTPException(401, { message: "Invalid credentials" })
  }

  const jwt = await makeJwt(userInfo)

  return c.json({ token: jwt })
})

app.get("/me", jwtMiddleware(), getUser(), (c) => {
  const user = c.get("user")
  return c.json({
    id: user.id,
    name: user.name,
    fullName: user.fullName,
    role: user.role,
    accountActive: user.accountActive,
  })
})

app.post(
  "/create",
  jwtMiddleware(),
  getUser(),
  authGuard("ADMIN"),
  zValidator("json", createUserSchema),
  async (c) => {
    const createUser = c.req.valid("json")

    const userExists = await UserService.findByName(createUser.name)

    if (userExists) {
      throw new HTTPException(400, {
        message: `User with name "${createUser.name}" already exists`,
      })
    }

    const createdUser = await UserService.create(createUser)

    if (!createdUser) {
      throw new HTTPException(500, { message: "Error creating user" })
    }

    return c.json({
      user: {
        id: createdUser.id,
        name: createdUser.name,
        fullName: createdUser.fullName,
        role: createdUser.role,
        accountActive: createdUser.accountActive,
      },
    })
  },
)

export default app
