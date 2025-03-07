import { Hono } from "hono"
import { zValidator } from "@hono/zod-validator"
import { sign } from "hono/jwt"
import { z } from "zod"
import { HTTPException } from "hono/http-exception"
import { addDays } from "date-fns"

import { db } from "./db/index.js"

import { verifyPassword } from "./hashing.js"

const app = new Hono()

// login: username e senha -> retorna JWT
// validar token: recebe token JWT pelos headers e valida
// criação de usuário: apenas admin (?) cria usuários -> retorna dados do usuário
//

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production"

const loginSchema = z.object({
  username: z.string(),
  password: z.string(),
})

app.post("/login", zValidator("json", loginSchema), async (c) => {
  const { username, password } = c.req.valid("json")

  const userInfo = await db.query.user.findFirst({
    where: (user, { eq }) => eq(user.name, username),
  })

  if (!userInfo) {
    throw new HTTPException(401, { message: "Invalid credentials" })
  }

  const userPawssordValid = verifyPassword(password, userInfo.passwordHash)

  if (!userPawssordValid) {
    throw new HTTPException(401, { message: "Invalid credentials" })
  }

  const exp = addDays(new Date(), 1).getTime()

  // cria jwt pro usuário
  const jwt = await sign({ exp, user: userInfo }, JWT_SECRET)

  return c.json({ token: jwt })
})

app.get("/", (c) => {
  return c.json({
    hello: "world",
  })
})

export default app
