import { Hono } from "hono"
import { zValidator } from "@hono/zod-validator"
import { jwt, sign } from "hono/jwt"
import { z } from "zod"
import { HTTPException } from "hono/http-exception"
import { addDays } from "date-fns"

import { db } from "./db/index.js"

import { verifyPassword } from "./hashing.js"
import type { User } from "./db/schema.js"
import { createMiddleware } from "hono/factory"
import { every } from "hono/combine"

const app = new Hono()

// login: username e senha -> retorna JWT
// validar token: recebe token JWT pelos headers e valida
// criação de usuário: apenas admin (?) cria usuários -> retorna dados do usuário
//

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production"

const jwtSchema = z.object({
  exp: z.number(),
  user: z.object({
    id: z.string(),
    name: z.string(),
  }),
})

type Jwt = z.infer<typeof jwtSchema>

const makeJwt = (user: User) => {
  return sign(
    // this should always be valid
    jwtSchema.parse({
      exp: addDays(new Date(), 1).getTime(),
      user: {
        id: user.id,
        name: user.name,
      },
    }),
    JWT_SECRET,
  )
}

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

  const jwt = await sign(
    {
      exp,
      user: {
        somekey: "hehehehehehhe",
      },
    },
    JWT_SECRET,
  )

  return c.json({ token: jwt })
})

// for some reason types are not working, maybe its the every function
const jwtMiddleware = every(
  jwt({ secret: JWT_SECRET }),
  createMiddleware<{
    Variables: {
      jwtPayload: Jwt
      something: string
    }
  }>(async (c, next) => {
    const token = c.get("jwtPayload")
    const parsed = jwtSchema.safeParse(token)

    if (!parsed.success) {
      throw new HTTPException(401, { message: "Invalid token" })
    }

    c.set("jwtPayload", parsed.data)

    await next()
  }),
)

app.get(
  "/validate",
  jwtMiddleware,

  (c) => {
    const token = c.get("jwtPayload")
    return c.json({
      token,
    })
  },
)

export default app
