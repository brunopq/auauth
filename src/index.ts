import { Hono } from "hono"
import { jwt, sign } from "hono/jwt"
import { HTTPException } from "hono/http-exception"
import { createMiddleware } from "hono/factory"
import { zValidator } from "@hono/zod-validator"
import { string, z } from "zod"
import { addDays } from "date-fns"

import { db } from "./db/index.js"

import { hashPassword, verifyPassword } from "./hashing.js"
import {
  user,
  userRoleSchmea,
  userSchema,
  type User,
  type UserRole,
} from "./db/schema.js"

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
    fullName: z.string().nullish(),
    role: userRoleSchmea(),
    accountActive: z.boolean(),
  }),
})

type Jwt = z.infer<typeof jwtSchema>

const makeJwt = (user: User) => {
  return sign(
    jwtSchema.parse({
      exp: addDays(new Date(), 1).getTime(),
      user,
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

  const jwt = await makeJwt(userInfo)

  return c.json({ token: jwt })
})

const getUser = () =>
  createMiddleware<{ Variables: { user: User } }>(async (c, next) => {
    const token = c.get("jwtPayload")
    const parsed = jwtSchema.safeParse(token)

    if (!parsed.success)
      throw new HTTPException(401, { message: "Invalid token" })

    const user = await db.query.user.findFirst({
      where: (user, { eq }) => eq(user.id, parsed.data.user.id),
    })

    if (!user) throw new HTTPException(401, { message: "Invalid token" })

    c.set("user", user)

    await next()
  })

const authGuard = (...roles: UserRole[]) =>
  createMiddleware<{ Variables: { user: User } }>(async (c, next) => {
    const user = c.get("user")

    if (!roles.includes(user.role)) {
      throw new HTTPException(403, { message: "Forbidden" })
    }

    await next()
  })

app.get("/me", jwt({ secret: JWT_SECRET }), getUser(), (c) => {
  const user = c.get("user")
  return c.json({
    id: user.id,
    name: user.name,
    fullName: user.fullName,
    role: user.role,
    accountActive: user.accountActive,
  })
})

const createUserSchema = userSchema
  .omit({ id: true, passwordHash: true })
  .extend({ password: z.string() })

app.post(
  "/create",
  jwt({ secret: JWT_SECRET }),
  getUser(),
  authGuard("ADMIN"),
  zValidator("json", createUserSchema),
  async (c) => {
    const createUser = c.req.valid("json")

    const userExists = await db.query.user.findFirst({
      where: (user, { eq }) => eq(user.name, createUser.name),
    })

    if (userExists) {
      throw new HTTPException(400, {
        message: `User with name "${createUser.name}" already exists`,
      })
    }

    const [createdUser] = await db
      .insert(user)
      .values({
        ...createUser,
        passwordHash: hashPassword(createUser.password),
      })
      .returning()

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
