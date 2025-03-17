import { Hono } from "hono"
import { showRoutes } from "hono/dev"
import { HTTPException } from "hono/http-exception"
import { zValidator } from "@hono/zod-validator"
import { z } from "zod"

import { verifyPassword } from "./hashing.js"

import { authGuard } from "./middlewares/authGuard.js"
import { getUser } from "./middlewares/getUser.js"
import { jwtMiddleware, makeJwt } from "./utils/jwt.js"

import UserService, {
  createUserSchema,
  updateUserSchema,
} from "./services/UserService.js"

const app = new Hono()

const loginSchema = z.object({
  username: z.string(),
  password: z.string(),
})

app.post("/login", zValidator("json", loginSchema), async (c) => {
  const { username, password } = c.req.valid("json")

  const userInfo = await UserService.findByName(username)

  if (!userInfo || !userInfo.accountActive) {
    throw new HTTPException(401, { message: "Invalid credentials" })
  }

  const userPawssordValid = verifyPassword(password, userInfo.passwordHash)

  if (!userPawssordValid) {
    throw new HTTPException(401, { message: "Invalid credentials" })
  }

  const jwt = await makeJwt(userInfo)

  return c.json({ token: jwt })
})

const userRouter = new Hono().use(jwtMiddleware(), getUser())

const idsSchema = z.object({
  ids: z
    .string()
    .regex(
      /([0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12},?)+/i,
    )
    .optional(),
})

userRouter.get("/", zValidator("query", idsSchema), async (c) => {
  const ids = c.req.valid("query").ids?.split(",")

  const users = await UserService.findAll(ids)
  return c.json({
    users: users.map((u) => ({
      id: u.id,
      name: u.name,
      fullName: u.fullName,
      role: u.role,
      accountActive: u.accountActive,
    })),
  })
})

userRouter.get("/me", (c) => {
  const user = c.get("user")
  return c.json({
    id: user.id,
    name: user.name,
    fullName: user.fullName,
    role: user.role,
    accountActive: user.accountActive,
  })
})

userRouter.post(
  "/",
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

userRouter.patch(
  "/:id",
  authGuard("ADMIN"),
  zValidator("json", updateUserSchema),
  async (c) => {
    const userId = c.req.param("id")
    const updateUser = c.req.valid("json")

    const userExists = await UserService.findById(userId)

    if (!userExists) {
      throw new HTTPException(404, {
        message: `User with id "${userId}" does not exist`,
      })
    }

    const updatedUser = await UserService.update(userId, updateUser)

    if (!updatedUser) {
      throw new HTTPException(500, { message: "Error update user" })
    }

    return c.json({
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        fullName: updatedUser.fullName,
        role: updatedUser.role,
        accountActive: updatedUser.accountActive,
      },
    })
  },
)

userRouter.delete("/:id", authGuard("ADMIN"), async (c) => {
  const userId = c.req.param("id")

  const userExists = await UserService.findById(userId)

  if (!userExists) {
    throw new HTTPException(404, {
      message: `User with id "${userId}" does not exist`,
    })
  }

  await UserService.delete(userId)

  return c.status(204)
})

app.route("/users", userRouter)

showRoutes(app, { colorize: true })
export default app
