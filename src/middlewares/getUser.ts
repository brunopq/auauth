import { createMiddleware } from "hono/factory"
import { HTTPException } from "hono/http-exception"

import type { User } from "../db/schema"

import { jwtSchema } from "../utils/jwt"

import UserService from "../services/UserService"

export const getUser = () =>
  createMiddleware<{ Variables: { user: User } }>(async (c, next) => {
    const token = c.get("jwtPayload")
    const parsed = jwtSchema.safeParse(token)

    if (!parsed.success)
      throw new HTTPException(401, { message: "Invalid token" })

    const user = await UserService.findById(parsed.data.user.id)

    if (!user || !user.accountActive)
      throw new HTTPException(401, { message: "Invalid token" })

    c.set("user", user)

    await next()
  })
