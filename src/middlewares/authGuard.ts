import { createMiddleware } from "hono/factory"
import { HTTPException } from "hono/http-exception"

import type { User, UserRole } from "../db/schema"

export const authGuard = (...roles: UserRole[]) =>
  createMiddleware<{ Variables: { user: User } }>(async (c, next) => {
    const user = c.get("user")

    if (!roles.includes(user.role)) {
      throw new HTTPException(403, { message: "Forbidden" })
    }

    await next()
  })
