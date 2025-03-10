import { jwt, sign } from "hono/jwt"
import { addDays } from "date-fns"
import { z } from "zod"

import { type User, userRoleSchmea } from "../db/schema"

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production"

export const jwtSchema = z.object({
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

export const makeJwt = (user: User) => {
  return sign(
    jwtSchema.parse({
      exp: addDays(new Date(), 1).getTime(),
      user,
    }),
    JWT_SECRET,
  )
}

export const jwtMiddleware = () => jwt({ secret: JWT_SECRET })
