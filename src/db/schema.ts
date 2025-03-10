import { boolean, pgEnum, pgTable, text, uuid } from "drizzle-orm/pg-core"
import { createInsertSchema, createSelectSchema } from "drizzle-zod"
import { z } from "zod"

export const userRoles = pgEnum("user_roles", ["ADMIN", "SELLER"])

export const user = pgTable("users", {
  id: uuid().primaryKey().defaultRandom(),
  name: text().notNull().unique(),
  passwordHash: text().notNull(),
  fullName: text(),
  role: userRoles().notNull(),
  accountActive: boolean().default(true).notNull(),
})

export const userRoleSchmea = (params?: z.RawCreateParams) =>
  z.enum(userRoles.enumValues, params)
export type UserRole = z.infer<ReturnType<typeof userRoleSchmea>>

export const userSchema = createSelectSchema(user)
export type User = z.infer<typeof userSchema>
export const newUserSchema = createInsertSchema(user)
export type NewUser = z.infer<typeof newUserSchema>
