import { pgTable, text, uuid } from "drizzle-orm/pg-core"
import { createSelectSchema } from "drizzle-zod"
import type { z } from "zod"

export const user = pgTable("users", {
  id: uuid().primaryKey().defaultRandom(),
  name: text().notNull(),
  passwordHash: text().notNull(),
})

export const userSchema = createSelectSchema(user)
export type User = z.infer<typeof userSchema>
