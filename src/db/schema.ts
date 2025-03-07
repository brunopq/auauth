import { pgTable, text, uuid } from "drizzle-orm/pg-core"

export const user = pgTable("users", {
  id: uuid().primaryKey().defaultRandom(),
  name: text().notNull(),
  passwordHash: text().notNull(),
})
