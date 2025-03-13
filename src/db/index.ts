import "dotenv"
import { drizzle } from "drizzle-orm/node-postgres"
import { migrate } from "drizzle-orm/node-postgres/migrator"
import { Pool } from "pg"

import * as schema from "./schema"

const { DATABASE_URL } = process.env
if (!DATABASE_URL) throw new Error("DATABASE_URL must be set")

const pool = new Pool({ connectionString: DATABASE_URL })
export const db = drizzle({ schema, casing: "snake_case", client: pool })
const migrations = drizzle({ schema, casing: "snake_case", client: pool })
await migrate(migrations, { migrationsFolder: "./drizzle" })
