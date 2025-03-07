import { db } from "."
import { hashPassword } from "../hashing"
import { user } from "./schema"

async function seed() {
  const ademiro = await db
    .insert(user)
    .values({
      name: "admin",
      passwordHash: hashPassword("password"),
    })
    .returning()

  console.log(ademiro)
}

seed()
