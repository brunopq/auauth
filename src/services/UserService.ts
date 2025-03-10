import { z } from "zod"

import { db } from "../db"
import { newUserSchema, user } from "../db/schema"

import { hashPassword } from "../hashing"

export const createUserSchema = newUserSchema
  .omit({ id: true, passwordHash: true })
  .extend({ password: z.string() })

export type CreateUser = z.infer<typeof createUserSchema>

class UserService {
  async findById(id: string) {
    return await db.query.user.findFirst({
      where: (user, { eq }) => eq(user.id, id),
    })
  }

  async findByName(name: string) {
    return await db.query.user.findFirst({
      where: (user, { eq }) => eq(user.name, name),
    })
  }

  async create(newUser: CreateUser) {
    const passwordHash = hashPassword(newUser.password)
    const [created] = await db
      .insert(user)
      .values({ ...newUser, passwordHash })
      .returning()

    return created
  }
}

export default new UserService()
