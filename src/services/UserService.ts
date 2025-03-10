import { z } from "zod"

import { db } from "../db"
import { newUserSchema, user } from "../db/schema"

import { hashPassword } from "../hashing"
import { eq } from "drizzle-orm"

export const createUserSchema = newUserSchema
  .omit({ id: true, passwordHash: true })
  .extend({ password: z.string() })
export const updateUserSchema = newUserSchema
  .extend({ password: z.string() })
  .partial()

export type CreateUser = z.infer<typeof createUserSchema>
export type UpdateUser = z.infer<typeof updateUserSchema>

class UserService {
  async findAll() {
    return await db.query.user.findMany()
  }

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

  async update(id: string, updateUser: UpdateUser) {
    if (updateUser.password) {
      updateUser.passwordHash = hashPassword(updateUser.password)
    }

    const [updatedUser] = await db
      .update(user)
      .set({ ...updateUser, id })
      .where(eq(user.id, id))
      .returning()

    return updatedUser
  }

  async delete(id: string) {
    return await db.delete(user).where(eq(user.id, id))
  }
}

export default new UserService()
