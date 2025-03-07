import { password } from "bun"

export function hashPassword(pswd: string) {
  return password.hashSync(pswd)
}

export function verifyPassword(pswd: string, hash: string) {
  return password.verifySync(pswd, hash)
}
