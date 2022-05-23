import { vi } from "vitest"

export const connection = {
  query: vi.fn()
}

export const mysql2 = {
  createConnection: vi.fn(() => connection),
  createPool: vi.fn(() => connection)
}

export const bcrypt = {
  hash: vi.fn(),
  compare: vi.fn(),
}

export const jwt = {
  sign: vi.fn(),
  verify: vi.fn(),
  decode: vi.fn(),
}

export default {
  mysql2,
  connection,
  bcrypt,
  jwt,
}