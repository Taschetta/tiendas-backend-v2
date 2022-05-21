import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest'
import packages from './_mocks.js'
import useApp from '../source/app.js'

const JWT_EXPIRATION_ACCESS = 1200
const JWT_EXPIRATION_REFRESH = 60000
const JWT_SECRET = 'secret'

describe("/session", () => {
  let app

  let date
  let user
  let request
  let accessToken
  let refreshToken

  beforeAll(async () => {
    process.env.JWT_EXPIRATION_ACCESS = JWT_EXPIRATION_ACCESS
    process.env.JWT_EXPIRATION_REFRESH = JWT_EXPIRATION_REFRESH
    process.env.JWT_SECRET = JWT_SECRET

    date = new Date(Date.now())

    // vi.useFakeTimers()
    // vi.setSystemTime(date)
    
    app = await useApp(packages)
  })

  beforeEach(() => {
    user = {
      id: 1,
      roleId: 2,
      email: 'test@mail',
      password: '1234'
    }
    
    request = { 
      method: 'POST', 
      url: '/session', 
      body: { 
        email: user.email, 
        password: user.password, 
      } 
    }

    accessToken = 'JWT.ACCESS.TOKEN'
    refreshToken = 'JWT.REFRESH.TOKEN'
    
    packages.connection.query.mockReturnValueOnce([[user],[]])
    
    packages.jwt.sign.mockReturnValueOnce(accessToken)
    packages.jwt.sign.mockReturnValueOnce(refreshToken)
  })
  
  describe("POST /session { email, password }", () => {
    
    it("finds the user by its email from the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(1, 'select id, roleId, active, password from user where email = ? limit 1', [request.body.email])
    })
    
    it("generates the tokens from the jwt package", async () => {
      await app.inject(request)
      expect(packages.jwt.sign).toHaveBeenNthCalledWith(1, { userId: 1, roleId: 2, type: 'access' }, JWT_SECRET, { expiresIn: JWT_EXPIRATION_ACCESS })
      expect(packages.jwt.sign).toHaveBeenNthCalledWith(2, { userId: 1, roleId: 2, type: 'refresh' }, JWT_SECRET, { expiresIn: JWT_EXPIRATION_REFRESH })
    })

    it("stores the tokens on the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(2, 'insert into session (userId, refreshToken, createdAt, updatedAt) values (?)', [[user.id, refreshToken, date, date]])
    })
    
    it("returns a 200 status code, an access token, a refresh token, and an expiration time", async () => {
      const response = await app.inject(request)
      expect(response.statusCode).toBe(200)
      expect(JSON.parse(response.body)).toEqual({
        accessToken,
        refreshToken,
        expiresIn: JWT_EXPIRATION_ACCESS,
      })
    })
    
  })
  
})