import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest'
import packages from './_mocks.js'
import useApp from '../source/app.js'

const JWT_EXPIRATION_ACCESS = 1200
const JWT_EXPIRATION_REFRESH = 60000
const JWT_SECRET = 'secret'

describe("/sessions", () => {
  let app

  let date
  let user
  let request

  let accessToken
  let accessTokenPayload
  
  let refreshToken
  let refreshTokenPayload

  beforeAll(async () => {
    process.env.JWT_EXPIRATION_ACCESS = JWT_EXPIRATION_ACCESS
    process.env.JWT_EXPIRATION_REFRESH = JWT_EXPIRATION_REFRESH
    process.env.JWT_SECRET = JWT_SECRET

    date = new Date(Date.now())
    vi.setSystemTime(date)

    app = await useApp(packages)
  })

  beforeEach(() => {
    user = {
      id: 1,
      active: true,
      roleId: 2,
      email: 'test@mail',
      password: '1234'
    }

    accessToken = 'JWT.ACCESS.TOKEN'
    accessTokenPayload = { userId: 1, roleId: 2, type: 'access' }

    refreshToken = 'JWT.REFRESH.TOKEN'
    refreshTokenPayload = { userId: 1, roleId: 2, type: 'refresh' }
  })
  
  describe("POST /sessions { email, password }", () => {

    beforeEach(() => {
      request = { 
        method: 'POST', 
        url: '/sessions', 
        body: { 
          email: user.email, 
          password: user.password, 
        } 
      }
      
      packages.connection.query.mockReturnValue([[user],[]])
      
      packages.bcrypt.compare.mockReturnValue(true)
      
      packages.jwt.sign.mockReturnValueOnce(accessToken)
      packages.jwt.sign.mockReturnValueOnce(refreshToken)
    })
    
    it("finds the user by its email from the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(1, 'select id, roleId, active, password from user where email = ? limit 1', [request.body.email])
    })

    it("validates the password with the bcrypt module", async () => {
      await app.inject(request)
      expect(packages.bcrypt.compare).toHaveBeenCalledWith(request.body.password, user.password)
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
      expect(response.json()).toEqual({
        accessToken,
        refreshToken,
        expiresIn: JWT_EXPIRATION_ACCESS,
      })
    })
    
    describe("if the user is not found", () => {
      
      it("return a 404 status code with an error message", async () => {
        packages.connection.query.mockReturnValue([[],[]])
        const response = await app.inject(request)
        expect(response.statusCode).toBe(404)
        expect(response.json()).toEqual({
          message: 'No pudimos encontrar tu cuenta. ¿El email que ingresaste es el correcto?'
        })
      })
      
    })

    describe("if the user is not active", () => {
      
      it("returns a 403 response with an error message", async () => {
        user.active = false
        const response = await app.inject(request)
        expect(response.statusCode).toBe(403)
        expect(response.json()).toEqual({
          message: 'Lo sentimos, tu cuenta se encuentra inactiva. Contactate con un administrador para poder acceder.'
        })
      })
      
    })

    describe("if the passwords do not match", () => {
      
      it("returns a 403 response with an error message", async () => {
        packages.bcrypt.compare.mockReturnValue(false)
        const response = await app.inject(request)
        expect(response.statusCode).toBe(403)
        expect(response.json()).toEqual({
          message: 'La contraseña que ingresaste es incorrecta.'
        })
      })
      
    })
    
  })

  describe("DELETE /sessions", () => {

    beforeEach(() => {
      request = { 
        method: 'DELETE', 
        url: '/sessions',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }

      packages.jwt.verify.mockReturnValue(accessTokenPayload)
      packages.connection.query.mockReturnValue([{ affectedRows: 5 }, []])
    })

    it("gets the user from the access token", async () => {
      await app.inject(request)
      expect(packages.jwt.verify).toHaveBeenCalledWith(accessToken, JWT_SECRET)
    })

    it("deletes the user's sessions from the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenCalledWith('update session set removedAt = now() where removedAt is null and userId = ?', [user.id])
    })
    
    it("returns the number of rows removed", async () => {
      const result = await app.inject(request)
      expect(result.json()).toEqual({ removed: 5 })
    })

    describe("if the access token is invalid", () => {
      
      it("returns 403 and an error message", async () => {
        packages.jwt.verify.mockImplementation(new Error())
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(403)
        expect(result.json()).toEqual({ message: 'No tenes permiso para acceder a este recurso.' })
      })
      
    })

    describe("if the request has no access header", () => {
      
      it("returns 403 and an error message", async () => {
        delete request.headers.Authorization
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(403)
        expect(result.json()).toEqual({ message: 'No tenes permiso para acceder a este recurso.' })
      })
      
    })

    describe("if the access header is malformed", () => {
      
      it("returns 403 and an error message", async () => {
        request.headers.Authorization = `Invalid ${accessToken}`
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(403)
        expect(result.json()).toEqual({ message: 'No tenes permiso para acceder a este recurso.' })
      })
      
    })
    
  })

})