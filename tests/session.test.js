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
  let accessTokenPayload
  
  let refreshToken
  let refreshTokenPayload

  let newAccessToken
  let newAccessTokenPayload
  
  let newRefreshToken
  let newRefreshTokenPayload

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

    refreshToken = 'JWT.REFRESH.TOKEN'
    refreshTokenPayload = { userId: 1, roleId: 2, type: 'refresh' }

    accessToken = 'JWT.ACCESS.TOKEN'
    accessTokenPayload = { userId: 1, roleId: 2, sessionId: 10, type: 'access' }

    newRefreshToken = 'NEW.REFRESH.TOKEN'
    newRefreshTokenPayload = { userId: 1, roleId: 2, type: 'refresh' }

    newAccessToken = 'NEW.ACCESS.TOKEN'
    newAccessTokenPayload = { userId: 1, roleId: 2, sessionId: 10, type: 'access' }
  })
  
  describe("POST /session { email, password }", () => {

    beforeEach(() => {
      request = { 
        method: 'POST', 
        url: '/session', 
        body: { 
          email: user.email, 
          password: user.password, 
        } 
      }
      
      packages.connection.query.mockReset()
      packages.connection.query.mockReturnValueOnce([[user],[]])
      packages.connection.query.mockReturnValueOnce([{ insertId: 10 },[]])
      
      packages.bcrypt.compare.mockReturnValue(true)
      
      packages.jwt.sign.mockReset()
      packages.jwt.sign.mockReturnValueOnce(refreshToken)
      packages.jwt.sign.mockReturnValueOnce(accessToken)
    })
    
    it("finds the user by its email from the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(1, 'select id, roleId, active, password from user where email = ? limit 1', [request.body.email])
    })

    it("validates the password with the bcrypt module", async () => {
      await app.inject(request)
      expect(packages.bcrypt.compare).toHaveBeenCalledWith(request.body.password, user.password)
    })
    
    it("generates the refresh token", async () => {
      await app.inject(request)
      expect(packages.jwt.sign).toHaveBeenNthCalledWith(1, refreshTokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRATION_REFRESH })
    })

    it("stores the tokens on the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(2, 'insert into session (userId, refreshToken, createdAt, updatedAt) values (?)', [[user.id, refreshToken, date, date]])
    })

    it("generates the acces token", async () => {
      await app.inject(request)
      expect(packages.jwt.sign).toHaveBeenNthCalledWith(2, accessTokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRATION_ACCESS })
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
      
      it("return a 401 status code with an error message", async () => {
        packages.connection.query.mockReset()
        packages.connection.query.mockReturnValue([[],[]])
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No pudimos encontrar tu cuenta. ¿El email que ingresaste es el correcto?' })
      })
      
    })

    describe("if the user is not active", () => {
      
      it("returns a 403 response with an error message", async () => {
        user.active = false
        const response = await app.inject(request)
        expect(response.statusCode).toEqual(401)
        expect(response.json()).toEqual({ message: 'Lo sentimos, tu cuenta se encuentra inactiva. Contactate con un administrador para poder acceder.' })
      })
      
    })

    describe("if the passwords do not match", () => {
      
      it("returns a 403 response with an error message", async () => {
        packages.bcrypt.compare.mockReturnValue(false)
        const response = await app.inject(request)
        expect(response.statusCode).toEqual(401)
        expect(response.json()).toEqual({ message: 'La contraseña que ingresaste es incorrecta.' })
      })
      
    })
    
  })

  describe("PUT /session", () => {

    beforeEach(() => {
      request = {
        method: 'PUT',
        url: '/session',
        headers: {
          'Authorization': `Bearer ${refreshToken}`
        }
      }

      packages.connection.query.mockReset()
      packages.connection.query.mockReturnValueOnce([[{ id: accessTokenPayload.sessionId }],[]])
      // packages.connection.query.mockReturnValueOnce([{ up},[]])

      packages.jwt.verify.mockReset()
      packages.jwt.verify.mockReturnValueOnce(refreshTokenPayload)

      packages.jwt.sign.mockReset()
      packages.jwt.sign.mockReturnValueOnce(newRefreshToken)
      packages.jwt.sign.mockReturnValueOnce(newAccessToken)
    })

    it("checks the authorization", async () => {
      await app.inject(request)
      expect(packages.jwt.verify).toHaveBeenCalled(refreshToken, JWT_SECRET)
    })

    it("finds the session by the refreshToken", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(1, 'select id from session where refreshToken = ?', [refreshToken])
    })

    it("generates a new refresh and access token", async () => {
      await app.inject(request)
      expect(packages.jwt.sign).toHaveBeenNthCalledWith(1, newRefreshTokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRATION_REFRESH })
      expect(packages.jwt.sign).toHaveBeenNthCalledWith(2, newAccessTokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRATION_ACCESS })
    })

    it("updates the session with the new access token", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenNthCalledWith(2, 'update session set refreshToken = ? where refreshToken = ?', [
        newRefreshToken,
        refreshToken,
      ])
    })

    it("returns the new tokens", async () => {
      const result = await app.inject(request)
      expect(result.json()).toEqual({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      })
    })

    describe("if no authorization header is set", () => {

      it("throws a 401 error", async () => {
        delete request.headers.Authorization
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })

    describe("if the token is invalid", () => {
      
      it("throws a 403 error", async () => {
        packages.jwt.verify.mockReset()
        packages.jwt.verify.mockImplementation(() => {throw new Error()})
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })

    describe("if the token does not match the token on the database", () => {
      
      it("throws a 403 error", async () => {
        packages.connection.query.mockReset()
        packages.connection.query.mockReturnValue([[],[]])
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })

  })

  describe("DELETE /session", () => {

    beforeEach(() => {
      request = { 
        method: 'DELETE', 
        url: '/session',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }

      packages.jwt.verify.mockReturnValue(accessTokenPayload)
      packages.connection.query.mockReturnValue([{ affectedRows: 5 }, []])
    })

    it("gets the sessionId from the access token", async () => {
      await app.inject(request)
      expect(packages.jwt.verify).toHaveBeenCalledWith(accessToken, JWT_SECRET)
    })

    it("deletes the session from the database", async () => {
      await app.inject(request)
      expect(packages.connection.query).toHaveBeenCalledWith('update session set removedAt = now() where removedAt is null and sessionId = ?', [accessTokenPayload.sessionId])
    })
    
    it("returns the number of rows removed", async () => {
      const result = await app.inject(request)
      expect(result.json()).toEqual({ removed: 5 })
    })

    describe("if the request has no access header", () => {
      
      it("returns 401 and an error message", async () => {
        delete request.headers.Authorization
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })

    describe("if the access header is malformed", () => {
      
      it("returns 401 and an error message", async () => {
        request.headers.Authorization = `Invalid ${accessToken}`
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })

    describe("if the access token is invalid", () => {
      
      it("returns 401 and an error message", async () => {
        packages.jwt.verify.mockImplementation(new Error())
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })

    describe("if the access token is a refresh token", () => {

      it("returns 401 and an error message", async () => {
        packages.jwt.verify.mockReset()
        packages.jwt.verify.mockReturnValue(refreshTokenPayload)
        const result = await app.inject(request)
        expect(result.statusCode).toEqual(401)
        expect(result.json()).toEqual({ message: 'No podes acceder a este recurso. Tus credenciales son invalidas' })
      })
      
    })
    
  })

})