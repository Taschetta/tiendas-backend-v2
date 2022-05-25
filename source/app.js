import fastify from "fastify"

class ForbiddenError extends Error {
  constructor(message = 'No tenes permiso para acceder a este recurso.') {
    super(message)
    this.name = 'ForbiddenError'
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, ForbiddenError)
    }
  }
}

class NotFoundError extends Error {
  constructor(message = 'Lo sentimos, no pudimos encontrar el recurso que estas buscando.') {
    super(message)
    this.name = 'NotFoundError'
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, NotFoundError)
    }
  }
}

class UnauthorizedError extends Error {
  constructor(message = 'No podes acceder a este recurso. Tus credenciales son invalidas') {
    super(message)
    this.name = 'UnauthorizedError'
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthorizedError)
    }
  }
}

export default async function useApp(packages, options) {
  const { jwt, mysql2, bcrypt } = packages
  
  const database = await mysql2.createPool({
    connectionLimit: 10,
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME,
  })
  
  const app = fastify(options)

  app.post('/session', async (request, response) => {
    const EXPIRATION_ACCESS = parseInt(process.env.JWT_EXPIRATION_ACCESS)
    const EXPIRATION_REFRESH = parseInt(process.env.JWT_EXPIRATION_REFRESH)
    const SECRET = process.env.JWT_SECRET

    const email = request.body.email
    const password = request.body.password

    const user = (await database.query('select id, roleId, active, password from user where email = ? limit 1', [email]))[0][0]
    
    if(!user) {
      throw new UnauthorizedError('No pudimos encontrar tu cuenta. ¿El email que ingresaste es el correcto?')
    }
    
    if(!user.active) {
      throw new UnauthorizedError('Lo sentimos, tu cuenta se encuentra inactiva. Contactate con un administrador para poder acceder.')
    }

    const passwordsMatch = await bcrypt.compare(password, user.password)
    
    if(!passwordsMatch) throw new UnauthorizedError('La contraseña que ingresaste es incorrecta.')

    const userId = user.id
    const roleId = user.roleId
    
    const refreshToken = jwt.sign({ userId, roleId, type: 'refresh' }, SECRET, { expiresIn: EXPIRATION_REFRESH })

    const date = new Date(Date.now())
    
    const sessionId = (await database.query('insert into session (userId, refreshToken, createdAt, updatedAt) values (?)', [
      [userId, refreshToken, date, date]
    ]))[0]['insertId']

    const accessToken = jwt.sign({ userId, roleId, sessionId, type: 'access' }, SECRET, { expiresIn: EXPIRATION_ACCESS })
    
    return {
      accessToken,
      refreshToken,
      expiresIn: EXPIRATION_ACCESS,
    }
  })

  app.put('/session', async (request, response) => {
    const EXPIRATION_ACCESS = parseInt(process.env.JWT_EXPIRATION_ACCESS)
    const EXPIRATION_REFRESH = parseInt(process.env.JWT_EXPIRATION_REFRESH)
    const SECRET = process.env.JWT_SECRET

    const authorization = request.headers.authorization

    if(!authorization) {
      throw new UnauthorizedError()
    }
    
    const authorizationParts = authorization.split(' ')
    const refreshToken = authorizationParts[1]
    
    let payload
    try {
      payload = jwt.verify(refreshToken, SECRET)      
    } catch (error) {
      throw new UnauthorizedError()
    }

    const session = (await database.query('select id from session where refreshToken = ?', [refreshToken]))[0][0]
    
    if(!session) {
      throw new UnauthorizedError()
    }
    
    const newRefreshTokenPayload = {
      userId: payload.userId,
      roleId: payload.roleId,
      type: 'refresh'
    }

    const newAccessTokenPayload = {
      userId: payload.userId,
      roleId: payload.roleId,
      sessionId: session.id,
      type: 'access',
    }
    
    const newRefreshToken = jwt.sign(newRefreshTokenPayload, SECRET, { expiresIn: EXPIRATION_REFRESH })
    const newAccessToken = jwt.sign(newAccessTokenPayload, SECRET, { expiresIn: EXPIRATION_ACCESS })
    
    await database.query('update session set refreshToken = ? where refreshToken = ?', [
      newRefreshToken,
      refreshToken,
    ])
    
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    }
  })

  app.delete('/session', async (request, response) => {
    const SECRET = process.env.JWT_SECRET

    const authorization = request.headers.authorization

    if(!authorization) {
      throw new UnauthorizedError()
    }
    
    const accessTokenParts = authorization.split(' ')

    if(accessTokenParts.length !== 2 || accessTokenParts[0] !== 'Bearer') {
      throw new UnauthorizedError()
    }
    
    let payload
    try {
      payload = jwt.verify(accessTokenParts[1], SECRET)      
    } catch (error) {
      throw new UnauthorizedError()
    }

    if(payload.type === 'refresh') {
      throw new UnauthorizedError()
    }
    
    const result = (await database.query('update session set removedAt = now() where removedAt is null and sessionId = ?', [payload.sessionId]))[0]
    
    return {
      removed: result.affectedRows
    }
  })

  app.setErrorHandler((error, request, reply) => {
    switch (error.name) {
      case 'ForbiddenError':
        reply.status(403).send({ message: error.message })
        break;
      case 'NotFoundError':
        reply.status(404).send({ message: error.message })
        break;
      case 'UnauthorizedError':
        reply.status(401).send({ message: error.message })
        break;
      default:
        reply.status(500).send({ message: 'Lo sentimos, se produjo un error.' })
        break;
    }
  })
  
  return app
}