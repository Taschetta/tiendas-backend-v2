import fastify from "fastify"

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

  app.post('/sessions', async (request, response) => {
    const EXPIRATION_ACCESS = parseInt(process.env.JWT_EXPIRATION_ACCESS)
    const EXPIRATION_REFRESH = parseInt(process.env.JWT_EXPIRATION_REFRESH)
    const SECRET = process.env.JWT_SECRET

    const email = request.body.email
    const password = request.body.password

    const user = (await database.query('select id, roleId, active, password from user where email = ? limit 1', [email]))[0][0]
    
    if(!user) {
      response.status(404).send({ message: 'No pudimos encontrar tu cuenta. ¿El email que ingresaste es el correcto?' })
    }

    if(!user.active) {
      response.status(403).send({ message: 'Lo sentimos, tu cuenta se encuentra inactiva. Contactate con un administrador para poder acceder.' })
    }
    
    const passwordsMatch = await bcrypt.compare(password, user.password)
    
    if(!passwordsMatch) {
      response.status(403).send({ message: 'La contraseña que ingresaste es incorrecta.' })
    }
    
    const userId = user.id
    const roleId = user.roleId
    
    const accessToken = jwt.sign({ userId, roleId, type: 'access' }, SECRET, { expiresIn: EXPIRATION_ACCESS })
    const refreshToken = jwt.sign({ userId, roleId, type: 'refresh' }, SECRET, { expiresIn: EXPIRATION_REFRESH })

    const date = new Date(Date.now())
    
    await database.query('insert into session (userId, refreshToken, createdAt, updatedAt) values (?)', [
      [userId, refreshToken, date, date]
    ])
    
    return {
      accessToken,
      refreshToken,
      expiresIn: EXPIRATION_ACCESS,
    }
  })

  app.delete('/sessions', async (request, response) => {
    const SECRET = process.env.JWT_SECRET

    const authorization = request.headers.authorization

    if(!authorization) {
      response.status(403).send({ message: 'No tenes permiso para acceder a este recurso.' })
    }
    
    const accessTokenParts = authorization.split(' ')

    if(accessTokenParts.length !== 2 || accessTokenParts[0] !== 'Bearer') {
      response.status(403).send({ message: 'No tenes permiso para acceder a este recurso.' })
    }
    
    let payload
    try {
      payload = jwt.verify(accessTokenParts[1], SECRET)      
    } catch (error) {
      response.status(403).send({ message: 'No tenes permiso para acceder a este recurso.' })
      return
    }
    
    const result = (await database.query('update session set removedAt = now() where removedAt is null and userId = ?', [payload.userId]))[0]
    
    return {
      removed: result.affectedRows
    }
  })

  return app
}