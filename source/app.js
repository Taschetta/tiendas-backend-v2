import fastify from "fastify"

export default async function useApp(packages, options) {
  const { jwt, mysql2 } = packages
  
  const connection = await mysql2.createConnection()
  
  const app = fastify(options)

  app.post('/session', async (request) => {
    const EXPIRATION_ACCESS = parseInt(process.env.JWT_EXPIRATION_ACCESS)
    const EXPIRATION_REFRESH = parseInt(process.env.JWT_EXPIRATION_REFRESH)
    const SECRET = process.env.JWT_SECRET

    const email = request.body.email

    const user = (await connection.query('select id, roleId, active, password from user where email = ? limit 1', [email]))[0][0]
    
    const userId = user.id
    const roleId = user.roleId
    
    const accessToken = jwt.sign({ userId, roleId, type: 'access' }, SECRET, { expiresIn: EXPIRATION_ACCESS })
    const refreshToken = jwt.sign({ userId, roleId, type: 'refresh' }, SECRET, { expiresIn: EXPIRATION_REFRESH })

    return {
      accessToken,
      refreshToken,
      expiresIn: EXPIRATION_ACCESS,
    }
  })

  return app
}