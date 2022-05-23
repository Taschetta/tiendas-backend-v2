import mysql2 from 'mysql2/promise'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

import useApp from './app.js'

const app = await useApp({ mysql2, bcrypt, jwt }, { logger: true })

app.listen(3000, (error) => {
  if(error) {
    app.log.error(error)
    process.exit(1)
  }
})