'use strict'

const debug = require('debug')('week8')

require('./startup/database')()

const express = require('express')

const app = express()

app.use(express.json())
app.use(require('express-mongo-sanitize')())

app.use('/auth', require('./routes/auth'))
app.use('/api/cars', require('./routes/cars'))
app.use('/api/people', require('./routes/people'))

// const port = process.env.PORT || 5000
const port = process.env.PORT || 3030

app.listen(port, () => debug(`Express is listening on port ${port} ...`))
