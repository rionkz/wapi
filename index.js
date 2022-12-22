const express = require('express')
const app = express()
const port = 3000
//MIDDLEWARES
app.use(express.json());
// Require API routes

app.get('/', (req, res) => {
    res.send('Hello World!')
  })

// Import API Routes
app.use('/api',require('./routes/generate'));


app.listen(port, () => {
    console.log(`Server listening on port ${port}`)
  })

