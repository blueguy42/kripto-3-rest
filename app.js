const express = require('express');
const cors = require('cors');
require('dotenv').config();

const routes = require('./routes');

const app = express();

// Enable CORS for all routes
app.use(cors());

// Enable JSON parsing for all routes
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  res.send('Hello, world!');
});

app.use('/key', routes.key);

app.listen(process.env.PORT, () => {
  console.log('Kripto 3 REST service started on port 3000');
});