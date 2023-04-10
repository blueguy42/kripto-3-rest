const express = require('express');
const cors = require('cors');
require('dotenv').config();

const routes = require('./api');

const app = express();

// Enable CORS for all routes
app.use(cors());

// Enable JSON parsing for all routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
  res.send('Hello, world!');
});

app.use('/api/key', routes.key);

app.listen(process.env.PORT, () => {
  console.log('Kripto 3 REST service started on port 3000');
});