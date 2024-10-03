const express = require('express');
require('dotenv').config();

const connectDB = require('./config/db');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();




// Connect Database
connectDB();


// Init Middleware
app.use(express.json());
app.use(cors());
app.use(bodyParser.json());

// Define Routes
app.use('/api/auth', require('./routes/auth'));

const PORT = process.env.PORT || 5001;


app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
