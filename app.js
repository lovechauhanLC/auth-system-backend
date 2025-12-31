// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const db = require('./config/db'); // Import our DB connection
const authRoutes = require('./routes/authRoutes');
const { apiLimiter } = require('./middleware/rateLimiter');


const app = express();


// Middleware (Security & Parsing)
app.use(helmet()); // Secure HTTP headers
app.use(cors());   // Allow cross-origin requests
app.use(express.json()); // Parse JSON bodies

app.use('/api', apiLimiter);

// Routes
app.use('/api/auth', authRoutes);


// Test Route to verify DB connection
app.get('/health', async (req, res) => {
    try {
        // Run a simple query to check DB
        await db.query('SELECT 1');
        res.status(200).json({ status: 'OK', message: 'Database connected successfully' });
    } catch (err) {
        console.error('Database connection failed:', err);
        res.status(500).json({ status: 'Error', message: 'Database connection failed' });
    }
});

const PORT = process.env.PORT || 5001;

module.exports = app;