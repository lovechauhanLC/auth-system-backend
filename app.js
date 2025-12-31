require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const db = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const { apiLimiter } = require('./middleware/rateLimiter');


const app = express();


app.use(helmet());
app.use(cors());
app.use(express.json());

app.use('/api', apiLimiter);

app.use('/api/auth', authRoutes);

app.get('/health', async (req, res) => {
    try {
        await db.query('SELECT 1');
        res.status(200).json({ status: 'OK', message: 'Database connected successfully' });
    } catch (err) {
        console.error('Database connection failed:', err);
        res.status(500).json({ status: 'Error', message: 'Database connection failed' });
    }
});

const PORT = process.env.PORT || 5001;

module.exports = app;