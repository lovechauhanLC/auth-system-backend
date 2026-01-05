require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const db = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const { apiLimiter } = require('./middleware/rateLimiter');
const userRoutes = require('./routes/userRoutes');


const app = express();


app.use(helmet());
app.use(cors({
    origin: [
        "http://localhost:5173",
        "http://localhost:3000",
        "https://auth-system-frontend-wine.vercel.app"
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));
app.use(express.json());

app.use('/api', apiLimiter);

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

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