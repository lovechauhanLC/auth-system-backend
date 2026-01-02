// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/authMiddleware');

// GET /api/user/dashboard
router.get('/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: `Welcome back, ${req.user.email}!`,
        user: {
            id: req.user.id,
            email: req.user.email,
            role: req.user.role,
            status: req.user.status,
            joinedAt: req.user.created_at
        },
        systemData: {
            activeUsers: 124, // Fake data for UI demo
            serverStatus: 'Online',
            lastLogin: new Date().toISOString()
        }
    });
});

module.exports = router;