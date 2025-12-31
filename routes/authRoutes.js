// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authenticateToken = require('../middleware/authMiddleware');
const { authLimiter } = require('../middleware/rateLimiter');

// Apply the strict authLimiter to login and register routes
router.post('/login', authLimiter, authController.login);
router.post('/register', authLimiter, authController.register);

// Public Routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);
router.get('/verify-email', authController.verifyEmail);
router.post('/forgot-password', authLimiter, authController.forgotPassword); 
router.post('/reset-password', authLimiter, authController.resetPassword);   

// Protected Route (Requires Login)
router.get('/profile', authenticateToken, (req, res) => {
    // Because the middleware ran first, we have req.user!
    res.json({ 
        message: 'This is a protected route', 
        user: req.user 
    });
});

module.exports = router;