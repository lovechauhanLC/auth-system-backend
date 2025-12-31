const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authenticateToken = require('../middleware/authMiddleware');
const { authLimiter } = require('../middleware/rateLimiter');
const { requireRole } = require('../middleware/rbacMiddleware');

router.post('/login', authLimiter, authController.login);
router.post('/register', authLimiter, authController.register);

router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);
router.get('/verify-email', authController.verifyEmail);
router.post('/forgot-password', authLimiter, authController.forgotPassword); 
router.post('/reset-password', authLimiter, authController.resetPassword);   

router.get('/profile', authenticateToken, (req, res) => {
    res.json({ 
        message: 'This is a protected route', 
        user: req.user 
    });
});

// --- ADMIN ONLY ROUTE ---
router.get('/admin/dashboard', authenticateToken, requireRole('admin'), (req, res) => {
    res.json({ message: 'Welcome, Admin! You can see all users here.' });
});

// --- MANAGER ONLY ROUTE ---
router.get('/manager/reports', authenticateToken, requireRole('manager'), (req, res) => {
    res.json({ message: 'Welcome, Manager! Here are the reports.' });
});

module.exports = router;