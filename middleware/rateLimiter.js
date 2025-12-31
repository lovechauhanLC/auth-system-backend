// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');

// 1. Strict Limiter (For Login/Register)
// If someone fails login 5 times in 15 minutes, block them.
exports.authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: { 
        message: 'Too many login attempts from this IP, please try again after 15 minutes' 
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// 2. General Limiter (For the rest of the API)
// Allow 100 requests per 15 minutes (generous for normal users)
exports.apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: {
        message: 'Too many requests, please try again later.'
    }
});