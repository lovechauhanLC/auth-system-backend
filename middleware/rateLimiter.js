const rateLimit = require('express-rate-limit');

exports.authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { 
        message: 'Too many login attempts from this IP, please try again after 1 minutes' 
    },
    standardHeaders: true,
    legacyHeaders: false,
});

exports.apiLimiter = rateLimit({
    windowMs: 60 * 1000, 
    max: 100, 
    message: {
        message: 'Too many requests, please try again later.'
    }
});