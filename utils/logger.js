// utils/logger.js
const winston = require('winston');

// Define log format
const logFormat = winston.format.printf(({ level, message, timestamp }) => {
    return `${timestamp} [${level.toUpperCase()}]: ${message}`;
});

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        logFormat
    ),
    transports: [
        // 1. Write all logs to console (so you see them while developing)
        new winston.transports.Console(),
        
        // 2. Write all logs with level 'error' to 'error.log'
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        
        // 3. Write all logs to 'app.log'
        new winston.transports.File({ filename: 'logs/app.log' })
    ],
});

module.exports = logger;