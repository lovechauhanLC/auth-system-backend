// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = (req, res, next) => {
    // 1. Get the token from the header
    // Format is usually: "Bearer <token>"
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    // Split "Bearer <token>" to get just the token part
    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. Invalid token format.' });
    }

    try {
        // 2. Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // 3. Attach user info to the request object
        // Now any route after this can use `req.user`
        req.user = decoded;

        // 4. Move to the next middleware/route
        next(); 
    } catch (error) {
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
};