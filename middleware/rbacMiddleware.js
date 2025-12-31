exports.requireRole = (requiredRole) => {
    return (req, res, next) => {
        // req.user is already populated by authMiddleware
        if (!req.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        // The Logic:
        // If route requires 'admin', user MUST be 'admin'.
        // If route requires 'manager', user can be 'manager' OR 'admin' (optional hierarchy).
        if (req.user.role !== requiredRole && req.user.role !== 'admin') {
            return res.status(403).json({ 
                message: `Access denied. You are a ${req.user.role}, but this requires ${requiredRole}.` 
            });
        }

        next();
    };
};