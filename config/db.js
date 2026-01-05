const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST, 
    user: process.env.DB_USER, 
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME,
    
    // 👇 NEW: Aiven runs on a custom port (13638), not 3306
    port: process.env.DB_PORT, 
    
    // 👇 NEW: Aiven requires an SSL connection
    ssl: {
        rejectUnauthorized: false
    },
    
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = pool.promise();