// backend/setup-db.js
const pool = require('./db');

const setupDatabase = async () => {
  try {
    console.log("⏳ Setting up database schema...");

    // 1. USERS TABLE (Core Identity)
    // UUID for ID, boolean for email verification, separate status column
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id CHAR(36) PRIMARY KEY, -- UUID
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin', 'manager') DEFAULT 'user',
        status ENUM('active', 'locked') DEFAULT 'active',
        email_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Table 'users' ready.");

    // 2. AUTH SESSIONS (For Refresh Tokens & Security Audit)
    // Stores HASH of the token, never the raw token.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id CHAR(36) PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        refresh_token_hash VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45), -- Supports IPv6
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    console.log("✅ Table 'auth_sessions' ready.");

    // 3. EMAIL VERIFICATIONS (For Signup flow)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        token VARCHAR(255) PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    console.log("✅ Table 'email_verifications' ready.");

    // 4. PASSWORD RESETS (For Forgot Password flow)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        token VARCHAR(255) PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    console.log("✅ Table 'password_resets' ready.");

    console.log("🚀 All tables created successfully!");
    process.exit();

  } catch (error) {
    console.error("❌ Schema Error:", error.message);
    process.exit(1);
  }
};

setupDatabase();