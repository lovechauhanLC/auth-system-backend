/* config/fix-setup-db.js */
// NOTE: Ensure this path is correct based on where you run the file
const pool = require('./db'); 

const fixDatabase = async () => {
  try {
    console.log("🔥 DROPING OLD TABLES (Cleaning up mismatches)...");
    
    // 1. DISABLE FOREIGN KEY CHECKS (The Fix)
    // This allows us to drop tables in any order without errors
    await pool.query('SET FOREIGN_KEY_CHECKS = 0');

    // 2. DROP ALL TABLES
    await pool.query('DROP TABLE IF EXISTS auth_audit_logs');
    await pool.query('DROP TABLE IF EXISTS auth_sessions'); // The culprit from your error
    await pool.query('DROP TABLE IF EXISTS email_verifications');
    await pool.query('DROP TABLE IF EXISTS password_resets');
    await pool.query('DROP TABLE IF EXISTS refresh_tokens');
    await pool.query('DROP TABLE IF EXISTS users');
    
    // 3. RE-ENABLE FOREIGN KEY CHECKS
    await pool.query('SET FOREIGN_KEY_CHECKS = 1');

    console.log("✅ Old tables deleted.");
    console.log("🏗️ CREATING NEW SCHEMA (Matching your screenshots)...");

    // 4. CREATE USERS TABLE (Matches Image 2)
    await pool.query(`
      CREATE TABLE users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin', 'manager') DEFAULT 'user',
        status ENUM('active', 'locked', 'suspended') DEFAULT 'active',
        is_verified TINYINT(1) DEFAULT 0,
        failed_login_attempts INT DEFAULT 0,
        lockout_until TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Table 'users' created.");

    // 5. CREATE EMAIL VERIFICATIONS (Matches Image 3)
    await pool.query(`
      CREATE TABLE email_verifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
      );
    `);
    console.log("✅ Table 'email_verifications' created.");

    // 6. CREATE REFRESH TOKENS (Matches Image 5)
    await pool.query(`
      CREATE TABLE refresh_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_revoked TINYINT(1) DEFAULT 0,
        replaced_by_token_hash VARCHAR(255) NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    console.log("✅ Table 'refresh_tokens' created.");

    // 7. CREATE PASSWORD RESETS (Matches Image 4)
    await pool.query(`
      CREATE TABLE password_resets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    console.log("✅ Table 'password_resets' created.");

    // 8. CREATE AUDIT LOGS (Matches Image 6)
    await pool.query(`
      CREATE TABLE auth_audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(36),
        action VARCHAR(50) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Table 'auth_audit_logs' created.");

    console.log("🚀 DATABASE SYNC COMPLETE! Your Cloud DB now matches your Code.");
    process.exit();

  } catch (error) {
    console.error("❌ Error updating database:", error);
    process.exit(1);
  }
};

fixDatabase();