const db = require('../config/db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../utils/emailService');
const crypto = require('crypto');
const logger = require('../utils/logger');
require('dotenv').config();

exports.register = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) return res.status(400).json({ message: 'Required fields missing' });

        const [existing] = await db.execute('SELECT email FROM users WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(409).json({ message: 'User already exists' });

        const passwordHash = await bcrypt.hash(password, 10);
        const userId = uuidv4();

        await db.execute(
            'INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)',
            [userId, email, passwordHash]
        );

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = await bcrypt.hash(verificationToken, 10);

        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        await db.execute(
            'INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
            [userId, tokenHash, expiresAt]
        );

        const verificationLink = `http://localhost:5001/api/auth/verify-email?token=${verificationToken}&email=${email}`;

        await sendEmail({
            to: email,
            subject: 'Verify your Account',
            html: `
                <h1>Welcome!</h1>
                <p>Please click the link below to verify your email address:</p>
                <a href="${verificationLink}">Verify Email</a>
                <p>This link expires in 24 hours.</p>
            `
        });

        logger.info(`New user registered: ${email} (ID: ${userId})`);

        res.status(201).json({
            message: 'User registered. Please check your email to verify your account.'
        });

    } catch (error) {
        logger.error(`Registration error: ${error.message}`);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        
        if (users.length === 0) {
            logger.warn(`Failed login attempt: Email ${email} not found`);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = users[0];

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            logger.warn(`Failed login attempt: Invalid password for ${email}`);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const accessToken = jwt.sign(
            { userId: user.id, email: user.email }, 
            process.env.JWT_SECRET, 
            { expiresIn: '15m' }
        );

        const refreshToken = uuidv4(); 

        const refreshHash = await bcrypt.hash(refreshToken, 10);
        
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        await db.execute(
            'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
            [user.id, refreshHash, expiresAt]
        );

        logger.info(`Login successful: User ${user.id} (${email})`);

        res.status(200).json({
            message: 'Login successful',
            accessToken,
            refreshToken
        });

    } catch (error) {
        logger.error(`Login error: ${error.message}`);
        res.status(500).json({ message: 'Server error during login' });
    }
};

exports.refreshToken = async (req, res) => {
    try {
        const { email, refreshToken } = req.body;

        if (!email || !refreshToken) {
            return res.status(400).json({ message: 'Email and Refresh Token are required' });
        }

        const [users] = await db.execute('SELECT id, email FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid email' });
        }
        const user = users[0];

        const [tokens] = await db.execute(
            'SELECT * FROM refresh_tokens WHERE user_id = ? AND is_revoked = FALSE',
            [user.id]
        );

        let validTokenRow = null;
        for (const tokenRow of tokens) {
            const isMatch = await bcrypt.compare(refreshToken, tokenRow.token_hash);
            if (isMatch) {
                validTokenRow = tokenRow;
                break;
            }
        }

        if (!validTokenRow) {
            return res.status(403).json({ message: 'Invalid Refresh Token' });
        }

        if (new Date(validTokenRow.expires_at) < new Date()) {
            return res.status(403).json({ message: 'Refresh Token Expired' });
        }

        await db.execute('UPDATE refresh_tokens SET is_revoked = TRUE WHERE id = ?', [validTokenRow.id]);

        const newAccessToken = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        const newRefreshToken = uuidv4();
        const newRefreshHash = await bcrypt.hash(newRefreshToken, 10);

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        await db.execute(
            'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
            [user.id, newRefreshHash, expiresAt]
        );

        logger.info(`Token refreshed for user: ${user.email}`);

        res.json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        logger.warn(`Suspicious: Invalid refresh token attempt for ${email}`);
        res.status(500).json({ message: 'Server error during token refresh' });
    }
};

exports.logout = async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({ message: 'Refresh Token is required' });
        }

        const [tokens] = await db.execute('SELECT * FROM refresh_tokens WHERE is_revoked = FALSE');

        let tokenToRevoke = null;
        for (const tokenRow of tokens) {
            const isMatch = await bcrypt.compare(refreshToken, tokenRow.token_hash);
            if (isMatch) {
                tokenToRevoke = tokenRow;
                break;
            }
        }

        if (tokenToRevoke) {
            await db.execute(
                'UPDATE refresh_tokens SET is_revoked = TRUE WHERE id = ?',
                [tokenToRevoke.id]
            );
        }

        logger.info(`Logout: Refresh token revoked`);

        res.status(200).json({ message: 'Logged out successfully' });

    } catch (error) {
        logger.error(`Logout error: ${error.message}`);
        res.status(500).json({ message: 'Server error during logout' });
    }
};

exports.verifyEmail = async (req, res) => {
    try {
        const { token, email } = req.query;

        if (!token || !email) {
            return res.status(400).send('Invalid link');
        }

        const [users] = await db.execute('SELECT id, is_verified FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(400).send('User not found');

        const user = users[0];
        if (user.is_verified) return res.status(200).send('Email already verified. You can login.');

        const [records] = await db.execute(
            'SELECT * FROM email_verifications WHERE user_id = ?',
            [user.id]
        );

        if (records.length === 0) return res.status(400).send('Invalid or expired token');

        let validRecord = null;
        for (const record of records) {
            const isMatch = await bcrypt.compare(token, record.token_hash);
            if (isMatch) {
                validRecord = record;
                break;
            }
        }

        if (!validRecord) return res.status(400).send('Invalid token');

        if (new Date(validRecord.expires_at) < new Date()) {
            return res.status(400).send('Token expired');
        }

        await db.execute('UPDATE users SET is_verified = TRUE WHERE id = ?', [user.id]);

        await db.execute('DELETE FROM email_verifications WHERE id = ?', [validRecord.id]);

        res.send('<h1>Email Verified Successfully!</h1><p>You can now login.</p>');

    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: 'Email is required' });

        const [users] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(200).json({ message: 'If that email exists, a reset link has been sent.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = await bcrypt.hash(resetToken, 10);
        
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);

        await db.execute(
            'INSERT INTO password_resets (email, token_hash, expires_at) VALUES (?, ?, ?)',
            [email, tokenHash, expiresAt]
        );

        const resetLink = `http://localhost:5001/api/auth/reset-password?token=${resetToken}&email=${email}`;
        
        await sendEmail({
            to: email,
            subject: 'Password Reset Request',
            html: `
                <p>You requested a password reset.</p>
                <p>Click this link to set a new password:</p>
                <a href="${resetLink}">Reset Password</a>
                <p>This link expires in 1 hour.</p>
            `
        });

        logger.info(`Password reset requested for: ${email}`);
        res.status(200).json({ message: 'If that email exists, a reset link has been sent.' });

    } catch (error) {
        logger.error(`Forgot Password Error: ${error.message}`);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { email, token, newPassword } = req.body;

        if (!email || !token || !newPassword) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const [requests] = await db.execute(
            'SELECT * FROM password_resets WHERE email = ? ORDER BY id DESC LIMIT 1', 
            [email]
        );

        if (requests.length === 0) return res.status(400).json({ message: 'Invalid or expired token' });
        
        const resetRequest = requests[0];

        if (new Date(resetRequest.expires_at) < new Date()) {
            return res.status(400).json({ message: 'Token expired' });
        }

        const isMatch = await bcrypt.compare(token, resetRequest.token_hash);
        if (!isMatch) return res.status(400).json({ message: 'Invalid token' });

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE users SET password_hash = ? WHERE email = ?', [newPasswordHash, email]);

        await db.execute('DELETE FROM password_resets WHERE email = ?', [email]);

        logger.info(`Password reset successful for: ${email}`);
        res.status(200).json({ message: 'Password has been reset successfully. You can now login.' });

    } catch (error) {
        logger.error(`Reset Password Error: ${error.message}`);
        res.status(500).json({ message: 'Server error' });
    }
};