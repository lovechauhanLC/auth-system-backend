# 🛡️ Secure Node.js Authentication System (Backend)

A robust, production-ready Authentication API built with **Node.js, Express, and MySQL**.  
It features **Role-Based Access Control (RBAC)**, Dual-Token Authentication (Access + Refresh), and secure Password Reset functionality.

---

## 🚀 Features

- **User Registration:** Secure signup with Bcrypt password hashing and UUIDs.
- **Role-Based Registration:** Create `Admin` or `Manager` accounts using a secure Secret Key (`ADMIN_SECRET`).
- **Dual-Token Auth:** Short-lived Access Tokens (JWT) and persistent Refresh Tokens.
- **RBAC Middleware:** Protect routes based on roles (`admin`, `manager`, `user`).
- **Password Reset:** Secure email flow using temporary tokens and Nodemailer.
- **Security Best Practices:**
  - SQL Injection protection (Prepared Statements)
  - Account lockout after 5 failed login attempts
  - CORS & Helmet security headers

---

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MySQL (`mysql2/promise`)
- **Authentication:** JSON Web Tokens (JWT)
- **Security:** Bcrypt.js, Dotenv, Crypto
- **Email:** Nodemailer

---

## 📂 Project Structure

```text
backend/
├── controllers/    # Request handling logic (Auth, User)
├── middleware/     # Auth, RBAC, error handling
├── routes/         # API route definitions
├── config/         # Database connection & logger
├── services/       # Email service & helpers
├── server.js       # Application entry point
└── .env            # Environment variables (gitignored)
```

---

## ⚙️ Setup & Installation

### 1. Prerequisites

- Node.js v16 or higher
- MySQL Server (local or cloud)

---

### 2. Install Dependencies

```bash
npm install
```

---

### 3. Environment Variables

Create a `.env` file in the root directory:

```env
PORT=5001

DB_HOST=localhost
DB_USER=root
DB_PASS=your_mysql_password
DB_NAME=auth_system

# Security Secrets (use strong random strings)
JWT_SECRET=super_secret_access_key_123
REFRESH_TOKEN_SECRET=super_secret_refresh_key_456
ADMIN_SECRET=MySuperSecretKey2025!

# Email (Password Reset)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

---

### 4. Database Setup

Run the following SQL:

```sql
CREATE DATABASE IF NOT EXISTS auth_system;
USE auth_system;

CREATE TABLE users (
    id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin', 'manager') DEFAULT 'user',
    refresh_token TEXT,
    failed_login_attempts INT DEFAULT 0,
    lockout_until DATETIME DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'locked') DEFAULT 'active'
);

CREATE TABLE password_resets (
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (email)
);
```

---

### 5. Run the Server

```bash
# Development (nodemon)
npm run dev

# Production
node server.js
```

Server runs at: `http://localhost:5001`

---

## 📡 API Endpoints

### Authentication

| Method | Endpoint | Description |
|------|---------|-------------|
| POST | `/api/auth/register` | Register user (Admin requires `adminSecret`) |
| POST | `/api/auth/login` | Login and receive access & refresh tokens |
| POST | `/api/auth/refresh-token` | Generate new access token |
| POST | `/api/auth/forgot-password` | Request password reset email |
| POST | `/api/auth/reset-password` | Reset password using token |

---

### Protected Routes (RBAC)

| Method | Endpoint | Access |
|------|---------|--------|
| GET | `/api/user/dashboard` | Logged-in users |
| GET | `/api/auth/admin/dashboard` | Admin only |
| GET | `/api/auth/manager/reports` | Manager only |

---

## 🧪 Testing (Postman)

1. Register user → `/api/auth/register`
2. Login → `/api/auth/login`
3. Copy `accessToken`
4. Use **Bearer Token** in Authorization header
5. Access protected routes
6. Test refresh token via `/refresh-token`

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

---

## 📝 License

Distributed under the MIT License.