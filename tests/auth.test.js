// tests/auth.test.js
const request = require('supertest');
const app = require('../app'); // Import the app we separated
const db = require('../config/db');

// We need a unique email for every test run, or it will fail with "User already exists"
const testEmail = `test_${Date.now()}@example.com`; 

describe('Auth Endpoints', () => {

    // Test 1: Registration
    it('should register a new user successfully', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send({
                email: testEmail,
                password: 'TestPassword123!'
            });

        // Expectations
        expect(res.statusCode).toEqual(201); // Expect 201 Created
        expect(res.body).toHaveProperty('message'); // Expect a success message
    },15000); // Increased timeout for DB operations

    // Test 2: Login
    it('should login the user we just registered', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({
                email: testEmail,
                password: 'TestPassword123!'
            });

        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('accessToken'); // Should return tokens
        expect(res.body).toHaveProperty('refreshToken');
    });

    // Test 3: Login Fail
    it('should reject login with wrong password', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({
                email: testEmail,
                password: 'WRONG_PASSWORD'
            });

        expect(res.statusCode).toEqual(401); // Unauthorized
    });
    
    // Cleanup: Close DB connection after tests are done
    afterAll(async () => {
        await db.end();
    });
});