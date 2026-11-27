// tests/endpoints/auth.test.js – covers POST /api/auth/register, login, changePassword, GET /me
const request = require('supertest');
const app     = require('../../src/app');

describe('Auth – POST /api/auth/register', () => {
  it('creates a user and returns a JWT', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ name: 'Alice', email: 'alice@test.com', password: 'Password1!' });
    expect(res.status).toBe(201);
    expect(res.body.token).toMatch(/^ey/);
    expect(res.body.user.email).toBe('alice@test.com');
    expect(res.body.user.password).toBeUndefined();
  });

  it('rejects a duplicate email', async () => {
    await request(app).post('/api/auth/register')
      .send({ name: 'A', email: 'dup@test.com', password: 'Password1!' });
    const res = await request(app).post('/api/auth/register')
      .send({ name: 'B', email: 'dup@test.com', password: 'Password1!' });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('DUPLICATE');
  });

  it('rejects a password shorter than 8 characters', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ name: 'A', email: 'short@test.com', password: '123' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rejects a missing email', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ name: 'A', password: 'Password1!' });
    expect(res.status).toBe(400);
  });
});

describe('Auth – POST /api/auth/login', () => {
  beforeEach(async () => {
    await request(app).post('/api/auth/register')
      .send({ name: 'Bob', email: 'bob@test.com', password: 'Password1!' });
  });

  it('returns a token for correct credentials', async () => {
    const res = await request(app).post('/api/auth/login')
      .send({ email: 'bob@test.com', password: 'Password1!' });
    expect(res.status).toBe(200);
    expect(res.body.token).toMatch(/^ey/);
  });

  it('rejects wrong password', async () => {
    const res = await request(app).post('/api/auth/login')
      .send({ email: 'bob@test.com', password: 'WrongPass!' });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_INVALID');
  });

  it('rejects an unknown email', async () => {
    const res = await request(app).post('/api/auth/login')
      .send({ email: 'nobody@test.com', password: 'Password1!' });
    expect(res.status).toBe(401);
  });
});

describe('Auth – GET /api/auth/me', () => {
  it('returns the authenticated user', async () => {
    const reg = await request(app).post('/api/auth/register')
      .send({ name: 'Carol', email: 'carol@test.com', password: 'Password1!' });
    const res = await request(app).get('/api/auth/me')
      .set('Authorization', `Bearer ${reg.body.token}`);
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('carol@test.com');
  });

  it('returns 401 without a token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_REQUIRED');
  });

  it('returns 401 with an invalid token', async () => {
    const res = await request(app).get('/api/auth/me')
      .set('Authorization', 'Bearer invalid.token.value');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_INVALID');
  });
});

describe('Auth – POST /api/auth/changePassword', () => {
  let token;

  beforeEach(async () => {
    const reg = await request(app).post('/api/auth/register')
      .send({ name: 'Dave', email: 'dave@test.com', password: 'OldPass1!' });
    token = reg.body.token;
  });

  it('changes the password successfully', async () => {
    const res = await request(app).post('/api/auth/changePassword')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'OldPass1!', newPassword: 'NewPass1!' });
    expect(res.status).toBe(200);

    // Logging in with the new password now works
    const login = await request(app).post('/api/auth/login')
      .send({ email: 'dave@test.com', password: 'NewPass1!' });
    expect(login.status).toBe(200);
  });

  it('rejects wrong currentPassword', async () => {
    const res = await request(app).post('/api/auth/changePassword')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'WrongOld!', newPassword: 'NewPass1!' });
    expect(res.status).toBe(401);
  });

  it('rejects newPassword identical to currentPassword', async () => {
    const res = await request(app).post('/api/auth/changePassword')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'OldPass1!', newPassword: 'OldPass1!' });
    expect(res.status).toBe(400);
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/auth/changePassword')
      .send({ currentPassword: 'OldPass1!', newPassword: 'NewPass1!' });
    expect(res.status).toBe(401);
  });
});
