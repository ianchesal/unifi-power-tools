import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../../src/server.js';
import { appDeps, baseConfig, loginAgent, TEST_PASSWORD } from '../helpers.js';

function app(configOverrides: Partial<typeof baseConfig> = {}) {
  return createApp(appDeps(), { ...baseConfig, ...configOverrides });
}

describe('dashboard auth', () => {
  it('rejects /api without a session', async () => {
    const res = await request(app()).get('/api/findings');
    expect(res.status).toBe(401);
  });

  it('rejects a wrong password', async () => {
    const res = await request(app()).post('/api/auth/login').send({ password: 'nope' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Invalid password' });
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('rejects a login with no password field', async () => {
    const res = await request(app()).post('/api/auth/login').send({});
    expect(res.status).toBe(401);
  });

  it('sets an HttpOnly, SameSite=Strict cookie (not Secure over plain HTTP) and lets /api through', async () => {
    const a = app();
    const agent = request.agent(a);
    const login = await agent.post('/api/auth/login').send({ password: TEST_PASSWORD });
    expect(login.status).toBe(200);
    const cookie = String(login.headers['set-cookie']);
    expect(cookie).toMatch(/^upt_session=/);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Strict/);
    expect(cookie).not.toMatch(/Secure/);
    expect((await agent.get('/api/findings')).status).toBe(200);
  });

  it('logout clears the cookie and later calls are 401', async () => {
    const agent = await loginAgent(app());
    const out = await agent.post('/api/auth/logout').send({});
    expect(out.status).toBe(200);
    expect(String(out.headers['set-cookie'])).toMatch(/upt_session=;/);
    expect((await agent.get('/api/findings')).status).toBe(401);
  });

  it('GET /api/auth/session is 401 signed out and 200 signed in', async () => {
    const a = app();
    expect((await request(a).get('/api/auth/session')).status).toBe(401);
    expect((await (await loginAgent(a)).get('/api/auth/session')).status).toBe(200);
  });

  it('rejects a tampered session cookie', async () => {
    const a = app();
    const res = await request(a).get('/api/findings').set('Cookie', 'upt_session=9999999999999.AAAA');
    expect(res.status).toBe(401);
  });

  it('a session from before a password change is rejected', async () => {
    const deps = appDeps();
    const before = createApp(deps, baseConfig);
    const login = await request(before).post('/api/auth/login').send({ password: TEST_PASSWORD });
    const cookie = String(login.headers['set-cookie']).split(';')[0];
    const after = createApp(deps, { ...baseConfig, dashboardPassword: 'changed' });
    expect((await request(after).get('/api/findings').set('Cookie', cookie)).status).toBe(401);
  });

  it('a session survives a restart with the same password and lens.db', async () => {
    const deps = appDeps();
    const login = await request(createApp(deps, baseConfig))
      .post('/api/auth/login')
      .send({ password: TEST_PASSWORD });
    const cookie = String(login.headers['set-cookie']).split(';')[0];
    const restarted = createApp(deps, baseConfig);
    expect((await request(restarted).get('/api/findings').set('Cookie', cookie)).status).toBe(200);
  });

  it('rate-limits failed logins: the 11th within the window is 429', async () => {
    const a = app();
    for (let i = 0; i < 10; i++) {
      expect((await request(a).post('/api/auth/login').send({ password: 'x' })).status).toBe(401);
    }
    expect((await request(a).post('/api/auth/login').send({ password: 'x' })).status).toBe(429);
  });

  it('/health and /ready stay open', async () => {
    const a = app();
    expect((await request(a).get('/health')).status).toBe(200);
    expect((await request(a).get('/ready')).status).toBe(200);
  });

  it('requires JSON on state-changing /api calls', async () => {
    const agent = await loginAgent(app());
    expect((await agent.post('/api/analysis/run')).status).toBe(415);
    expect(
      (await agent.post('/api/analysis/run').type('form').send('a=1')).status
    ).toBe(415);
    expect((await agent.post('/api/analysis/run').send({})).status).toBe(200);
  });

  it('marks the cookie Secure behind a trusted proxy that says https', async () => {
    const res = await request(app({ trustProxy: '1' }))
      .post('/api/auth/login')
      .set('X-Forwarded-Proto', 'https')
      .send({ password: TEST_PASSWORD });
    expect(String(res.headers['set-cookie'])).toMatch(/Secure/);
  });

  it('ignores X-Forwarded-Proto when no proxy is trusted', async () => {
    const res = await request(app())
      .post('/api/auth/login')
      .set('X-Forwarded-Proto', 'https')
      .send({ password: TEST_PASSWORD });
    expect(String(res.headers['set-cookie'])).not.toMatch(/Secure/);
  });

  it('/mcp traffic does not use up the dashboard rate-limit budget', async () => {
    const a = app();
    for (let i = 0; i < 301; i++) {
      const res = await request(a).post('/mcp').set('Authorization', 'Bearer wrong').send({});
      expect(res.status).toBe(401);
    }
    expect((await request(a).get('/api/auth/session')).status).toBe(401);
    expect((await (await loginAgent(a)).get('/api/findings')).status).toBe(200);
  });
});

