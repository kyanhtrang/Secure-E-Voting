import { describe, expect, it, vi } from 'vitest';
import { ApiError, createAuthClient } from './auth';
import { localAuthEnabled } from '../config';
import { localTarget } from '../../vite.config';

const token = 'A'.repeat(43);
const identity = { voter_id: '11111111-1111-4111-8111-111111111111' };
const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status });
function fixture() {
  const fetcher = vi.fn<typeof fetch>();
  fetcher.mockResolvedValueOnce(json({ access_token: token, token_type: 'Bearer' })).mockResolvedValueOnce(json(identity));
  return { api: createAuthClient(true, fetcher), fetcher };
}

describe('real auth wire contract', () => {
  it('uses only the three auth endpoints and never persists a token', async () => {
    const local = vi.spyOn(Storage.prototype, 'setItem');
    const { api, fetcher } = fixture();
    expect(await api.login('synthetic-user', 'synthetic-password')).toEqual(identity);
    fetcher.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await api.logout();
    expect(fetcher.mock.calls.map(call => call[0])).toEqual(['/api/v1/ra/auth/login', '/api/v1/ra/auth/me', '/api/v1/ra/auth/logout']);
    expect(fetcher.mock.calls[0]?.[1]?.headers).not.toHaveProperty('Authorization');
    for (const call of fetcher.mock.calls.slice(1)) expect(call[1]?.headers).toHaveProperty('Authorization', 'Bearer ' + token);
    for (const [url, options] of fetcher.mock.calls) {
      expect(String(url)).not.toContain(token); expect(options?.credentials).toBe('omit');
      expect(options?.cache).toBe('no-store'); expect(options?.redirect).toBe('error');
    }
    expect(local).not.toHaveBeenCalled();
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
  it.each([401, 422, 429, 500, 503])('sanitizes login failure %i without echoing the body', async status => {
    const canary = 'SENSITIVE-password-token-canary';
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({ detail: canary }, status));
    const api = createAuthClient(true, fetcher);
    const error: unknown = await api.login('user', canary).catch(value => value);
    expect(error).toBeInstanceOf(ApiError); expect(String(error)).not.toContain(canary);
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects malformed/noncanonical tokens before /me', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({ access_token: 'A'.repeat(42) + 'B', token_type: 'Bearer' }));
    const api = createAuthClient(true, fetcher);
    await expect(api.login('user', 'synthetic')).rejects.toMatchObject({ code: 'unavailable' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('requires /me to confirm login and rejects missing identity', async () => {
    const { api, fetcher } = fixture();
    fetcher.mockReset().mockResolvedValueOnce(json({ access_token: token, token_type: 'Bearer' })).mockResolvedValueOnce(json({ username: 'invented' }));
    await expect(api.login('user', 'synthetic')).rejects.toMatchObject({ code: 'unavailable' });
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
  });
  it('clears the token on expiry and never converts failed logout to success', async () => {
    const { api, fetcher } = fixture(); await api.login('user', 'synthetic');
    fetcher.mockResolvedValueOnce(json({ detail: 'sensitive' }, 503));
    await expect(api.logout()).rejects.toMatchObject({ code: 'unavailable' });
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
  });
  it('invalidates an expired/revoked session', async () => {
    const { api, fetcher } = fixture(); await api.login('user', 'synthetic');
    fetcher.mockResolvedValueOnce(json({}, 401));
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
  it('does not resurrect a token from a late login response body', async () => {
    let resolve!: (value: unknown) => void;
    const response = { status: 200, json: () => new Promise(value => { resolve = value; }) } as Response;
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
    const api = createAuthClient(true, fetcher);
    const pending = api.login('user', 'synthetic').catch(value => value as ApiError);
    await vi.waitFor(() => expect(resolve).toBeDefined());
    api.forget(); resolve({ access_token: token, token_type: 'Bearer' });
    expect(await pending).toMatchObject({ code: 'cancelled' });
    await expect(api.me()).rejects.toMatchObject({ code: 'expired' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('does not send any request in disabled mode', async () => {
    const fetcher = vi.fn<typeof fetch>();
    await expect(createAuthClient(false, fetcher).login('user', 'synthetic')).rejects.toMatchObject({ code: 'disabled' });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('maps network errors to safe text', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new Error('secret-password-canary'));
    await expect(createAuthClient(true, fetcher).login('user', 'synthetic')).rejects.toMatchObject({ code: 'unavailable' });
  });
});

describe('explicit local configuration', () => {
  it.each(['https://example.com', 'http://example.com', 'https://127.0.0.1'])('disables authentication at %s', address => {
    expect(localAuthEnabled(true, new URL(address))).toBe(false);
  });
  it('requires explicit activation even on loopback', () => {
    expect(localAuthEnabled(false, new URL('http://127.0.0.1'))).toBe(false);
    expect(localAuthEnabled(true, new URL('http://127.0.0.1'))).toBe(true);
  });
  it.each(['https://127.0.0.1:8000', 'http://example.com', 'http://user:password@127.0.0.1:8000', 'http://127.0.0.1:8000/api', 'http://127.0.0.1:8000?token=value'])('rejects unsafe proxy target %s', address => {
    expect(() => localTarget(address)).toThrow();
  });
  it('does not echo malformed configuration input', () => {
    expect(() => localTarget('sensitive-invalid-configuration-canary')).toThrow('The RA demo target must be a loopback HTTP origin.');
  });
});
