import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Link, MemoryRouter } from 'react-router';
import { Profiler } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { AdminFailure, createAdminClient, type AdminClient, type Election } from './client';
import { AdminWorkspace } from './workspace';

describe('independent administrator boundary', () => {
  it('keeps the token in its closure, omits cookies and refuses other APIs', async () => {
    const transport = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'adm1.' + 'A'.repeat(43), token_type: 'bearer' })))
      .mockResolvedValueOnce(new Response('{"admin_id":"11111111-1111-4111-8111-111111111111","role":"ELECTION_ADMIN"}')).mockResolvedValueOnce(new Response('{"elections":[]}'));
    const client = createAdminClient(transport);
    await client.login('synthetic-admin', 'synthetic-test-only');
    await client.list();
    expect(transport.mock.calls[0]?.[1].headers.Authorization).toBeUndefined();
    expect(transport.mock.calls[2]?.[1].headers.Authorization).toMatch(/^Bearer adm1\./);
    for (const [path, options] of transport.mock.calls) {
      expect(path.startsWith('/api/v1/admin/')).toBe(true);
      expect(options.credentials).toBe('omit'); expect(options.cache).toBe('no-store');
    }
    await expect(client.change('../ra/auth/me', '', 'GET', {})).rejects.toBeInstanceOf(AdminFailure);
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
  });
  it('rejects voter bearer format and sanitizes error contents', async () => {
    const client = createAdminClient(vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'A'.repeat(43), token_type: 'bearer' }))));
    await expect(client.login('x', 'x')).rejects.toThrow('Administrative service unavailable');
    const failing = createAdminClient(vi.fn().mockResolvedValue(new Response('sensitive-server-error', { status: 503 })));
    await expect(failing.list()).rejects.toThrow('Administrative service unavailable');
  });
  it('requires separate sign in, then presents a real empty state and logout', async () => {
    const client = { login: vi.fn(), forget: vi.fn(), logout: vi.fn(), list: vi.fn().mockResolvedValue({ elections: [] }), keys: vi.fn().mockResolvedValue({ keysets: [] }) } as unknown as AdminClient;
    render(<MemoryRouter><AdminWorkspace client={client} /></MemoryRouter>);
    expect(screen.queryByRole('button', { name: 'Create draft' })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Admin username'), { target: { value: 'synthetic-admin' } });
    fireEvent.change(screen.getByLabelText('Admin password'), { target: { value: 'synthetic-test-only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in as administrator' }));
    expect(await screen.findByText('No managed elections')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Admin logout' }));
    expect(await screen.findByRole('heading', { name: 'Administrator sign-in' })).toBeInTheDocument();
    expect(client.logout).toHaveBeenCalledTimes(1);
  });
  it('requires confirmation before opening and clears expired sessions', async () => {
    const election = { election_id: '11111111-1111-4111-8111-111111111111', title: 'Synthetic review election', status: 'DRAFT', phase: 'FROZEN', revision: 2,
      opens_at: '2026-01-01T00:00:00Z', closes_at: '2027-01-01T00:00:00Z', candidates: [], ra_ready: false, keyset_id: 'synthetic-keyset', config_hash: 'a'.repeat(64), bundle: {} } satisfies Election;
    const client = { login: vi.fn(), forget: vi.fn(), logout: vi.fn(), list: vi.fn().mockResolvedValue({ elections: [election] }),
      keys: vi.fn().mockResolvedValue({ keysets: [] }), detail: vi.fn().mockResolvedValue(election), audit: vi.fn().mockResolvedValue({ events: [] }), change: vi.fn().mockRejectedValue(new AdminFailure(401)) } as unknown as AdminClient;
    render(<MemoryRouter><AdminWorkspace client={client} /></MemoryRouter>);
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in as administrator' }).closest('form')!);
    fireEvent.click(await screen.findByRole('button', { name: 'Synthetic review election · DRAFT' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open / reconcile opening' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Open / reconcile opening' }));
    expect(client.change).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm open' }));
    await waitFor(() => expect(client.change).toHaveBeenCalledWith(election.election_id, '/open', 'POST', {}));
    expect(await screen.findByRole('heading', { name: 'Administrator sign-in' })).toBeInTheDocument();
  });
  it('preserves confirmation requested at the selection commit before passive effects', async () => {
    const election = { election_id: '11111111-1111-4111-8111-111111111111', title: 'Synthetic commit-boundary election', status: 'DRAFT', phase: 'FROZEN', revision: 2,
      opens_at: '2026-01-01T00:00:00Z', closes_at: '2027-01-01T00:00:00Z', candidates: [], ra_ready: false, keyset_id: 'synthetic-keyset', config_hash: 'a'.repeat(64), bundle: {} } satisfies Election;
    const client = { login: vi.fn(), forget: vi.fn(), logout: vi.fn(), list: vi.fn().mockResolvedValue({ elections: [election] }),
      keys: vi.fn().mockResolvedValue({ keysets: [] }), detail: vi.fn().mockResolvedValue(election), audit: vi.fn().mockResolvedValue({ events: [] }), change: vi.fn().mockRejectedValue(new AdminFailure(401)) } as unknown as AdminClient;
    let requested = false;
    render(<Profiler id="selection-commit" onRender={() => {
      // Profiler runs during commit, before passive effects. Exercise the exact
      // ordering without sleeps, timeouts, or mocking the production component.
      const button = screen.queryByRole<HTMLButtonElement>('button', { name: 'Open / reconcile opening' });
      if (button && !button.disabled && !requested) { requested = true; button.click(); }
    }}><MemoryRouter><AdminWorkspace client={client} /></MemoryRouter></Profiler>);
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in as administrator' }).closest('form')!);
    fireEvent.click(await screen.findByRole('button', { name: 'Synthetic commit-boundary election · DRAFT' }));
    await waitFor(() => expect(requested).toBe(true));
    expect(await screen.findByRole('button', { name: 'Confirm open' })).toBeEnabled();
    expect(client.change).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm open' }));
    await waitFor(() => expect(client.change).toHaveBeenCalledWith(election.election_id, '/open', 'POST', {}));
    expect(await screen.findByRole('heading', { name: 'Administrator sign-in' })).toBeInTheDocument();
  });
  it('clears stale confirmation when switching elections or routes, including returning to the previous context', async () => {
    const first = { election_id: '11111111-1111-4111-8111-111111111111', title: 'Synthetic first election', status: 'DRAFT', phase: 'FROZEN', revision: 2,
      opens_at: '2026-01-01T00:00:00Z', closes_at: '2027-01-01T00:00:00Z', candidates: [], ra_ready: false, keyset_id: 'synthetic-keyset', config_hash: 'a'.repeat(64), bundle: {} } satisfies Election;
    const second = { ...first, election_id: '22222222-2222-4222-8222-222222222222', title: 'Synthetic second election' };
    const client = { login: vi.fn(), forget: vi.fn(), logout: vi.fn(), list: vi.fn().mockResolvedValue({ elections: [first, second] }),
      keys: vi.fn().mockResolvedValue({ keysets: [] }), detail: vi.fn().mockImplementation(async (id: string) => ({ ...(id === first.election_id ? first : second) })),
      audit: vi.fn().mockResolvedValue({ events: [] }), change: vi.fn() } as unknown as AdminClient;
    render(<MemoryRouter initialEntries={['/admin']}><Link to="/admin/status">Change admin route</Link><Link to="/admin">Return to overview</Link><AdminWorkspace client={client} /></MemoryRouter>);
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in as administrator' }).closest('form')!);
    async function select(election: Election) {
      fireEvent.click(await screen.findByRole('button', { name: election.title + ' · DRAFT' }));
      await waitFor(() => expect(screen.getByRole('button', { name: 'Open / reconcile opening' })).toBeEnabled());
      expect(screen.getByRole('heading', { name: election.title })).toBeInTheDocument();
    }
    await select(first);
    fireEvent.click(screen.getByRole('button', { name: 'Open / reconcile opening' }));
    expect(screen.getByRole('button', { name: 'Confirm open' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh status' })).toBeEnabled());
    expect(screen.getByRole('button', { name: 'Confirm open' })).toBeInTheDocument();
    await select(second);
    expect(screen.queryByRole('button', { name: 'Confirm open' })).not.toBeInTheDocument();
    await select(first);
    expect(screen.queryByRole('button', { name: 'Confirm open' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Open / reconcile opening' }));
    expect(screen.getByRole('button', { name: 'Confirm open' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('link', { name: 'Change admin route' }));
    expect(screen.queryByRole('button', { name: 'Confirm open' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('link', { name: 'Return to overview' }));
    expect(screen.queryByRole('button', { name: 'Confirm open' })).not.toBeInTheDocument();
    expect(client.change).not.toHaveBeenCalled();
  });
});
