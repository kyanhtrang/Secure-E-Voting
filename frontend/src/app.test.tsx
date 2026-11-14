import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { App } from './app';
import { ApiError, type AuthClient } from './api/auth';
import { PublicationGate } from './components/ui';

const identity = { voter_id: '11111111-1111-4111-8111-111111111111' };
function setup(path = '/voter/login', enabled = true) {
  const client = { login: vi.fn<AuthClient['login']>().mockResolvedValue(identity), me: vi.fn<AuthClient['me']>().mockResolvedValue(identity),
    logout: vi.fn<AuthClient['logout']>().mockResolvedValue(undefined), forget: vi.fn() };
  render(<MemoryRouter initialEntries={[path]}><App settings={{ authEnabled: enabled }} client={client} /></MemoryRouter>);
  return { client, user: userEvent.setup() };
}
async function login(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Username'), 'synthetic-voter');
  await user.type(screen.getByLabelText('Password'), 'synthetic-password');
  await user.click(screen.getByRole('button', { name: 'Sign in securely' }));
}

describe('voter access and state transitions', () => {
  it('protects voter pages without calling an API', () => {
    const { client } = setup('/voter/elections');
    expect(screen.getByRole('heading', { name: 'A trusted place for your voice.' })).toBeInTheDocument();
    expect(client.me).not.toHaveBeenCalled();
  });
  it('keeps default sign-in disabled', () => {
    const { client } = setup('/voter/login', false);
    expect(screen.getByRole('button', { name: 'Sign in securely' })).toBeDisabled();
    expect(client.login).not.toHaveBeenCalled();
  });
  it('logs in, shows only verified session data and honest election availability, then logs out', async () => {
    const { client, user } = setup(); await login(user);
    expect(await screen.findByRole('heading', { name: 'Ready when your election is.' })).toBeInTheDocument();
    expect(screen.getByText('Session verified')).toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Elections' }));
    expect(await screen.findByText('No election catalogue is connected')).toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Overview' }));
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('You have signed out.')).toBeInTheDocument();
    expect(client.logout).toHaveBeenCalledTimes(1);
  });
  it('clears the form password immediately and displays safe login failure', async () => {
    const { client, user } = setup();
    client.login.mockRejectedValueOnce(new ApiError('credentials'));
    await login(user);
    expect(await screen.findByText('The username or password is incorrect.')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.queryByText('synthetic-password')).not.toBeInTheDocument();
  });
  it('shows a genuine loading state while verifying login', async () => {
    const { client, user } = setup();
    let resolve!: (value: typeof identity) => void;
    client.login.mockImplementationOnce(() => new Promise(value => { resolve = value; }));
    await login(user);
    expect(screen.getByRole('button', { name: 'Verifying your access…' })).toBeDisabled();
    await act(async () => { resolve(identity); });
    expect(await screen.findByText('Session verified')).toBeInTheDocument();
  });
  it('returns to login when the server reports expiry', async () => {
    const { client, user } = setup(); await login(user);
    await screen.findByText('Session verified');
    client.me.mockRejectedValueOnce(new ApiError('expired'));
    await user.click(screen.getByRole('button', { name: 'Check session' }));
    expect(await screen.findByText('Your session has ended. Please sign in again.')).toBeInTheDocument();
    expect(screen.queryByText('Session verified')).not.toBeInTheDocument();
  });
  it('fails closed on session-check failure and can recover', async () => {
    const { client, user } = setup(); await login(user); await screen.findByText('Session verified');
    client.me.mockRejectedValueOnce(new ApiError('unavailable'));
    await user.click(screen.getByRole('button', { name: 'Check session' }));
    expect(await screen.findByRole('heading', { name: 'We couldn’t check your session' })).toBeInTheDocument();
    expect(screen.queryByText('Session verified')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Session verified')).toBeInTheDocument();
  });
  it('does not claim server revocation on a failed logout', async () => {
    const { client, user } = setup(); await login(user); await screen.findByText('Session verified');
    client.logout.mockRejectedValueOnce(new ApiError('unavailable'));
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText(/server could not confirm revocation/)).toBeInTheDocument();
    expect(screen.queryByText('You have signed out.')).not.toBeInTheDocument();
  });
  it('revalidates on window focus and forgets RA access when leaving the voter workspace', async () => {
    const { client, user } = setup(); await login(user); await screen.findByText('Session verified');
    await act(async () => { window.dispatchEvent(new Event('focus')); });
    await waitFor(() => expect(client.me).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole('link', { name: 'Public' }));
    expect(await screen.findByRole('heading', { name: 'Election outcomes, open to everyone.' })).toBeInTheDocument();
    expect(client.forget).toHaveBeenCalled();
    const count = client.me.mock.calls.length;
    await user.click(screen.getByRole('link', { name: 'Verify a receipt' }));
    expect(client.me).toHaveBeenCalledTimes(count);
  });
});

describe('foundation boundaries and public publication gating', () => {
  it.each(['DRAFT', 'OPEN', 'CLOSED', 'TALLIED', undefined, 'published'])('does not disclose results for %s', status => {
    render(<PublicationGate status={status} fallback={<p>Not available</p>}><p>synthetic-published-count</p></PublicationGate>);
    expect(screen.queryByText('synthetic-published-count')).not.toBeInTheDocument();
  });
  it('allows the publication renderer only for PUBLISHED', () => {
    render(<PublicationGate status="PUBLISHED" fallback={<p>Not available</p>}><p>synthetic-published-count</p></PublicationGate>);
    expect(screen.getByText('synthetic-published-count')).toBeInTheDocument();
  });
  it('cannot manufacture public results through query parameters and never requests RA access', () => {
    const { client } = setup('/public/results/unknown?status=PUBLISHED&counted=999');
    expect(screen.getByText('No published chart data')).toBeInTheDocument();
    expect(screen.getAllByLabelText('Not published')).toHaveLength(4);
    expect(screen.queryByText('999')).not.toBeInTheDocument();
    expect(client.me).not.toHaveBeenCalled(); expect(client.login).not.toHaveBeenCalled();
  });
  it('keeps anonymous voting separate and disabled', () => {
    const { client } = setup('/vote');
    expect(screen.getByRole('button', { name: 'Submit ballot' })).toBeDisabled();
    expect(client.me).not.toHaveBeenCalled();
  });
  it.each(['elections', 'candidates', 'status', 'tally', 'publication', 'audit'])('keeps admin %s controls disabled without authorization', section => {
    const { client } = setup('/admin/'+section);
    expect(screen.getByText('Read-only foundation.')).toBeInTheDocument();
    for (const button of screen.getAllByRole('button').filter(value => !value.classList.contains('menu-toggle'))) expect(button).toBeDisabled();
    expect(client.me).not.toHaveBeenCalled();
  });
  it('does not submit or store receipt references', () => {
    setup('/public/verify');
    expect(screen.getByLabelText('Receipt reference')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Verify receipt' })).toBeDisabled();
  });
});
