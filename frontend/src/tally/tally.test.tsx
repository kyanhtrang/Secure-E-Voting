import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { createTallyClient, TallyFailure, type TallyClient } from './client';
import { TallyWorkspace } from './workspace';

describe('separate restricted Tally client and UI', () => {
  it('uses only its own in-memory bearer and omits cookies', async () => {
    const transport = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'tly1.' + 'A'.repeat(43), token_type: 'bearer' })))
      .mockResolvedValueOnce(new Response('{"role":"TALLY_OPERATOR"}')).mockResolvedValueOnce(new Response('{"elections":[]}'));
    const client = createTallyClient(transport);
    await client.login('synthetic', 'synthetic-only'); await client.elections();
    for (const [path, options] of transport.mock.calls) { expect(path.startsWith('/api/v1/tally/')).toBe(true); expect(options.credentials).toBe('omit'); }
    expect(transport.mock.calls[0]?.[1].headers.Authorization).toBeUndefined();
    expect(transport.mock.calls[2]?.[1].headers.Authorization).toBe('Bearer tly1.' + 'A'.repeat(43));
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
  });
  it('rejects Admin tokens and sanitizes unknown errors', async () => {
    const client = createTallyClient(vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'adm1.' + 'A'.repeat(43), token_type: 'bearer' }))));
    await expect(client.login('synthetic', 'synthetic')).rejects.toBeInstanceOf(TallyFailure);
    const failing = createTallyClient(vi.fn().mockResolvedValue(new Response('{"code":"INTEGRITY","detail":"SECRET_CANARY"}', { status: 503 })));
    await expect(failing.elections()).rejects.toThrow('integrity verification failed');
  });
  it('requires operator authorization and displays an honest empty state', async () => {
    const client = { login: vi.fn(), forget: vi.fn(), elections: vi.fn().mockResolvedValue({ elections: [] }) } as unknown as TallyClient;
    render(<TallyWorkspace client={client} />);
    expect(screen.queryByRole('button', { name: 'Verify and tally' })).not.toBeInTheDocument();
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in to Tally' }).closest('form')!);
    expect(await screen.findByText('No closed elections available')).toBeInTheDocument();
  });
});
