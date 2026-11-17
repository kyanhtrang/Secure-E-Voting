import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { ApiError, createAuthClient, safeError, type AuthClient, type VoterIdentity } from '../api/auth';
import { FlowError } from '../voting/api';

type Phase = 'anonymous' | 'signing-in' | 'checking' | 'authenticated' | 'unavailable';
interface SessionState { phase: Phase; identity: VoterIdentity | null; message: string; checkedAt: Date | null; busy: boolean }
interface Session extends SessionState {
  enabled: boolean;
  login(username: string, password: string): Promise<void>;
  refresh(): Promise<void>;
  logout(): Promise<void>;
  elections(): Promise<unknown>;
  issue(payload: {election_id:string;request_id:string;blinded_msg:string}): Promise<unknown>;
}
const SessionContext = createContext<Session | null>(null);
const initial: SessionState = { phase: 'anonymous', identity: null, message: '', checkedAt: null, busy: false };

export function SessionProvider({ enabled, children, client: supplied }: { enabled: boolean; children: ReactNode; client?: AuthClient }) {
  const [client] = useState(() => supplied ?? createAuthClient(enabled));
  const [state, setState] = useState(initial);
  const stateRef = useRef(state); stateRef.current = state;
  const operation = useRef(0);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; operation.current++; client.forget(); }; }, [client]);
  const update = (id: number, next: SessionState) => { if (mounted.current && operation.current === id) setState(next); };
  const login = async (username: string, password: string) => {
    const id = ++operation.current;
    setState({ ...initial, phase: 'signing-in', busy: true });
    try {
      const identity = await client.login(username, password);
      update(id, { ...initial, phase: 'authenticated', identity, checkedAt: new Date() });
    } catch (error) { update(id, { ...initial, message: safeError(error) }); }
  };
  const refresh = useCallback(async () => {
    const current = stateRef.current;
    if (!current.identity || current.busy) return;
    const id = ++operation.current;
    setState({ ...current, phase: 'checking', busy: true, message: '' });
    try {
      const identity = await client.me();
      update(id, { ...initial, phase: 'authenticated', identity, checkedAt: new Date() });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'expired') {
        client.forget(); update(id, { ...initial, message: error.message });
      } else update(id, { ...current, phase: 'unavailable', busy: false, message: safeError(error) });
    }
  }, [client]);
  const logout = async () => {
    const id = ++operation.current;
    setState(current => ({ ...current, busy: true }));
    let message = 'You have signed out.';
    try { await client.logout(); }
    catch (error) {
      message = error instanceof ApiError && error.code === 'expired' ? error.message
        : 'Signed out on this device. The server could not confirm revocation; its session may remain active until it expires.';
    }
    update(id, { ...initial, message });
  };
  useEffect(() => {
    if (state.phase !== 'authenticated' && state.phase !== 'unavailable') return;
    const interval = setInterval(() => { if (document.visibilityState === 'visible') void refresh(); }, 60_000);
    const focus = () => { if (document.visibilityState === 'visible') void refresh(); };
    window.addEventListener('focus', focus);
    document.addEventListener('visibilitychange', focus);
    return () => { clearInterval(interval); window.removeEventListener('focus', focus); document.removeEventListener('visibilitychange', focus); };
  }, [state.phase, refresh]);
  async function votingCall(action:()=>Promise<unknown>) {
    try { return await action(); } catch (error) {
      if ((error instanceof FlowError && error.code === 'session') || (error instanceof ApiError && error.code === 'expired')) {
        client.forget(); operation.current++; if (mounted.current) setState({...initial,message:'Your session has ended. Please sign in again.'});
      }
      throw error;
    }
  }
  const elections=useCallback(async()=>votingCall(()=>{ if (!client.elections) throw new ApiError('unavailable'); return client.elections(); }),[client]);
  const issue=useCallback(async(payload: {election_id:string;request_id:string;blinded_msg:string})=>votingCall(()=>{ if (!client.issue) throw new ApiError('unavailable'); return client.issue(payload); }),[client]);
  return <SessionContext value={{ ...state, enabled, login, refresh, logout, elections, issue }}>{children}</SessionContext>;
}
export function useSession(): Session {
  const session = useContext(SessionContext);
  if (!session) throw new Error('Voter session context required');
  return session;
}
