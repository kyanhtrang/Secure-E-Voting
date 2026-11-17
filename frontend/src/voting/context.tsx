import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { anonymousClient } from './api';
import { unb64 } from './crypto';
import { browserRecoveryStore } from './recovery';
import { VotingWorkflow } from './workflow';

const Context=createContext<VotingWorkflow | null>(null);
export function VotingProvider({pin,children}: {pin:string;children:ReactNode}) {
  const [workflow]=useState(()=>new VotingWorkflow(pin,browserRecoveryStore(),anonymousClient(true)));
  return <Context value={workflow}>{children}</Context>;
}
export function useVoting() { const value=useContext(Context); if (!value) throw new Error('Voting unavailable'); const [,change]=useState(0); useEffect(()=>value.subscribe(()=>change(x=>x+1)),[value]); return value; }
export function configured(pin: string) { try { return unb64(pin,32).length === 32; } catch { return false; } }
