declare const __LOCAL_RA_DEMO__: boolean;
declare const __LOCAL_PUBLICATION_PROXY__: boolean;

import type { BoardPins } from './board/verification';
export interface AppConfig { authEnabled: boolean; adminEnabled?: boolean; publicationEnabled?: boolean; tallyEnabled?: boolean; votingEnabled?: boolean; authorityPin?: string; boardEnabled?:boolean; boardPins?:BoardPins }

export function localAuthEnabled(explicit: boolean, location: Pick<Location, 'hostname' | 'protocol'>): boolean {
  return explicit && location.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(location.hostname);
}

export const config: AppConfig = { tallyEnabled: localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_TALLY === 'true', adminEnabled: localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_ADMIN === 'true', authEnabled: localAuthEnabled(__LOCAL_RA_DEMO__, window.location),
  publicationEnabled: localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && __LOCAL_PUBLICATION_PROXY__ && import.meta.env.VITE_ENABLE_ADMIN === 'true' && import.meta.env.VITE_ENABLE_PUBLICATION === 'true',
  votingEnabled:localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_VOTING === 'true',
  authorityPin:import.meta.env.VITE_MANIFEST_AUTHORITY_PIN ?? '',
  boardEnabled:localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_BOARD==='true',
  boardPins:{authority:import.meta.env.VITE_MANIFEST_AUTHORITY_PIN??'',evidence:import.meta.env.VITE_EVIDENCE_PIN??'',evidenceKeyId:import.meta.env.VITE_EVIDENCE_KEY_ID??'',
    publication:import.meta.env.VITE_PUBLICATION_PIN??'',publicationKeyId:import.meta.env.VITE_PUBLICATION_KEY_ID??''} };

// These are capability declarations from source inspection, not API responses.
// No endpoint or data shape is assumed for the missing services.
export const capabilities = Object.freeze({ electionCatalogue: false, admin: false,
  publishedResults: false, bulletinBoard: false, receiptVerification: false });
