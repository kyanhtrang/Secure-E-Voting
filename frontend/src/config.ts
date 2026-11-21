declare const __LOCAL_RA_DEMO__: boolean;

export interface AppConfig { authEnabled: boolean; adminEnabled?: boolean; tallyEnabled?: boolean; votingEnabled?: boolean; authorityPin?: string }

export function localAuthEnabled(explicit: boolean, location: Pick<Location, 'hostname' | 'protocol'>): boolean {
  return explicit && location.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(location.hostname);
}

export const config: AppConfig = { tallyEnabled: localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_TALLY === 'true', adminEnabled: localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_ADMIN === 'true', authEnabled: localAuthEnabled(__LOCAL_RA_DEMO__, window.location),
  votingEnabled:localAuthEnabled(__LOCAL_RA_DEMO__,window.location) && import.meta.env.VITE_ENABLE_VOTING === 'true',
  authorityPin:import.meta.env.VITE_MANIFEST_AUTHORITY_PIN ?? '' };

// These are capability declarations from source inspection, not API responses.
// No endpoint or data shape is assumed for the missing services.
export const capabilities = Object.freeze({ electionCatalogue: false, admin: false,
  publishedResults: false, bulletinBoard: false, receiptVerification: false });
