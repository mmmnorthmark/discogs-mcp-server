/**
 * OAuth authorization-code store — persistent, cross-instance lookup of
 * codes generated during /authorize and consumed during /callback + /token.
 *
 * In-memory storage was unreliable on Cloud Run: /authorize and /callback
 * (or /token) can land on different instances when the platform cold-starts
 * a new container mid-flow, causing "Invalid OAuth callback" 400s and
 * /token "invalid_grant" failures despite a successful sign-in.
 *
 * Mirrors the backend pattern of oauth-client-store. Entries are short-lived
 * — Google authorization codes expire in ~10 minutes, so we set a TTL of
 * 15 minutes as a safety margin.
 *
 * Environment variables:
 * - STORAGE_BACKEND: "memory" | "sqlite" | "firestore" (default: "memory")
 * - STORAGE_SQLITE_PATH: Path to SQLite file (default: "./data/sessions.sqlite")
 * - FIRESTORE_PROJECT_ID: GCP project ID (required for firestore backend)
 * - OAUTH_CODES_COLLECTION: Firestore collection name (default: "oauth-codes")
 */

import KeyvSqlite from '@keyv/sqlite';
import Keyv from 'keyv';
import { log } from '../utils.js';

const debug = (message: string): void => log.debug(message);
const info = (message: string): void => log.info(message);
const error = (message: string): void => log.error(message);

export interface AuthorizationCodeData {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  state?: string;
  scopes?: string[];
  /**
   * Google's authorization code, set during /callback. We keep this as a
   * field on the entry (keyed by our internal UUID) rather than re-keying
   * the entry by Google's code itself — Google codes contain '/' which
   * Firestore would reject as a malformed document path.
   */
  googleCode?: string;
}

const NAMESPACE = 'discogs-oauth-codes';
const TTL_MS = 15 * 60 * 1000;

let store: Keyv<AuthorizationCodeData> | null = null;

function getBackendType(): 'memory' | 'sqlite' | 'firestore' {
  const backend = process.env.STORAGE_BACKEND?.toLowerCase();
  if (backend === 'sqlite' || backend === 'firestore') {
    return backend;
  }
  return 'memory';
}

async function initializeStore(): Promise<Keyv<AuthorizationCodeData>> {
  const backend = getBackendType();
  info(`Initializing OAuth auth-code store with backend: ${backend}`);

  switch (backend) {
    case 'sqlite': {
      const sqlitePath = process.env.STORAGE_SQLITE_PATH || './data/sessions.sqlite';
      const keyvSqlite = new KeyvSqlite(`sqlite://${sqlitePath}`);
      return new Keyv<AuthorizationCodeData>({
        store: keyvSqlite,
        namespace: NAMESPACE,
        ttl: TTL_MS,
      });
    }

    case 'firestore': {
      const projectId = process.env.FIRESTORE_PROJECT_ID;
      const collection = process.env.OAUTH_CODES_COLLECTION || 'oauth-codes';

      if (!projectId) {
        error('FIRESTORE_PROJECT_ID is required when using firestore backend. Falling back to memory.');
        return new Keyv<AuthorizationCodeData>({ namespace: NAMESPACE, ttl: TTL_MS });
      }

      const KeyvFirestore = (await import('keyv-firestore')).default;
      const firestoreStore = new KeyvFirestore({ projectId, collection });

      return new Keyv<AuthorizationCodeData>({
        store: firestoreStore,
        namespace: NAMESPACE,
        ttl: TTL_MS,
      });
    }

    case 'memory':
    default:
      return new Keyv<AuthorizationCodeData>({ namespace: NAMESPACE, ttl: TTL_MS });
  }
}

async function getStore(): Promise<Keyv<AuthorizationCodeData>> {
  if (!store) {
    store = await initializeStore();
    store.on('error', (err: Error) => {
      error(`OAuth code store error: ${err.message}`);
    });
  }
  return store;
}

export async function getAuthorizationCode(
  key: string,
): Promise<AuthorizationCodeData | undefined> {
  const keyv = await getStore();
  return keyv.get(key);
}

export async function setAuthorizationCode(
  key: string,
  data: AuthorizationCodeData,
): Promise<void> {
  const keyv = await getStore();
  await keyv.set(key, data);
  debug(`Stored auth code under key: ${key.slice(0, 8)}...`);
}

export async function deleteAuthorizationCode(key: string): Promise<boolean> {
  const keyv = await getStore();
  return keyv.delete(key);
}

/**
 * Test-only: drop the memoized store so tests with stubbed env vars start clean.
 */
export function _resetStoreForTests(): void {
  store = null;
}
