/**
 * OAuth Client Store - Keyv-based persistent storage for dynamically registered OAuth clients
 *
 * Shares the same backend configuration as the session store:
 * - memory: In-memory storage (default, for local development)
 * - sqlite: SQLite file-based storage (local persistence)
 * - firestore: Google Cloud Firestore (for GCP deployments)
 *
 * Environment variables:
 * - STORAGE_BACKEND: "memory" | "sqlite" | "firestore" (default: "memory")
 * - STORAGE_SQLITE_PATH: Path to SQLite file (default: "./data/sessions.sqlite")
 * - FIRESTORE_PROJECT_ID: GCP project ID (required for firestore backend)
 * - OAUTH_CLIENTS_COLLECTION: Firestore collection name (default: "oauth-clients")
 * - GOOGLE_APPLICATION_CREDENTIALS: Path to GCP credentials JSON (for firestore)
 */

import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import Keyv from 'keyv';
import { log } from '../utils.js';

const debug = (message: string): void => log.debug(message);
const info = (message: string): void => log.info(message);
const error = (message: string): void => log.error(message);

// No TTL — client registrations don't expire
const NAMESPACE = 'discogs-oauth-clients';

// Lazy-initialized store instance
let store: Keyv<OAuthClientInformationFull> | null = null;

function getBackendType(): 'memory' | 'sqlite' | 'firestore' {
  const backend = process.env.STORAGE_BACKEND?.toLowerCase();
  if (backend === 'sqlite' || backend === 'firestore') {
    return backend;
  }
  return 'memory';
}

async function initializeStore(): Promise<Keyv<OAuthClientInformationFull>> {
  const backend = getBackendType();
  info(`Initializing OAuth client store with backend: ${backend}`);

  switch (backend) {
    case 'sqlite': {
      const sqlitePath = process.env.STORAGE_SQLITE_PATH || './data/sessions.sqlite';
      debug(`Using SQLite storage for OAuth clients at: ${sqlitePath}`);

      // Dynamic import: @keyv/sqlite pulls in sqlite3's native binding, which
      // memory/firestore deployments must not need at startup.
      const KeyvSqlite = (await import('@keyv/sqlite')).default;
      const keyvSqlite = new KeyvSqlite(`sqlite://${sqlitePath}`);
      return new Keyv<OAuthClientInformationFull>({
        store: keyvSqlite,
        namespace: NAMESPACE,
      });
    }

    case 'firestore': {
      const projectId = process.env.FIRESTORE_PROJECT_ID;
      const collection = process.env.OAUTH_CLIENTS_COLLECTION || 'oauth-clients';

      if (!projectId) {
        error(
          'FIRESTORE_PROJECT_ID is required when using firestore backend. Falling back to memory.',
        );
        return new Keyv<OAuthClientInformationFull>({ namespace: NAMESPACE });
      }

      debug(
        `Using Firestore storage for OAuth clients: project=${projectId}, collection=${collection}`,
      );

      const KeyvFirestore = (await import('keyv-firestore')).default;
      const firestoreStore = new KeyvFirestore({ projectId, collection });

      return new Keyv<OAuthClientInformationFull>({
        store: firestoreStore,
        namespace: NAMESPACE,
      });
    }

    case 'memory':
    default: {
      debug('Using in-memory storage for OAuth clients (will not persist across restarts)');
      return new Keyv<OAuthClientInformationFull>({ namespace: NAMESPACE });
    }
  }
}

async function getStore(): Promise<Keyv<OAuthClientInformationFull>> {
  if (!store) {
    store = await initializeStore();
    store.on('error', (err: Error) => {
      error(`OAuth client store error: ${err.message}`);
    });
  }
  return store;
}

/**
 * Get a registered OAuth client by client_id
 */
export async function getOAuthClient(
  clientId: string,
): Promise<OAuthClientInformationFull | undefined> {
  const keyv = await getStore();
  const client = await keyv.get(clientId);

  if (client) {
    debug(`Retrieved registered OAuth client: ${clientId}`);
  }

  return client;
}

/**
 * Store a registered OAuth client
 */
export async function setOAuthClient(
  clientId: string,
  client: OAuthClientInformationFull,
): Promise<void> {
  const keyv = await getStore();
  await keyv.set(clientId, client);
  debug(`Stored OAuth client: ${clientId}`);
}

/**
 * Delete a registered OAuth client
 */
export async function deleteOAuthClient(clientId: string): Promise<boolean> {
  const keyv = await getStore();
  const deleted = await keyv.delete(clientId);
  debug(`Deleted OAuth client ${clientId}: ${deleted}`);
  return deleted;
}

/**
 * Test-only: drop the memoized store so tests with stubbed env vars start clean.
 */
export function _resetStoreForTests(): void {
  store = null;
}
