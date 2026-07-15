/**
 * Session Store - Keyv-based persistent session storage
 *
 * Supports multiple backends via environment configuration:
 * - memory: In-memory storage (default, for local development)
 * - sqlite: SQLite file-based storage (local persistence)
 * - firestore: Google Cloud Firestore (for GCP deployments)
 *
 * Environment variables:
 * - STORAGE_BACKEND: "memory" | "sqlite" | "firestore" (default: "memory")
 * - STORAGE_SQLITE_PATH: Path to SQLite file (default: "./data/sessions.sqlite")
 * - FIRESTORE_PROJECT_ID: GCP project ID (required for firestore backend)
 * - FIRESTORE_COLLECTION: Firestore collection name (default: "sessions")
 * - GOOGLE_APPLICATION_CREDENTIALS: Path to GCP credentials JSON (for firestore)
 */

import Keyv from 'keyv';
import { log } from '../utils.js';

// Discogs ships a single `log` object instead of cellartracker's named-export
// severity helpers. Alias so this module stays close to the cellartracker-mcp
// source it was ported from.
const debug = (message: string): void => log.debug(message);
const info = (message: string): void => log.info(message);
const error = (message: string): void => log.error(message);

// Session TTL - 30 minutes
const SESSION_TTL_MS = 30 * 60 * 1000;

const NAMESPACE = 'discogs-sessions';

/**
 * Cached session data structure
 */
export interface CachedSession {
  cookie: string;
  expiresAt: number;
  username: string;
}

// Lazy-initialized store instance
let store: Keyv<CachedSession> | null = null;

/**
 * Get the storage backend type from environment
 */
function getBackendType(): 'memory' | 'sqlite' | 'firestore' {
  const backend = process.env.STORAGE_BACKEND?.toLowerCase();
  if (backend === 'sqlite' || backend === 'firestore') {
    return backend;
  }
  return 'memory';
}

/**
 * Initialize the Keyv store based on environment configuration
 */
async function initializeStore(): Promise<Keyv<CachedSession>> {
  const backend = getBackendType();
  info(`Initializing session store with backend: ${backend}`);

  switch (backend) {
    case 'sqlite': {
      const sqlitePath = process.env.STORAGE_SQLITE_PATH || './data/sessions.sqlite';
      debug(`Using SQLite storage at: ${sqlitePath}`);

      // Dynamic import: @keyv/sqlite pulls in sqlite3's native binding, which
      // memory/firestore deployments must not need at startup.
      const KeyvSqlite = (await import('@keyv/sqlite')).default;
      const keyvSqlite = new KeyvSqlite(`sqlite://${sqlitePath}`);
      return new Keyv<CachedSession>({
        store: keyvSqlite,
        namespace: NAMESPACE,
        ttl: SESSION_TTL_MS,
      });
    }

    case 'firestore': {
      const projectId = process.env.FIRESTORE_PROJECT_ID;
      const collection = process.env.FIRESTORE_COLLECTION || 'sessions';

      if (!projectId) {
        error(
          'FIRESTORE_PROJECT_ID is required when using firestore backend. Falling back to memory.',
        );
        return new Keyv<CachedSession>({
          namespace: NAMESPACE,
          ttl: SESSION_TTL_MS,
        });
      }

      debug(`Using Firestore storage: project=${projectId}, collection=${collection}`);

      // Dynamic import for keyv-firestore keeps the firestore SDK out of the
      // startup path for memory/sqlite deployments.
      const KeyvFirestore = (await import('keyv-firestore')).default;
      const firestoreStore = new KeyvFirestore({ projectId, collection });

      return new Keyv<CachedSession>({
        store: firestoreStore,
        namespace: NAMESPACE,
        ttl: SESSION_TTL_MS,
      });
    }

    case 'memory':
    default: {
      debug('Using in-memory storage (sessions will not persist across restarts)');
      return new Keyv<CachedSession>({
        namespace: NAMESPACE,
        ttl: SESSION_TTL_MS,
      });
    }
  }
}

/**
 * Get the initialized store instance (lazy initialization)
 */
async function getStore(): Promise<Keyv<CachedSession>> {
  if (!store) {
    store = await initializeStore();
    store.on('error', (err: Error) => {
      error(`Session store error: ${err.message}`);
    });
  }
  return store;
}

/**
 * Get a session by username
 */
export async function getSession(username: string): Promise<CachedSession | undefined> {
  const keyv = await getStore();
  const session = await keyv.get(username);

  if (session) {
    // Belt and suspenders with the Keyv TTL: entries read from a backend that
    // lost its TTL metadata must still expire.
    if (Date.now() >= session.expiresAt) {
      debug(`Session for ${username} has expired, removing`);
      await keyv.delete(username);
      return undefined;
    }
    debug(`Retrieved cached session for ${username}`);
  }

  return session;
}

/**
 * Store a session
 */
export async function setSession(
  username: string,
  cookie: string,
  ttlMs: number = SESSION_TTL_MS,
): Promise<void> {
  const keyv = await getStore();
  const session: CachedSession = {
    cookie,
    expiresAt: Date.now() + ttlMs,
    username,
  };

  await keyv.set(username, session, ttlMs);
  debug(`Stored session for ${username} (TTL: ${ttlMs}ms)`);
}

/**
 * Delete a session (invalidate)
 */
export async function deleteSession(username: string): Promise<boolean> {
  const keyv = await getStore();
  const deleted = await keyv.delete(username);
  debug(`Deleted session for ${username}: ${deleted}`);
  return deleted;
}

/**
 * Clear all sessions (use with caution)
 */
export async function clearAllSessions(): Promise<void> {
  const keyv = await getStore();
  await keyv.clear();
  info('Cleared all sessions from store');
}

/**
 * Check if the store is using persistent storage
 */
export function isPersistentStorage(): boolean {
  const backend = getBackendType();
  return backend === 'sqlite' || backend === 'firestore';
}

/**
 * Get current backend type (for diagnostics)
 */
export function getStorageBackend(): string {
  return getBackendType();
}

/**
 * Test-only: drop the memoized store so tests with stubbed env vars start clean.
 */
export function _resetStoreForTests(): void {
  store = null;
}
