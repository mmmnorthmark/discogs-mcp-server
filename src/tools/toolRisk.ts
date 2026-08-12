/**
 * Per-tool risk profile — the single source of truth for what a tool does
 * to data, and therefore for every access decision made about it.
 *
 * Three things derive from this table, so a tool is classified in exactly
 * one place:
 *
 *   1. RBAC          — `role` is the minimum tier required to call the tool
 *                      (src/auth/toolAuthz.ts).
 *   2. Read-only mode — READONLY_MODE=true registers only tools whose
 *                      `readOnly` is true (src/tools/index.ts).
 *   3. MCP annotations — the four ToolAnnotations hints are emitted to
 *                      clients so they can drive confirmation prompts.
 *
 * On annotations: the MCP spec defines these as HINTS, not controls, and
 * requires clients to treat them as untrusted unless the server is trusted.
 * They are for client UX and policy input. Enforcement is the role gate,
 * which runs server-side and does not consult them.
 *
 * Role tiers (higher satisfies lower): admin > writer > reader
 *   reader → only reads data.
 *   writer → mutates user data non-destructively (add, edit, rate, create).
 *   admin  → irreversible deletes, where losing the record is hard or
 *            impossible to undo.
 *
 * Invariant (enforced by tests/tools/toolRisk.test.ts): readOnly === true
 * implies role === 'reader' and destructive === false. A tool cannot be
 * read-only and also require write privileges.
 */

import type { Role } from '../auth/roleAuthz.js';

export interface ToolRisk {
  /** Minimum role tier required to call this tool. */
  role: Role;
  /** True when the tool does not modify its environment. */
  readOnly: boolean;
  /** True when a modification is destructive rather than additive. Only meaningful when readOnly is false. */
  destructive: boolean;
  /** True when repeated calls with identical arguments have no additional effect. */
  idempotent: boolean;
  /** True when the tool reaches entities outside this server's immediate domain. */
  openWorld: boolean;
}

/** A pure read: no mutation, repeatable, closed world. */
const read: ToolRisk = {
  role: 'reader',
  readOnly: true,
  destructive: false,
  idempotent: true,
  openWorld: false,
};

/** An additive or in-place update: mutates, but nothing is lost. */
const write: ToolRisk = {
  role: 'writer',
  readOnly: false,
  destructive: false,
  idempotent: false,
  openWorld: false,
};

/** An idempotent update — setting a value to what it already is changes nothing. */
const writeIdempotent: ToolRisk = { ...write, idempotent: true };

/** An irreversible delete. */
const destroy: ToolRisk = {
  role: 'admin',
  readOnly: false,
  destructive: true,
  idempotent: true,
  openWorld: false,
};

export const TOOL_RISK: Readonly<Record<string, ToolRisk>> = {
  // ===== database (Discogs catalog) =====
  search: read,
  get_release: read,
  get_release_rating_by_user: read,
  get_release_community_rating: read,
  get_master_release: read,
  get_master_release_versions: read,
  get_artist: read,
  get_artist_releases: read,
  get_label: read,
  get_label_releases: read,
  edit_release_rating: writeIdempotent,
  delete_release_rating: destroy,

  // ===== marketplace =====
  get_user_inventory: read,
  get_marketplace_listing: read,
  get_marketplace_order: read,
  get_marketplace_orders: read,
  get_marketplace_order_messages: read,
  get_marketplace_release_stats: read,
  create_marketplace_listing: write,
  update_marketplace_listing: writeIdempotent,
  delete_marketplace_listing: destroy,
  edit_marketplace_order: writeIdempotent,
  create_marketplace_order_message: write,

  // ===== inventory export =====
  get_inventory_exports: read,
  get_inventory_export: read,
  download_inventory_export: read,
  // Queues a new export job on Discogs: each call creates another export.
  inventory_export: write,

  // ===== user identity =====
  get_user_identity: read,
  get_user_profile: read,
  get_user_submissions: read,
  get_user_contributions: read,
  edit_user_profile: writeIdempotent,

  // ===== user collection =====
  get_user_collection_folders: read,
  get_user_collection_folder: read,
  find_release_in_user_collection: read,
  get_user_collection_items: read,
  get_user_collection_custom_fields: read,
  get_user_collection_value: read,
  create_user_collection_folder: write,
  edit_user_collection_folder: writeIdempotent,
  delete_user_collection_folder: destroy,
  add_release_to_user_collection_folder: write,
  rate_release_in_user_collection: writeIdempotent,
  move_release_in_user_collection: writeIdempotent,
  delete_release_from_user_collection_folder: destroy,
  edit_user_collection_custom_field_value: writeIdempotent,

  // ===== user wantlist =====
  get_user_wantlist: read,
  add_to_wantlist: write,
  edit_item_in_wantlist: writeIdempotent,
  delete_item_in_wantlist: destroy,

  // ===== user lists =====
  get_user_lists: read,
  get_list: read,

  // ===== media =====
  // Fetches image bytes from Discogs CDN hosts — reads only, but reaches
  // outside the API domain, so openWorld is true.
  fetch_image: { ...read, openWorld: true },
};

/**
 * Applied to any tool missing from TOOL_RISK. Deny-by-default: an
 * unclassified tool is assumed to be an irreversible mutation, so it
 * requires admin and is excluded from read-only deployments. Adding a tool
 * without classifying it fails safe rather than silently granting access.
 */
export const UNKNOWN_TOOL_RISK: ToolRisk = {
  role: 'admin',
  readOnly: false,
  destructive: true,
  idempotent: false,
  openWorld: true,
};

export function getToolRisk(toolName: string): ToolRisk {
  return TOOL_RISK[toolName] ?? UNKNOWN_TOOL_RISK;
}
