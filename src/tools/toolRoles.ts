/**
 * Per-tool required role (dispatch table).
 *
 * RBAC is enforced only when at least one IDENTITY_ROLE_*_GROUPS env var
 * is configured (see roleAuthz.requireRole). When RBAC is off this table
 * is still consulted but the enforcement call is a no-op, so the mapping
 * is safe for all deployments — including stdio and single-tenant HTTP
 * deployments with no identity gateway.
 *
 * Tiers (higher tier satisfies any lower-tier requirement):
 *   admin  > writer > reader
 *
 *   reader → tools that ONLY read data (search, get_*, list_*, find_*,
 *            get_user_collection_items, get_user_inventory, etc.).
 *   writer → tools that mutate the user's data (add/edit/delete/rate,
 *            create/update/delete marketplace listings & orders, etc.).
 *   admin  → reserved; no Discogs tools currently warrant admin.
 *
 * Any tool not listed below defaults to `writer` — safer than `reader`
 * for an unrecognized mutation.
 */

import type { Role } from '../auth/roleAuthz.js';

export const TOOL_ROLES: Readonly<Record<string, Role>> = {
  // ===== database (Discogs catalog) =====
  search: 'reader',
  get_release: 'reader',
  get_release_rating: 'reader',
  get_release_rating_by_user: 'reader',
  get_release_community_rating: 'reader',
  get_master_release: 'reader',
  get_master_release_versions: 'reader',
  get_artist: 'reader',
  get_artist_releases: 'reader',
  get_label: 'reader',
  get_label_releases: 'reader',
  edit_release_rating: 'writer',
  delete_release_rating: 'writer',

  // ===== marketplace =====
  get_user_inventory: 'reader',
  get_marketplace_listing: 'reader',
  get_marketplace_order: 'reader',
  get_marketplace_orders: 'reader',
  get_marketplace_order_messages: 'reader',
  get_marketplace_release_stats: 'reader',
  create_marketplace_listing: 'writer',
  update_marketplace_listing: 'writer',
  delete_marketplace_listing: 'writer',
  edit_marketplace_order: 'writer',
  create_marketplace_order_message: 'writer',

  // ===== inventory export =====
  get_inventory_exports: 'reader',
  get_inventory_export: 'reader',
  download_inventory_export: 'reader',
  inventory_export: 'writer',

  // ===== user identity =====
  get_user_identity: 'reader',
  get_user_profile: 'reader',
  get_user_submissions: 'reader',
  get_user_contributions: 'reader',
  edit_user_profile: 'writer',

  // ===== user collection =====
  get_user_collection_folders: 'reader',
  get_user_collection_folder: 'reader',
  find_release_in_user_collection: 'reader',
  get_user_collection_items: 'reader',
  get_user_collection_custom_fields: 'reader',
  get_user_collection_value: 'reader',
  create_user_collection_folder: 'writer',
  edit_user_collection_folder: 'writer',
  delete_user_collection_folder: 'writer',
  add_release_to_user_collection_folder: 'writer',
  rate_release_in_user_collection: 'writer',
  move_release_in_user_collection: 'writer',
  delete_release_from_user_collection_folder: 'writer',
  edit_user_collection_custom_field_value: 'writer',

  // ===== user wantlist =====
  get_user_wantlist: 'reader',
  add_to_wantlist: 'writer',
  edit_item_in_wantlist: 'writer',
  delete_item_in_wantlist: 'writer',

  // ===== user lists =====
  get_user_lists: 'reader',
  get_list: 'reader',

  // ===== media =====
  fetch_image: 'reader',
};

export const DEFAULT_TOOL_ROLE: Role = 'writer';
