// End-to-end test of READONLY_MODE against the REAL Discogs API.
//
// Phase 1 (READONLY_MODE=false): a minor field edit must SUCCEED, then is reverted.
// Phase 2 (READONLY_MODE=true):  the same edit must be IMPOSSIBLE (tool absent / call fails).
//
// It writes to the live collection of whoever owns DISCOGS_PERSONAL_ACCESS_TOKEN:
// it appends a marker to one item's Notes custom field, verifies, then restores the
// original value and asserts the restore. Nothing is created or deleted.
//
// Not part of `pnpm test` — it needs real credentials and hits the network.
//   pnpm build
//   set -a; . ./.env; set +a      # or export DISCOGS_PERSONAL_ACCESS_TOKEN yourself
//   node tests/e2e/readonly-mode.e2e.mjs
//
// Exits non-zero if any check fails.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '../../dist/index.js');

if (!process.env.DISCOGS_PERSONAL_ACCESS_TOKEN) {
  console.error('DISCOGS_PERSONAL_ACCESS_TOKEN is not set — see the header of this file.');
  process.exit(1);
}
const MUTATING_TOOL = 'edit_user_collection_custom_field_value';

async function connect(readOnly) {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [SERVER],
    env: { ...process.env, READONLY_MODE: String(readOnly) },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'readonly-e2e', version: '1.0.0' }, { capabilities: {} });
  await client.connect(transport);
  return client;
}

const text = (r) => r?.content?.map((c) => c.text ?? '').join('') ?? '';
const json = (r) => {
  try {
    return JSON.parse(text(r));
  } catch {
    return null;
  }
};

let failures = 0;
const check = (label, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// ---------- PHASE 1: writes enabled ----------
console.log('\n=== PHASE 1: READONLY_MODE=false (writes should work) ===');
let client = await connect(false);

const tools1 = (await client.listTools()).tools.map((t) => t.name);
console.log(`Tools registered: ${tools1.length}`);
check('mutating tool is registered', tools1.includes(MUTATING_TOOL));

const ident = json(await client.callTool({ name: 'get_user_identity', arguments: {} }));
const username = ident?.username;
check('authenticated to Discogs', !!username, username ? `user ${username}` : 'no username');
if (!username) {
  console.log('Cannot continue without auth.');
  process.exit(1);
}

// Discover the custom fields available on the collection.
const fields = json(
  await client.callTool({ name: 'get_user_collection_custom_fields', arguments: { username } }),
);
const textField = (fields?.fields ?? []).find((f) => f.type === 'textarea' || f.type === 'text');
check(
  'found an editable text custom field',
  !!textField,
  textField ? `"${textField.name}" (id ${textField.id})` : 'none',
);
if (!textField) {
  console.log('Cannot continue without a text field.');
  process.exit(1);
}

// Take the first item in folder 1 (All) as the subject.
const items = json(
  await client.callTool({
    name: 'get_user_collection_items',
    arguments: { username, folder_id: 1, per_page: 1, page: 1 },
  }),
);
const item = items?.releases?.[0];
check(
  'found a collection item to edit',
  !!item,
  item ? `"${item.basic_information?.title}" instance ${item.instance_id}` : 'none',
);
if (!item) {
  console.log('Cannot continue without an item.');
  process.exit(1);
}

const originalValue = (item.notes ?? []).find((n) => n.field_id === textField.id)?.value ?? '';
console.log(`Original "${textField.name}" value: ${JSON.stringify(originalValue)}`);

const testValue = `${originalValue}${originalValue ? ' ' : ''}[e2e-test]`;
const editArgs = {
  username,
  folder_id: 1,
  release_id: item.id,
  instance_id: item.instance_id,
  field_id: textField.id,
  value: testValue,
};

let wroteSuccessfully = false;
try {
  const res = await client.callTool({ name: MUTATING_TOOL, arguments: editArgs });
  wroteSuccessfully = !res.isError;
  check(
    'edit call succeeded with writes enabled',
    !res.isError,
    res.isError ? text(res).slice(0, 200) : '',
  );
} catch (e) {
  check('edit call succeeded with writes enabled', false, e.message.slice(0, 200));
}

// Verify the value actually changed on Discogs.
if (wroteSuccessfully) {
  const after = json(
    await client.callTool({
      name: 'get_user_collection_items',
      arguments: { username, folder_id: 1, per_page: 1, page: 1 },
    }),
  );
  const newValue =
    (after?.releases?.[0]?.notes ?? []).find((n) => n.field_id === textField.id)?.value ?? '';
  check('value changed on Discogs', newValue === testValue, `now ${JSON.stringify(newValue)}`);
}

// ---------- RESTORE ----------
if (wroteSuccessfully) {
  const res = await client.callTool({
    name: MUTATING_TOOL,
    arguments: { ...editArgs, value: originalValue },
  });
  const back = json(
    await client.callTool({
      name: 'get_user_collection_items',
      arguments: { username, folder_id: 1, per_page: 1, page: 1 },
    }),
  );
  const restored =
    (back?.releases?.[0]?.notes ?? []).find((n) => n.field_id === textField.id)?.value ?? '';
  check(
    'ORIGINAL VALUE RESTORED',
    restored === originalValue && !res.isError,
    `now ${JSON.stringify(restored)}`,
  );
}
await client.close();

// ---------- PHASE 2: read-only ----------
console.log('\n=== PHASE 2: READONLY_MODE=true (writes must be impossible) ===');
client = await connect(true);
const tools2 = (await client.listTools()).tools.map((t) => t.name);
console.log(`Tools registered: ${tools2.length} (was ${tools1.length})`);
check('mutating tool is NOT registered', !tools2.includes(MUTATING_TOOL));
check(
  'read tools still available',
  tools2.includes('get_user_collection_items') && tools2.includes('search'),
);
check('tool count dropped', tools2.length < tools1.length, `${tools1.length} -> ${tools2.length}`);

let blocked = false;
try {
  const res = await client.callTool({ name: MUTATING_TOOL, arguments: editArgs });
  blocked = !!res.isError;
} catch {
  blocked = true;
}
check('edit call REJECTED in read-only mode', blocked);

// Confirm the collection value is still the original after the blocked attempt.
const final = json(
  await client.callTool({
    name: 'get_user_collection_items',
    arguments: { username, folder_id: 1, per_page: 1, page: 1 },
  }),
);
const finalValue =
  (final?.releases?.[0]?.notes ?? []).find((n) => n.field_id === textField.id)?.value ?? '';
check(
  'COLLECTION UNCHANGED at end of test',
  finalValue === originalValue,
  `${JSON.stringify(finalValue)}`,
);
await client.close();

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
