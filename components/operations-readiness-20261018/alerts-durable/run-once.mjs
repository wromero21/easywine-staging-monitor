// Local, explicit input only. No collector, transport, schedule or delivery receipt.
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { AlertEngine } from '../../operations-readiness-20261017/alerts/alert-engine.mjs';

const ENGINE = fileURLToPath(new URL('../../operations-readiness-20261017/alerts/alert-engine.mjs', import.meta.url));
const METHODS = new Set(['sampleHealth', 'sampleLatency', 'sampleTraffic', 'recordHeartbeat',
  'inspectHeartbeat', 'sampleBackup', 'sampleReservations']);
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const hash = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const safeInt = n => Number.isSafeInteger(n) && n >= 0;
const seal = payload => ({ ...payload, sha256: hash(payload) });
const verifySeal = value => {
  const { sha256, ...payload } = value ?? {};
  if (!HASH.test(sha256 ?? '') || hash(payload) !== sha256) fail('E_INTEGRITY');
};
const rejectSensitive = value => {
  if (/(?:https?:|@|authorization|cookie|password|secret|token)/i.test(JSON.stringify(value))) fail('E_FORBIDDEN_CONTENT');
};

async function readJson(filename, optional = false) {
  try {
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2_000_000) fail('E_FILE_SHAPE');
    return JSON.parse(await fs.readFile(filename, 'utf8'));
  } catch (error) {
    if (optional && error.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) fail('E_JSON_PARTIAL_OR_INVALID');
    throw error;
  }
}

export async function runOnce({ store, configFile, feedFile, onPhase = async () => {} }) {
  // Reject network path syntax. The operator must also use a local, trusted disk.
  for (const filename of [store, configFile, feedFile]) {
    if (typeof filename !== 'string' || !filename || /^(?:\\\\|\/\/|[a-z]+:\/\/)/i.test(filename)) fail('E_LOCAL_PATH_REQUIRED');
  }
  const config = await readJson(configFile);
  if (!exact(config, ['version', 'environment', 'mode', 'createdAt']) || config.version !== 1
    || config.environment !== 'staging' || config.mode !== 'offline-explicit-feed' || !safeInt(config.createdAt)) fail('E_CONFIG');
  const feed = await readJson(feedFile);
  if (!exact(feed, ['version', 'environment', 'feedId', 'events']) || feed.version !== 1 || feed.environment !== 'staging'
    || !ID.test(feed.feedId ?? '') || !Array.isArray(feed.events) || feed.events.length < 1 || feed.events.length > 1000) fail('E_FEED');
  rejectSensitive(feed);
  for (const event of feed.events) {
    if (!exact(event, ['method', 'input']) || !METHODS.has(event.method) || !event.input || typeof event.input !== 'object'
      || Array.isArray(event.input)) fail('E_METHOD_OR_EVENT');
    // The engine requires disjoint DELTA buckets. Adapter requires explicit bounds.
    if (event.method === 'sampleTraffic' && (!safeInt(event.input.startAt) || !safeInt(event.input.at)
      || event.input.startAt >= event.input.at)) fail('E_TRAFFIC_BOUNDS');
  }
  const engineSha256 = hash(await fs.readFile(ENGINE));
  const configSha256 = hash(config), feedSha256 = hash(feed);
  const root = path.resolve(store);
  await fs.mkdir(root, { recursive: true });
  if ((await fs.lstat(root)).isSymbolicLink()) fail('E_STORE_SYMLINK');
  const lock = path.join(root, 'writer.lock');
  const stateFile = path.join(root, 'checkpoint.json');
  const journalFile = path.join(root, 'pending.json');
  const owner = { version: 1, pid: process.pid, nonce: randomUUID() };
  let locked = false;
  try {
    try { await fs.mkdir(lock); locked = true; } catch (error) {
      if (error.code === 'EEXIST') fail('E_LOCKED_REQUIRES_OPERATOR_IF_ORPHANED');
      throw error;
    }
    // A crash even before this write leaves the lock closed, never auto-reclaimed.
    await fs.writeFile(path.join(lock, 'owner.json'), JSON.stringify(owner), { flag: 'wx', mode: 0o600 });
    await onPhase('locked', {});
    const validateState = state => {
      if (!exact(state, ['version', 'environment', 'mode', 'engineSha256', 'configSha256', 'revision', 'feeds', 'snapshot', 'trafficEndAt', 'sha256'])) fail('E_STATE_SHAPE');
      if (Buffer.byteLength(JSON.stringify(state)) > 1_900_000) fail('E_STATE_SIZE_REVIEW_REQUIRED');
      verifySeal(state); rejectSensitive(state);
      if (state.version !== 1 || state.environment !== 'staging' || state.mode !== config.mode
        || state.engineSha256 !== engineSha256 || state.configSha256 !== configSha256) fail('E_STATE_INCOMPATIBLE');
      if (!safeInt(state.revision) || !Array.isArray(state.feeds) || state.feeds.length !== state.revision
        || state.feeds.length > 10_000 || !(state.trafficEndAt === null || safeInt(state.trafficEndAt))) fail('E_STATE_SHAPE');
      const ids = new Set();
      for (const item of state.feeds) {
        if (!exact(item, ['id', 'sha256']) || !ID.test(item.id) || !HASH.test(item.sha256) || ids.has(item.id)) fail('E_STATE_LEDGER');
        ids.add(item.id);
      }
      new AlertEngine({ snapshot: state.snapshot });
      return state;
    };
    const empty = seal({ version: 1, environment: 'staging', mode: config.mode, engineSha256, configSha256,
      revision: 0, feeds: [], snapshot: new AlertEngine({ createdAt: config.createdAt }).snapshot(), trafficEndAt: null });
    let current = validateState((await readJson(stateFile, true)) ?? empty);
    const atomicWrite = async (filename, value, kind) => {
      const temp = path.join(root, `.atomic.${kind}.${owner.nonce}.tmp`);
      await onPhase(`before-${kind}-write`, { temp });
      let handle;
      try {
        handle = await fs.open(temp, 'wx', 0o600);
        await handle.writeFile(JSON.stringify(value) + '\n');
        await handle.sync();
      } finally { await handle?.close(); }
      await onPhase(`${kind}-temp-synced`, { temp });
      await fs.rename(temp, filename);
      await onPhase(`${kind}-renamed`, {});
      // Node on Windows offers no portable directory fsync: power loss is not claimed.
    };
    let recoveredJournal = false;
    const pending = await readJson(journalFile, true);
    if (pending) {
      if (!exact(pending, ['version', 'baseRevision', 'baseSha256', 'next', 'sha256']) || pending.version !== 1) fail('E_JOURNAL_SHAPE');
      verifySeal(pending); validateState(pending.next);
      if (pending.next.revision !== pending.baseRevision + 1) fail('E_JOURNAL_CONFLICT');
      if (current.sha256 !== pending.next.sha256) {
        if (pending.baseRevision !== current.revision || pending.baseSha256 !== current.sha256
          || JSON.stringify(pending.next.feeds.slice(0, -1)) !== JSON.stringify(current.feeds)) fail('E_JOURNAL_CONFLICT');
        await atomicWrite(stateFile, pending.next, 'checkpoint');
        current = pending.next;
      }
      await fs.unlink(journalFile);
      recoveredJournal = true;
    }
    const existing = current.feeds.find(item => item.id === feed.feedId);
    if (existing) {
      if (existing.sha256 !== feedSha256) fail('E_FEED_ID_CONFLICT');
      return { status: 'duplicate', revision: current.revision, recoveredJournal,
        pendingNotifications: new AlertEngine({ snapshot: current.snapshot }).pendingNotifications().length,
        deliveriesPerformed: 0, monitoringActivated: false };
    }
    if (current.revision >= 10_000) fail('E_LEDGER_LIMIT_REVIEW_REQUIRED');
    const engine = new AlertEngine({ snapshot: current.snapshot });
    let trafficEndAt = current.trafficEndAt;
    for (const event of feed.events) {
      if (event.method === 'sampleTraffic') {
        if (trafficEndAt !== null && event.input.startAt < trafficEndAt) fail('E_TRAFFIC_OVERLAP');
        const { startAt, ...input } = event.input;
        engine.sampleTraffic(input); trafficEndAt = input.at;
      } else engine[event.method](event.input);
    }
    const next = validateState(seal({ version: 1, environment: 'staging', mode: config.mode, engineSha256, configSha256,
      revision: current.revision + 1, feeds: [...current.feeds, { id: feed.feedId, sha256: feedSha256 }],
      snapshot: engine.snapshot(), trafficEndAt }));
    const journal = seal({ version: 1, baseRevision: current.revision, baseSha256: current.sha256, next });
    await atomicWrite(journalFile, journal, 'journal');
    await atomicWrite(stateFile, next, 'checkpoint');
    await fs.unlink(journalFile);
    return { status: 'applied', revision: next.revision, recoveredJournal,
      pendingNotifications: engine.pendingNotifications().length, deliveriesPerformed: 0, monitoringActivated: false };
  } finally {
    if (locked) {
      const actual = await readJson(path.join(lock, 'owner.json'), true);
      if (actual?.nonce === owner.nonce && actual.pid === owner.pid) {
        await fs.unlink(path.join(lock, 'owner.json'));
        await fs.rmdir(lock);
      }
      // An unrecognized/incomplete marker remains blocked for operator review.
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 6 || args[0] !== '--store' || args[2] !== '--config' || args[4] !== '--feed') fail('E_USAGE');
    console.log(JSON.stringify(await runOnce({ store: args[1], configFile: args[3], feedFile: args[5] })));
  } catch (error) {
    // Never echo source values, paths, complete exception stacks or event bodies.
    console.error(JSON.stringify({ status: 'rejected', code: error.code ?? 'E_VALIDATION', monitoringActivated: false }));
    process.exitCode = 1;
  }
}
