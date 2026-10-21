// Review-only operational adapter. Importing this file performs no requests.
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createPassiveCollector } from './components/monitor-collector/passive-collector.mjs';
import { AlertEngine } from './components/operations-readiness-20261017/alerts/alert-engine.mjs';
import { runOnce } from './components/operations-readiness-20261018/alerts-durable/run-once.mjs';

export const policy = Object.freeze({ repository: 'wromero21/easywine-staging-monitor', branch: 'monitor-state',
  pilotId: 'easywine-staging-public-pilot-v1', durationMs: 7 * 24 * 60 * 60 * 1000,
  intervalMs: 300_000, maxRounds: 2016, requestsPerRound: 2, maxGetReservations: 4032,
  components: Object.freeze({
    'components/monitor-collector/passive-collector.mjs': '07274ca0afcbcd0bc5b527900345f0db2fa994550ee8db86cf4dc72f651287c3',
    'components/operations-readiness-20261017/alerts/alert-engine.mjs': '37d2cc59813fdf504c234817eedffa4b4f6efc104d0fac31544d6b29dd29d010',
    'components/operations-readiness-20261018/alerts-durable/run-once.mjs': 'ee996298942c63f20995d9021de83eb41915f1244d314f83367ad1508c484f81',
  }),
});
const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATE_FILES = ['config.json', 'host-state.json', 'pilot.json'];
const SHA = /^[a-f0-9]{64}$/;
const OID = /^[a-f0-9]{40}$/;
const NOTIFICATION_ID = /^stg-[0-9]{6,}:(opened|recovered)$/;
const integer = n => Number.isSafeInteger(n) && n >= 0;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const stop = code => { throw Object.assign(new Error(code), { code }); };
export const digest = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value)
  ? value : JSON.stringify(value)).digest('hex');
const ADAPTER = Object.freeze({
  driverSha256: digest(await fs.readFile(fileURLToPath(import.meta.url))),
  workflowSha256: digest(await fs.readFile(path.join(ROOT, '.github/workflows/staging-monitor.yml'))),
  policySha256: digest(await fs.readFile(path.join(ROOT, 'pilot-policy.public.json'))),
});
const seal = value => ({ ...value, sha256: digest(value) });
const verifySeal = value => {
  const { sha256, ...payload } = value ?? {};
  if (!SHA.test(sha256 ?? '') || digest(payload) !== sha256) stop('E_STATE_INTEGRITY');
};
const safeError = error => /^E_[A-Z0-9_]{1,64}$/.test(error?.code ?? '') ? error.code : 'E_HOST_BLOCKED';
const copy = value => structuredClone(value);

export async function verifyComponents() {
  for (const [relative, expected] of Object.entries(policy.components)) {
    if (digest(await fs.readFile(path.join(ROOT, relative))) !== expected) stop('E_COMPONENT_CHANGED');
  }
}

export function validateState(value) {
  if (!value || !OID.test(value.tip ?? '') || !value.files || typeof value.files !== 'object') stop('E_STATE_MISSING');
  const names = Object.keys(value.files).sort();
  const expected = [...STATE_FILES, ...(value.files['checkpoint.json'] ? ['checkpoint.json'] : [])].sort();
  if (JSON.stringify(names) !== JSON.stringify(expected)) stop('E_STATE_FILES');
  const pilot = value.files['pilot.json'], config = value.files['config.json'], host = value.files['host-state.json'];
  verifySeal(pilot); verifySeal(host);
  if (!exact(pilot, ['version','pilotId','repository','branch','createdAt','deadlineAt','intervalMs','maxRounds','getReservationsPerRound','components','adapter','sha256'])
    || pilot.version !== 1 || pilot.pilotId !== policy.pilotId || pilot.repository !== policy.repository
    || pilot.branch !== policy.branch || !integer(pilot.createdAt) || pilot.deadlineAt !== pilot.createdAt + policy.durationMs
    || pilot.intervalMs !== policy.intervalMs || pilot.maxRounds !== policy.maxRounds || pilot.getReservationsPerRound !== 2
    || JSON.stringify(pilot.components) !== JSON.stringify(policy.components) || JSON.stringify(pilot.adapter) !== JSON.stringify(ADAPTER)) stop('E_PILOT_CONFIG');
  if (!exact(config, ['version','environment','mode','createdAt']) || config.version !== 1 || config.environment !== 'staging'
    || config.mode !== 'offline-explicit-feed' || config.createdAt !== pilot.createdAt) stop('E_RUNNER_CONFIG');
  if (!exact(host, ['version','pilotSha256','lastAt','rounds','notifications','sha256']) || host.version !== 1
    || host.pilotSha256 !== pilot.sha256 || !integer(host.lastAt) || host.lastAt < pilot.createdAt
    || !Array.isArray(host.rounds) || host.rounds.length > policy.maxRounds || !Array.isArray(host.notifications)) stop('E_HOST_STATE');
  if (Buffer.byteLength(JSON.stringify(value.files)) > 1_900_000) stop('E_HOST_STATE_SIZE');
  const runIds = new Set();
  let previousAt = pilot.createdAt - 1, previousSlot = -1;
  for (const round of host.rounds) {
    if (!exact(round, ['runId','reservedAt','phase','completedAt','feedSha256']) || !integer(round.runId) || runIds.has(round.runId)
      || !integer(round.reservedAt) || round.reservedAt <= previousAt || round.reservedAt >= pilot.deadlineAt
      || !['reserved','completed'].includes(round.phase)) stop('E_ROUND_LEDGER');
    if (round.phase === 'reserved' && (round.completedAt !== null || round.feedSha256 !== null)) stop('E_ROUND_LEDGER');
    if (round.phase === 'completed' && (!integer(round.completedAt) || round.completedAt < round.reservedAt
      || !SHA.test(round.feedSha256 ?? ''))) stop('E_ROUND_LEDGER');
    const slot = Math.floor((round.reservedAt - pilot.createdAt) / policy.intervalMs);
    if (slot <= previousSlot || host.lastAt < (round.completedAt ?? round.reservedAt)) stop('E_ROUND_LEDGER');
    runIds.add(round.runId); previousAt = round.reservedAt; previousSlot = slot;
  }
  const ids = new Set();
  for (const item of host.notifications) {
    if (!exact(item, ['id','transition','recordedAt','runId','nativeFailureIntent','jobStatus','jobConclusion','jobFailureObserved','manualReceiptAt','receiptRunId'])
      || !NOTIFICATION_ID.test(item.id ?? '') || ids.has(item.id) || !['opened','recovered'].includes(item.transition)
      || item.id.split(':')[1] !== item.transition || !integer(item.recordedAt) || !runIds.has(item.runId)
      || item.nativeFailureIntent !== (item.transition === 'opened')
      || !['not_observed','queued','in_progress','completed'].includes(item.jobStatus)
      || ![null,'success','failure','cancelled','skipped','timed_out','action_required','neutral','stale','startup_failure'].includes(item.jobConclusion)
      || item.jobFailureObserved !== (item.jobStatus === 'completed' && item.jobConclusion === 'failure')
      || !(item.manualReceiptAt === null || integer(item.manualReceiptAt))
      || !(item.receiptRunId === null || integer(item.receiptRunId))) stop('E_NOTIFICATION_LEDGER');
    ids.add(item.id);
  }
  const checkpoint = value.files['checkpoint.json'];
  const completed = host.rounds.filter(item => item.phase === 'completed');
  if (!checkpoint) {
    if (completed.length !== 0 || host.notifications.length !== 0) stop('E_CHECKPOINT_MISSING');
  } else {
    verifySeal(checkpoint);
    if (!exact(checkpoint, ['version','environment','mode','engineSha256','configSha256','revision','feeds','snapshot','trafficEndAt','sha256'])
      || checkpoint.version !== 1 || checkpoint.environment !== 'staging' || checkpoint.mode !== config.mode
      || checkpoint.engineSha256 !== policy.components['components/operations-readiness-20261017/alerts/alert-engine.mjs']
      || checkpoint.configSha256 !== digest(config) || checkpoint.revision !== completed.length
      || !Array.isArray(checkpoint.feeds) || checkpoint.feeds.length !== completed.length || checkpoint.trafficEndAt !== null) stop('E_CHECKPOINT_STATE');
    completed.forEach((round, index) => {
      const feed = checkpoint.feeds[index];
      if (!exact(feed, ['id','sha256']) || feed.id !== `stg-health-${round.runId}` || feed.sha256 !== round.feedSha256) stop('E_CHECKPOINT_LEDGER');
    });
    new AlertEngine({ snapshot: checkpoint.snapshot });
    for (const item of host.notifications) {
      if (!checkpoint.snapshot.outbox.some(note => note.id === item.id && note.transition === item.transition)) stop('E_NOTIFICATION_CHECKPOINT');
    }
    if (checkpoint.snapshot.outbox.length !== host.notifications.length) stop('E_NOTIFICATION_CHECKPOINT');
  }
  return value;
}

async function applyFeed(files, feed) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'easywine-monitor-'));
  const store = path.join(temporary, 'state');
  await fs.mkdir(store);
  if (files['checkpoint.json']) await fs.writeFile(path.join(store, 'checkpoint.json'), JSON.stringify(files['checkpoint.json']), { mode: 0o600 });
  const configFile = path.join(temporary, 'config.json'), feedFile = path.join(temporary, 'feed.json');
  await fs.writeFile(configFile, JSON.stringify(files['config.json']), { mode: 0o600 });
  await fs.writeFile(feedFile, JSON.stringify(feed), { mode: 0o600 });
  const result = await runOnce({ store, configFile, feedFile });
  if (result.status !== 'applied') stop('E_RUNNER_NOT_APPLIED');
  return JSON.parse(await fs.readFile(path.join(store, 'checkpoint.json'), 'utf8'));
}

// All effects are injected. Tests use a memory repository and simulated responses.
export async function hostOnce({ mode = 'sample', repo, now, runId, runAttempt = 1, fetchImpl,
  confirmation = '', notificationId = '', receiptKind = '' }) {
  if (!['bootstrap','sample','receipt'].includes(mode) || !integer(runId) || runAttempt !== 1
    || typeof repo?.read !== 'function' || typeof repo?.commit !== 'function' || typeof now !== 'function') stop('E_HOST_INPUT');
  await verifyComponents();
  const at = now();
  if (!integer(at)) stop('E_CLOCK');
  let current = await repo.read();
  if (mode === 'bootstrap') {
    if (confirmation !== 'BEGIN_7_DAY_PUBLIC_STAGING_PILOT' || current !== null) stop('E_BOOTSTRAP_REFUSED');
    const pilot = seal({ version: 1, pilotId: policy.pilotId, repository: policy.repository, branch: policy.branch,
      createdAt: at, deadlineAt: at + policy.durationMs, intervalMs: policy.intervalMs, maxRounds: policy.maxRounds,
      getReservationsPerRound: 2, components: policy.components, adapter: ADAPTER });
    const files = { 'pilot.json': pilot,
      'config.json': { version: 1, environment: 'staging', mode: 'offline-explicit-feed', createdAt: at },
      'host-state.json': seal({ version: 1, pilotSha256: pilot.sha256, lastAt: at, rounds: [], notifications: [] }) };
    const tip = await repo.commit(null, files, 'Begin bounded seven-day Staging pilot');
    validateState({ tip, files });
    return { status: 'BOOTSTRAPPED_NO_PROBES', roundReservations: 0, getReservations: 0, nativeFailureRequired: false, deliveriesConfirmed: 0 };
  }
  current = validateState(current);
  const files = copy(current.files), pilot = files['pilot.json'];
  let host = files['host-state.json'];
  if (at < host.lastAt) stop('E_CLOCK_REGRESSION');
  if (mode === 'sample' && at >= pilot.deadlineAt) return { status: 'EXPIRED_NO_PROBES', roundReservations: host.rounds.length,
    getReservations: host.rounds.length * 2, nativeFailureRequired: false, incompleteReservationNeedsReview: host.rounds.some(round => round.phase !== 'completed'),
    deliveriesConfirmed: host.notifications.filter(note => note.transition === 'opened' && note.manualReceiptAt !== null).length };
  if (host.rounds.some(round => round.phase !== 'completed')) stop('E_INCOMPLETE_RESERVATION_REVIEW_REQUIRED');
  if (host.rounds.some(round => round.runId === runId)) stop('E_RUN_REPLAY');
  if (mode === 'receipt') {
    if (confirmation !== 'HUMAN_RECEIPT_CONFIRMED' || !NOTIFICATION_ID.test(notificationId)
      || !['opening-email','recovery-summary'].includes(receiptKind)) stop('E_RECEIPT_INPUT');
    const note = host.notifications.find(item => item.id === notificationId);
    if (!note || (receiptKind === 'opening-email') !== (note.transition === 'opened') || note.manualReceiptAt !== null) stop('E_RECEIPT_REFUSED');
    note.manualReceiptAt = at; note.receiptRunId = runId; host.lastAt = at;
    delete host.sha256; files['host-state.json'] = seal(host);
    const tip = await repo.commit(current.tip, files, 'Record explicit human monitor receipt');
    validateState({ tip, files });
    return { status: 'MANUAL_RECEIPT_RECORDED', nativeFailureRequired: false, deliveriesConfirmed: host.notifications.filter(n => n.transition === 'opened' && n.manualReceiptAt !== null).length };
  }
  const terminal = host.rounds.length >= policy.maxRounds ? 'CAP_REACHED_NO_PROBES' : null;
  if (terminal) return { status: terminal, roundReservations: host.rounds.length, getReservations: host.rounds.length * 2, nativeFailureRequired: false,
    deliveriesConfirmed: host.notifications.filter(note => note.transition === 'opened' && note.manualReceiptAt !== null).length };
  const previous = host.rounds.at(-1);
  if (previous && Math.floor((at - pilot.createdAt) / policy.intervalMs)
    <= Math.floor((previous.reservedAt - pilot.createdAt) / policy.intervalMs)) stop('E_ROUND_TOO_SOON');
  if (typeof fetchImpl !== 'function') stop('E_FETCH_REQUIRED');
  // Reconcile only recorded notification jobs. Completion is never email receipt.
  const statuses = new Map();
  for (const note of host.notifications) {
    if (note.jobStatus !== 'completed') {
      if (typeof repo.runStatus !== 'function') stop('E_JOB_STATUS_REQUIRED');
      if (!statuses.has(note.runId)) statuses.set(note.runId, await repo.runStatus(note.runId));
      const status = statuses.get(note.runId);
      if (!exact(status, ['status','conclusion']) || !['queued','in_progress','completed'].includes(status.status)
        || ![null,'success','failure','cancelled','skipped','timed_out','action_required','neutral','stale','startup_failure'].includes(status.conclusion)
        || (status.status === 'completed') !== (status.conclusion !== null)) stop('E_JOB_STATUS');
      note.jobStatus = status.status; note.jobConclusion = status.conclusion;
      note.jobFailureObserved = status.status === 'completed' && status.conclusion === 'failure';
    }
  }
  const reservation = { runId, reservedAt: at, phase: 'reserved', completedAt: null, feedSha256: null };
  host.rounds.push(reservation); host.lastAt = at;
  delete host.sha256; files['host-state.json'] = seal(host);
  // Publication must succeed before even constructing a collector.
  const reservedTip = await repo.commit(current.tip, files, 'Reserve one Staging round and two GET attempts');
  validateState({ tip: reservedTip, files });
  let requestsAttempted = 0, previousClock = at, transportGuardFailure = null;
  const checkedClock = () => {
    const value = now();
    if (!integer(value) || value < previousClock) { transportGuardFailure = 'E_CLOCK_REGRESSION'; stop(transportGuardFailure); }
    previousClock = value; return value;
  };
  if (checkedClock() >= pilot.deadlineAt) stop('E_PILOT_REQUEST_DEADLINE');
  const boundedFetch = (url, options) => {
    const requestedAt = checkedClock();
    if (requestedAt >= pilot.deadlineAt) { transportGuardFailure = 'E_PILOT_REQUEST_DEADLINE'; stop(transportGuardFailure); }
    if (requestsAttempted >= policy.requestsPerRound) stop('E_GET_LIMIT');
    requestsAttempted++;
    return fetchImpl(url, options);
  };
  const collected = await createPassiveCollector({ fetchImpl: boundedFetch, now: checkedClock }).collectRound({ roundId: runId });
  // The collector converts transport errors to samples. A host deadline/clock
  // refusal is infrastructure, never evidence of an application outage.
  if (transportGuardFailure) stop(transportGuardFailure);
  files['checkpoint.json'] = await applyFeed(files, collected.feed);
  host = copy(files['host-state.json']); delete host.sha256;
  const finishedAt = checkedClock();
  if (!integer(finishedAt) || finishedAt < at || finishedAt < files['checkpoint.json'].snapshot.now) stop('E_CLOCK');
  const last = host.rounds.at(-1);
  last.phase = 'completed'; last.completedAt = finishedAt; last.feedSha256 = digest(collected.feed); host.lastAt = finishedAt;
  const known = new Set(host.notifications.map(note => note.id));
  const fresh = files['checkpoint.json'].snapshot.outbox.filter(note => !known.has(note.id));
  for (const note of fresh) {
    if (!['opened','recovered'].includes(note.transition) || !NOTIFICATION_ID.test(note.id)) stop('E_NOTIFICATION_SCOPE');
    host.notifications.push({ id: note.id, transition: note.transition, recordedAt: note.at, runId,
      nativeFailureIntent: note.transition === 'opened', jobStatus: 'not_observed', jobConclusion: null, jobFailureObserved: false,
      manualReceiptAt: null, receiptRunId: null });
  }
  files['host-state.json'] = seal(host);
  const nextTip = await repo.commit(reservedTip, files, 'Persist Staging result and notification intents');
  validateState({ tip: nextTip, files });
  const openings = fresh.filter(note => note.transition === 'opened').map(note => note.id);
  const recoveries = fresh.filter(note => note.transition === 'recovered').map(note => note.id);
  const activeHealthIncidents = Object.values(files['checkpoint.json'].snapshot.incidents).filter(item => item.active && item.key.startsWith('health:')).length;
  return { status: openings.length ? 'NEW_INCIDENT_OPENING' : recoveries.length ? 'RECOVERY_REPORTED' : activeHealthIncidents ? 'INCIDENT_STILL_ACTIVE' : 'SAMPLED',
    roundReservations: host.rounds.length, getReservations: host.rounds.length * 2, requestsAttempted,
    samples: collected.summary.samples, activeHealthIncidents, openings, recoveries, nativeFailureRequired: openings.length > 0,
    deliveriesConfirmed: host.notifications.filter(note => note.transition === 'opened' && note.manualReceiptAt !== null).length,
    engineNotificationsRemainPending: true, absenceWatcherIndependent: false };
}

// Fixed-repository client. Its requests are reachable only through the explicit
// hosted approval gate below; no installation, git subprocess or token file.
export function createGitHubRepository({ token, fetchImpl }) {
  if (typeof token !== 'string' || token.length < 10 || typeof fetchImpl !== 'function') stop('E_REPOSITORY_CREDENTIAL');
  const base = `https://api.github.com/repos/${policy.repository}`;
  async function request(url, { method = 'GET', body, missing = false } = {}) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetchImpl(url, { method, redirect: 'manual', credentials: 'omit', signal: controller.signal,
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28', ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}) });
      if (missing && response.status === 404) return null;
      if (response.status < 200 || response.status > 299 || response.redirected) stop('E_REPOSITORY_REQUEST');
      const reader = response.body?.getReader();
      if (!reader) stop('E_REPOSITORY_RESPONSE');
      const chunks = []; let length = 0;
      try {
        while (true) { const part = await reader.read(); if (part.done) break;
          length += part.value.byteLength; if (length > 4_000_000) stop('E_REPOSITORY_RESPONSE_SIZE'); chunks.push(part.value); }
      } finally { try { await reader.cancel(); } catch { /* no response details */ } }
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      if (value?.errors || value?.error) stop('E_REPOSITORY_GRAPHQL');
      return value;
    } catch (error) { stop(safeError(error)); } finally { clearTimeout(timer); }
  }
  let identityVerified = false;
  async function verifyIdentity() {
    if (identityVerified) return;
    const value = await request(base);
    if (value.full_name !== policy.repository || value.owner?.login !== 'wromero21' || value.private !== false
      || value.archived !== false || value.disabled !== false || !value.default_branch) stop('E_REPOSITORY_IDENTITY');
    identityVerified = true;
  }
  async function ref() {
    const value = await request(`${base}/git/ref/heads/${policy.branch}`, { missing: true });
    if (value === null) return null;
    if (value.ref !== `refs/heads/${policy.branch}` || value.object?.type !== 'commit' || !OID.test(value.object.sha)) stop('E_REPOSITORY_REF');
    return value.object.sha;
  }
  return {
    async read() {
      await verifyIdentity(); const tip = await ref(); if (tip === null) return null;
      const commit = await request(`${base}/git/commits/${tip}`);
      if (!OID.test(commit.tree?.sha ?? '')) stop('E_REPOSITORY_TREE');
      const tree = await request(`${base}/git/trees/${commit.tree.sha}`);
      if (!Array.isArray(tree.tree) || tree.truncated) stop('E_REPOSITORY_TREE');
      const files = {};
      for (const item of tree.tree) {
        if (![...STATE_FILES, 'checkpoint.json'].includes(item.path) || item.mode !== '100644' || item.type !== 'blob' || !OID.test(item.sha)) stop('E_REPOSITORY_FILES');
        const blob = await request(`${base}/git/blobs/${item.sha}`);
        if (blob.encoding !== 'base64' || typeof blob.content !== 'string' || blob.size > 1_900_000) stop('E_REPOSITORY_BLOB');
        const bytes = Buffer.from(blob.content.replace(/\s/g, ''), 'base64');
        if (bytes.length !== blob.size) stop('E_REPOSITORY_BLOB');
        files[item.path] = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      }
      return { tip, files };
    },
    async commit(expectedTip, files, message) {
      await verifyIdentity(); if (await ref() !== expectedTip) stop('E_STATE_CAS_CONFLICT');
      const additions = Object.entries(files).map(([name, value]) => ({ path: name, contents: Buffer.from(JSON.stringify(value) + '\n').toString('base64') }));
      let tip;
      if (expectedTip === null) {
        const tree = await request(`${base}/git/trees`, { method: 'POST', body: { tree: Object.entries(files).map(([name, value]) => ({ path: name, mode: '100644', type: 'blob', content: JSON.stringify(value) + '\n' })) } });
        if (!OID.test(tree.sha ?? '')) stop('E_BOOTSTRAP_TREE');
        const commit = await request(`${base}/git/commits`, { method: 'POST', body: { message, tree: tree.sha, parents: [] } });
        if (!OID.test(commit.sha ?? '')) stop('E_BOOTSTRAP_COMMIT');
        const created = await request(`${base}/git/refs`, { method: 'POST', body: { ref: `refs/heads/${policy.branch}`, sha: commit.sha } });
        if (created.object?.sha !== commit.sha) stop('E_BOOTSTRAP_REF'); tip = commit.sha;
      } else {
        if (!OID.test(expectedTip)) stop('E_STATE_CAS_INPUT');
        const value = await request('https://api.github.com/graphql', { method: 'POST', body: {
          query: 'mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}',
          variables: { input: { branch: { repositoryNameWithOwner: policy.repository, branchName: policy.branch },
            expectedHeadOid: expectedTip, message: { headline: message }, fileChanges: { additions } } },
        } });
        tip = value.data?.createCommitOnBranch?.commit?.oid;
        if (!OID.test(tip ?? '')) stop('E_STATE_COMMIT');
      }
      if (await ref() !== tip) stop('E_STATE_PUBLICATION_UNCONFIRMED');
      return tip;
    },
    async runStatus(runId) {
      if (!integer(runId)) stop('E_JOB_ID');
      const value = await request(`${base}/actions/runs/${runId}`);
      if (value.id !== runId || value.repository?.full_name !== policy.repository) stop('E_JOB_IDENTITY');
      return { status: value.status, conclusion: value.conclusion };
    },
  };
}

async function writeSummary(value) {
  if (process.env.GITHUB_STEP_SUMMARY) await fs.appendFile(process.env.GITHUB_STEP_SUMMARY,
    `## Staging monitor pilot\n\n\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\`\n\nA successful monitor job is not a claim that targets are healthy: check sample outcomes and active incidents. Job completion is not email receipt. Recovery is reported here with a successful job. An independent absence watcher is not active.\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.slice(2).join(' ') !== '--approved-hosted-pilot') {
    console.log(JSON.stringify({ status: 'INERT_REVIEW_ONLY', requests: 0, repositoryWrites: 0 }));
  } else {
    try {
      const mode = process.env.MONITOR_OPERATION || 'sample';
      const approval = process.env.MONITOR_PILOT_APPROVED;
      if (!(approval === 'true' || (approval === 'bootstrap-only' && mode === 'bootstrap')) || process.env.GITHUB_REPOSITORY !== policy.repository
        || process.env.GITHUB_ACTOR !== 'wromero21' || process.env.RUNNER_OS !== 'Linux'
        || process.versions.node !== '24.14.0' || !['schedule','workflow_dispatch'].includes(process.env.GITHUB_EVENT_NAME)) stop('E_HOST_APPROVAL_GATE');
      if (mode !== 'sample' && process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch') stop('E_MANUAL_OPERATION_REQUIRED');
      const result = await hostOnce({ mode, repo: createGitHubRepository({ token: process.env.GITHUB_TOKEN, fetchImpl: globalThis.fetch }),
        fetchImpl: globalThis.fetch, now: Date.now, runId: Number(process.env.GITHUB_RUN_ID), runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
        confirmation: process.env.MONITOR_CONFIRMATION || '', notificationId: process.env.MONITOR_NOTIFICATION_ID || '', receiptKind: process.env.MONITOR_RECEIPT_KIND || '' });
      await writeSummary(result); console.log(JSON.stringify(result));
      if (result.nativeFailureRequired) process.exitCode = 1;
    } catch (error) {
      const result = { status: 'BLOCKED', code: safeError(error), futureProbesStopped: true,
        probeAttemptsThisRun: 'NOT_ASSERTED_ON_ERROR_CHECK_PRESERVED_RESERVATION', emailReceiptConfirmed: false };
      try { await writeSummary(result); } catch { /* no raw errors */ }
      console.error(JSON.stringify(result)); process.exitCode = 1;
    }
  }
}
