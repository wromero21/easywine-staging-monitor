// Passive Staging sampling only. No global fetch, CLI, schedule, storage or transport.
const TARGETS = Object.freeze([
  Object.freeze({ target: 'static', url: 'https://easywine-staging.pages.dev/', maxBodyBytes: 65_536, mediaType: 'text/html' }),
  Object.freeze({ target: 'liveness', url: 'https://easywine-staging.pages.dev/api/health', maxBodyBytes: 4_096, mediaType: 'application/json' }),
]);
const TIMEOUT_MS = 10_000;
const TIMEOUT = Symbol('deadline');
const INVALID_BODY = Symbol('body-shape');
const BODY_LIMIT = Symbol('body-limit');
const stop = code => { throw Object.assign(new Error(code), { code }); };
const safeInteger = value => Number.isSafeInteger(value) && value >= 0;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

export const collectorPolicy = Object.freeze({
  environment: 'staging', targets: TARGETS, timeoutMs: TIMEOUT_MS,
  method: 'GET', credentials: 'omit', redirect: 'manual', retries: 0, requestsPerRound: 2,
});

function cancelQuietly(streamOrReader) {
  try { Promise.resolve(streamOrReader?.cancel()).catch(() => {}); } catch { /* No raw errors escape. */ }
}

function validDocument(text) {
  return /<!doctype\s+html\s*>/i.test(text)
    && /<title\b[^>]*>\s*EasyWine\s*<\/title\s*>/i.test(text)
    && /<div\b[^>]*\bid\s*=\s*["']root["'][^>]*>/i.test(text)
    && /<script\b(?=[^>]*\btype\s*=\s*["']module["'])(?=[^>]*\bsrc\s*=\s*["']\/assets\/[a-z0-9._-]+\.js["'])[^>]*>/i.test(text);
}

function validHealth(text) {
  try {
    const value = JSON.parse(text);
    return exact(value, ['ok']) && value.ok === true;
  } catch { return false; }
}

// The host must supply a trusted fetch-compatible implementation. There is deliberately
// no fallback to global fetch and no caller-controlled URL/header/credential configuration.
export function createPassiveCollector(options) {
  const allowed = new Set(['fetchImpl', 'now', 'schedule', 'unschedule']);
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || Object.keys(options).some(key => !allowed.has(key)) || typeof options.fetchImpl !== 'function') stop('E_COLLECTOR_CONFIG');
  const { fetchImpl, now = Date.now, schedule = setTimeout, unschedule = clearTimeout } = options;
  if ([now, schedule, unschedule].some(value => typeof value !== 'function')) stop('E_COLLECTOR_CONFIG');
  let collecting = false;
  let previousClock = -1;
  const clock = () => {
    let value;
    try { value = now(); } catch { stop('E_CLOCK'); }
    if (!safeInteger(value) || value < previousClock) stop('E_CLOCK');
    previousClock = value;
    return value;
  };

  async function probe(target) {
    const startedAt = clock();
    const controller = new AbortController();
    let timer, reader, response, expired = false, status = null, bodyBytes = 0;
    const deadline = new Promise((_, reject) => {
      try {
        timer = schedule(() => {
          expired = true;
          controller.abort();
          cancelQuietly(reader ?? response?.body);
          reject(TIMEOUT);
        }, TIMEOUT_MS);
      } catch { reject(INVALID_BODY); }
    });
    const work = async () => {
      response = await fetchImpl(target.url, {
        method: 'GET', credentials: 'omit', redirect: 'manual', cache: 'no-store',
        referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: { Accept: target.mediaType },
      });
      if (expired) { cancelQuietly(response?.body); throw TIMEOUT; }
      if (!response || !Number.isInteger(response.status) || response.status < 100 || response.status > 599
        || typeof response.headers?.get !== 'function') return 'invalid_response';
      status = response.status;
      if (response.redirected === true || response.type === 'opaqueredirect' || (status >= 300 && status <= 399)) return 'redirect';
      // URL is only compared, never followed, returned, or reused as another target.
      if (response.url && response.url !== target.url) return 'destination_mismatch';
      if (status !== 200) return 'http_status';
      const mediaType = (response.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
      if (mediaType !== target.mediaType) return 'invalid_content_type';
      const length = response.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))) return 'invalid_response';
      if (length !== null && Number(length) > target.maxBodyBytes) return 'body_too_large';
      if (typeof response.body?.getReader !== 'function') return 'invalid_response';
      reader = response.body.getReader();
      const chunks = [];
      try {
        while (true) {
          const next = await reader.read();
          if (expired) throw TIMEOUT;
          if (!next || typeof next.done !== 'boolean') throw INVALID_BODY;
          if (next.done) break;
          if (!(next.value instanceof Uint8Array)) throw INVALID_BODY;
          if (next.value.byteLength > target.maxBodyBytes - bodyBytes) throw BODY_LIMIT;
          bodyBytes += next.value.byteLength;
          chunks.push(next.value);
        }
      } finally {
        cancelQuietly(reader);
        try { reader.releaseLock(); } catch { /* A deadline may leave a read pending. */ }
      }
      const bytes = new Uint8Array(bodyBytes);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return 'invalid_content'; }
      return (target.target === 'static' ? validDocument(text) : validHealth(text)) ? 'ok' : 'invalid_content';
    };
    let outcome;
    try { outcome = await Promise.race([deadline, work()]); }
    catch (error) {
      outcome = expired || error === TIMEOUT ? 'timeout' : error === BODY_LIMIT ? 'body_too_large'
        : error === INVALID_BODY ? 'invalid_response' : 'network';
    } finally {
      try { unschedule(timer); } catch { /* Timer handles/errors never leave the collector. */ }
      controller.abort();
      cancelQuietly(reader ?? response?.body);
    }
    const at = clock();
    return {
      event: { method: 'sampleHealth', input: {
        target: target.target, at, status, valid: outcome === 'ok', durationMs: at - startedAt,
        failure: outcome === 'timeout' ? 'timeout' : outcome === 'network' ? 'network' : null,
      } },
      sample: { target: target.target, outcome, bodyBytes },
    };
  }

  return Object.freeze({
    async collectRound(input) {
      if (!exact(input, ['roundId']) || !safeInteger(input.roundId)) stop('E_ROUND');
      if (collecting) stop('E_ROUND_IN_PROGRESS');
      collecting = true;
      try {
        const startedAt = clock(), events = [], samples = [];
        // Fixed order also preserves the existing engine's globally ordered clock.
        for (const target of TARGETS) {
          const result = await probe(target);
          events.push(result.event); samples.push(result.sample);
        }
        return {
          feed: { version: 1, environment: 'staging', feedId: `stg-health-${input.roundId}`, events },
          summary: { startedAt, finishedAt: clock(), requests: 2, samples,
            monitoringActivated: false, deliveriesPerformed: 0 },
        };
      } finally { collecting = false; }
    },
  });
}
