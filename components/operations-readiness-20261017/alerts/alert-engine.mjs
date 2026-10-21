// Modelo puro e offline. Não contém transporte, destino, relógio real ou agendamento.
const MINUTE = 60_000;
const TARGETS = new Set(['static', 'liveness']);
const SERVICES = new Set(['hosting', 'database', 'mail']);
const finite = (value, name, min = 0) => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min) throw new TypeError(name);
  return value;
};
const integer = (value, name, min = 0) => {
  finite(value, name, min);
  if (!Number.isSafeInteger(value)) throw new TypeError(name);
  return value;
};
const targetName = target => {
  if (!TARGETS.has(target)) throw new TypeError('target');
  return target;
};
const clone = value => structuredClone(value);
const blank = at => ({
  version: 1, environment: 'staging', createdAt: at, now: at, sequence: 0,
  streams: {}, incidents: {}, outbox: [], targets: {}, traffic: [], latency: {},
  heartbeatAt: null, budgetLedger: [], assessments: {},
  backup: { lastSourceAt: null },
  reservations: { lastSourceAt: null, oldSamples: 0, cleanSamples: 0 },
});

export class AlertEngine {
  constructor({ createdAt = 0, snapshot } = {}) {
    integer(createdAt, 'createdAt');
    this.state = blank(createdAt);
    if (snapshot !== undefined) {
      // Importação local para o ensaio, somente de snapshots deste motor.
      // Não constitui parser de entrada remota nem armazenamento de produção.
      if (!snapshot || snapshot.version !== 1 || snapshot.environment !== 'staging') throw new TypeError('snapshot');
      this.#validateSnapshot(snapshot);
      this.state = clone(snapshot);
    }
  }

  #validateSnapshot(s) {
    const expected = Object.keys(blank(0)).sort().join(',');
    if (Object.keys(s).sort().join(',') !== expected) throw new TypeError('snapshot fields');
    integer(s.createdAt, 'snapshot createdAt'); integer(s.now, 'snapshot now');
    integer(s.sequence, 'snapshot sequence');
    if (s.now < s.createdAt || !Array.isArray(s.outbox) || !Array.isArray(s.budgetLedger)) throw new TypeError('snapshot shape');
    // O relatório publica hashes dos arquivos do ensaio. O snapshot é estado
    // local confiável, sem alegação de autenticação criptográfica do conteúdo.
    const serialized = JSON.stringify(s);
    if (serialized.length > 1_000_000 || /(?:https?:|@|authorization|cookie|password|secret|token)/i.test(serialized)) throw new TypeError('snapshot forbidden content');
  }

  #accept(stream, at) {
    integer(at, 'at');
    if (at < this.state.now) throw new RangeError('clock moved backwards');
    this.state.now = at;
    if (this.state.streams[stream] === at) return false;
    this.state.streams[stream] = at;
    return true;
  }

  #notification(incident, transition, at, severity, reason) {
    const id = `${incident.id}:${transition}`;
    if (this.state.outbox.some(item => item.id === id)) return;
    this.state.outbox.push({ id, incidentId: incident.id, key: incident.key, transition,
      at, severity, reason, delivery: 'pending', attempts: 0, lastAttemptAt: null });
  }

  #open(key, at, severity, reason) {
    const previous = this.state.incidents[key];
    if (previous?.active) {
      if (severity === 'critical' && previous.severity !== 'critical') {
        previous.severity = 'critical'; previous.reason = reason;
        this.#notification(previous, 'escalated', at, severity, reason);
      }
      return previous;
    }
    const incident = { id: `stg-${String(++this.state.sequence).padStart(6, '0')}`,
      key, active: true, openedAt: at, closedAt: null, severity, reason };
    this.state.incidents[key] = incident;
    this.#notification(incident, 'opened', at, severity, reason);
    return incident;
  }

  #close(key, at, reason) {
    const incident = this.state.incidents[key];
    if (!incident?.active) return;
    incident.active = false; incident.closedAt = at;
    this.#notification(incident, 'recovered', at, 'info', reason);
  }

  sampleHealth({ target, at, status = null, valid = false, durationMs, failure = null }) {
    targetName(target); finite(durationMs, 'durationMs');
    if (typeof valid !== 'boolean' || (status !== null && (!Number.isInteger(status) || status < 100 || status > 599))) throw new TypeError('health format');
    if (![null, 'network', 'timeout'].includes(failure)) throw new TypeError('failure');
    if (!this.#accept(`health:${target}`, at)) return 'duplicate';
    const bucket = this.state.targets[target] ??= { failures: 0, successes: 0, status: 'not-measured' };
    const timeout = failure === 'timeout' || durationMs >= 10_000;
    const ok = !timeout && failure === null && status >= 200 && status < 300 && valid;
    bucket.status = ok ? 'responding' : 'failed';
    bucket.successes = ok ? bucket.successes + 1 : 0;
    bucket.failures = ok ? 0 : bucket.failures + 1;
    if (bucket.failures >= 3) this.#open(`health:${target}`, at, 'critical', timeout ? 'timeout' : failure ?? 'status-or-format');
    if (bucket.successes >= 2) this.#close(`health:${target}`, at, 'two-successes');
    return bucket.status;
  }

  sampleLatency({ target, at, durationMs }) {
    targetName(target); finite(durationMs, 'durationMs');
    if (!this.#accept(`latency:${target}`, at)) return 'duplicate';
    const samples = this.state.latency[target] ??= [];
    samples.push({ at, durationMs });
    this.state.latency[target] = samples.filter(sample => sample.at > at - 15 * MINUTE).slice(-3);
    const last = this.state.latency[target];
    if (last.length < 3) return 'insufficient-samples';
    if (last.every(sample => sample.durationMs > 3_000)) this.#open(`latency:${target}`, at, 'warning', 'three-slow-samples');
    if (last.every(sample => sample.durationMs < 3_000)) this.#close(`latency:${target}`, at, 'three-fast-samples');
    return this.state.incidents[`latency:${target}`]?.active ? 'warning' : 'within-threshold';
  }

  // Cada entrada é DELTA de um bucket disjunto e terminado em `at`, nunca
  // contador cumulativo nem janela móvel sobreposta. O futuro adaptador deve
  // garantir esse contrato; sem start/end o modelo não detecta sobreposição.
  sampleTraffic({ at, total, serverErrors, expectedClientErrors = 0 }) {
    integer(total, 'total'); integer(serverErrors, 'serverErrors'); integer(expectedClientErrors, 'expectedClientErrors');
    if (serverErrors + expectedClientErrors > total) throw new RangeError('traffic counts');
    if (!this.#accept('traffic', at)) return 'duplicate';
    this.state.traffic.push({ at, total, serverErrors, expectedClientErrors });
    this.state.traffic = this.state.traffic.filter(sample => sample.at > at - 15 * MINUTE);
    const counts = this.state.traffic.reduce((a, b) => ({ total: a.total + b.total, errors: a.errors + b.serverErrors }), { total: 0, errors: 0 });
    if (counts.total < 20) {
      this.state.assessments.traffic = 'insufficient-volume';
      return 'insufficient-volume'; // Pouco tráfego nunca fecha um incidente existente.
    }
    const bad = counts.errors / counts.total >= 0.05;
    this.state.assessments.traffic = bad ? 'high-error-rate' : 'within-threshold';
    if (bad) this.#open('traffic', at, 'warning', 'five-percent-5xx');
    else this.#close('traffic', at, 'sufficient-volume-below-five-percent');
    return this.state.assessments.traffic;
  }

  recordHeartbeat({ at, sourceAt }) {
    integer(sourceAt, 'sourceAt');
    if (sourceAt > at) throw new RangeError('heartbeat from future');
    if (this.state.heartbeatAt !== null && sourceAt < this.state.heartbeatAt) throw new RangeError('heartbeat moved backwards');
    if (!this.#accept('heartbeat-sample', at)) return 'duplicate';
    this.state.heartbeatAt = sourceAt;
    return this.#heartbeat(at);
  }

  inspectHeartbeat({ at }) {
    if (!this.#accept('heartbeat-witness', at)) return 'duplicate';
    return this.#heartbeat(at);
  }

  #heartbeat(at) {
    const reference = this.state.heartbeatAt ?? this.state.createdAt;
    const missing = at - reference >= 15 * MINUTE;
    const assessment = missing ? 'missing-or-stale' : this.state.heartbeatAt === null ? 'not-measured' : 'fresh';
    this.state.assessments.heartbeat = assessment;
    if (missing) this.#open('heartbeat', at, 'critical', 'fifteen-minutes-without-execution');
    else if (this.state.heartbeatAt !== null) this.#close('heartbeat', at, 'fresh-independent-observation');
    return assessment;
  }

  sampleBudget({ service, at, period, amount, currency, sourceAt, budget = null,
    budgetCurrency = currency, zeroAdditionalCost = false, additionalCost = 0,
    planChanged = false, quota = null, quotaUsed = null }) {
    if (!SERVICES.has(service) || !/^\d{4}-(0[1-9]|1[0-2])$/.test(period)) throw new TypeError('budget scope');
    if (!['BRL', 'USD'].includes(currency) || !['BRL', 'USD'].includes(budgetCurrency)) throw new TypeError('currency');
    finite(amount, 'amount'); integer(sourceAt, 'sourceAt');
    if (budget !== null) finite(budget, 'budget');
    finite(additionalCost, 'additionalCost');
    if (typeof zeroAdditionalCost !== 'boolean' || typeof planChanged !== 'boolean') throw new TypeError('cost policy');
    if (quota !== null) finite(quota, 'quota', Number.MIN_VALUE);
    if (quotaUsed !== null) finite(quotaUsed, 'quotaUsed');
    const [year, month] = period.split('-').map(Number);
    const start = Date.UTC(year, month - 1), end = Date.UTC(year, month);
    if (at < start || at >= end || sourceAt > at) throw new RangeError('budget period or source time');
    if (!this.#accept(`budget:${service}`, at)) return 'duplicate';
    // Uma cobrança positiva já atribuída ao período é informação acionável
    // mesmo se a fonte estiver atrasada. Não se presume ausência de gasto.
    if (sourceAt >= start && zeroAdditionalCost && (additionalCost > 0 || planChanged)) {
      this.#open(`unexpected-cost:${service}:${period}`, at, 'critical', 'additional-cost-or-plan-change');
    }
    if (sourceAt < start || at - sourceAt > 6 * 60 * MINUTE) {
      this.#open(`budget-source:${service}`, at, 'warning', 'source-stale-or-wrong-period');
      this.state.assessments[`budget:${service}`] = 'not-measured-stale-source';
      return 'not-measured-stale-source';
    }
    this.#close(`budget-source:${service}`, at, 'fresh-source');
    if (currency !== budgetCurrency) {
      this.#open(`budget-currency:${service}`, at, 'warning', 'currency-mismatch');
      this.state.assessments[`budget:${service}`] = 'not-measured-currency-mismatch';
      return 'not-measured-currency-mismatch';
    }
    this.#close(`budget-currency:${service}`, at, 'currency-matches');
    const once = (kind, threshold, severity) => {
      const key = `${kind}:${service}:${period}:${threshold}`;
      if (this.state.budgetLedger.includes(key)) return;
      this.state.budgetLedger.push(key);
      this.#open(key, at, severity, kind === 'budget' ? 'budget-threshold-crossed' : 'quota-threshold-crossed');
    };
    if (budget !== null && budget > 0) {
      for (const threshold of [50, 80, 100]) {
        if (amount >= budget * threshold / 100) once('budget', threshold, threshold === 100 ? 'critical' : 'warning');
      }
    }
    if (quota !== null && quotaUsed !== null) {
      for (const threshold of [80, 95]) {
        if (quotaUsed >= quota * threshold / 100) once('quota', threshold, threshold === 95 ? 'critical' : 'warning');
      }
    }
    const result = budget === null || budget === 0
      ? zeroAdditionalCost ? 'zero-additional-cost-policy' : 'budget-not-defined'
      : amount >= budget ? 'budget-reached' : amount >= budget * 0.5 ? 'budget-warning' : 'below-half-of-budget';
    this.state.assessments[`budget:${service}`] = result;
    this.state.assessments[`quota:${service}`] = quota === null || quotaUsed === null ? 'quota-not-measured' : 'quota-measured';
    return result;
  }

  sampleBackup({ at, sourceAt, frequencyMs = null, lastValidatedAt = null, validation = 'unknown' }) {
    integer(sourceAt, 'sourceAt');
    if (frequencyMs !== null) integer(frequencyMs, 'frequencyMs', 1);
    if (lastValidatedAt !== null) integer(lastValidatedAt, 'lastValidatedAt');
    if (!['passed', 'failed', 'unknown'].includes(validation)) throw new TypeError('backup validation');
    if (sourceAt > at || (lastValidatedAt !== null && lastValidatedAt > sourceAt)) throw new RangeError('backup source time');
    if (this.state.backup.lastSourceAt !== null && sourceAt < this.state.backup.lastSourceAt) throw new RangeError('backup source moved backwards');
    if (!this.#accept('backup', at)) return 'duplicate';
    const assess = status => (this.state.assessments.backup = status);
    if (frequencyMs === null) return assess('frequency-not-defined');
    // Freshness de cinco minutos é hipótese explícita deste modelo, não
    // configuração aprovada ou frequência real de backup/coleta.
    if (at - sourceAt > 5 * MINUTE) {
      this.#open('backup-source', at, 'warning', 'backup-source-stale');
      return assess('not-measured-stale-source');
    }
    if (this.state.backup.lastSourceAt === sourceAt) return assess('duplicate-source');
    this.state.backup.lastSourceAt = sourceAt;
    this.#close('backup-source', at, 'fresh-source');
    if (validation === 'failed') {
      this.#open('backup', at, 'critical', 'backup-validation-failed');
      return assess('validation-failed');
    }
    if (lastValidatedAt === null) {
      this.#open('backup', at, 'warning', 'no-validated-backup');
      return assess('no-validated-backup');
    }
    if (at - lastValidatedAt > frequencyMs) {
      this.#open('backup', at, 'warning', 'validated-backup-overdue');
      return assess('validated-backup-overdue');
    }
    if (validation !== 'passed') return assess('validation-not-confirmed');
    this.#close('backup', at, 'fresh-source-and-validated-backup-within-frequency');
    return assess('validated-within-frequency');
  }

  sampleReservations({ at, sourceAt, pendingCount, oldestPendingAgeMs = null, uncertainCount, completionVerified = false }) {
    integer(sourceAt, 'sourceAt'); integer(pendingCount, 'pendingCount'); integer(uncertainCount, 'uncertainCount');
    if (oldestPendingAgeMs !== null) finite(oldestPendingAgeMs, 'oldestPendingAgeMs');
    if (typeof completionVerified !== 'boolean' || sourceAt > at) throw new TypeError('reservation source or verification');
    if ((pendingCount === 0 && oldestPendingAgeMs !== null) || (pendingCount > 0 && oldestPendingAgeMs === null)) throw new RangeError('reservation age aggregate');
    const state = this.state.reservations;
    if (state.lastSourceAt !== null && sourceAt < state.lastSourceAt) throw new RangeError('reservation source moved backwards');
    if (!this.#accept('reservations', at)) return 'duplicate';
    const assess = status => (this.state.assessments.reservations = status);
    if (at - sourceAt > 5 * MINUTE) {
      state.oldSamples = 0; state.cleanSamples = 0;
      this.#open('reservations-source', at, 'warning', 'reservations-source-stale');
      return assess('not-measured-stale-source');
    }
    if (state.lastSourceAt === sourceAt) return assess('duplicate-source');
    state.lastSourceAt = sourceAt;
    this.#close('reservations-source', at, 'fresh-source');
    const old = pendingCount > 0 && oldestPendingAgeMs > 5 * MINUTE;
    const persistent = pendingCount > 0 && oldestPendingAgeMs >= 24 * 60 * MINUTE;
    state.oldSamples = old ? state.oldSamples + 1 : 0;
    if (uncertainCount > 0 || persistent || state.oldSamples >= 2) {
      state.cleanSamples = 0;
      this.#open('reservations', at, persistent ? 'critical' : 'warning', persistent ? 'pending-at-least-twenty-four-hours'
        : uncertainCount > 0 ? 'uncertain-state-observed' : 'pending-over-five-minutes-twice');
      return assess(persistent ? 'critical-persistent-pending' : 'investigation-needed');
    }
    if (old) { state.cleanSamples = 0; return assess('old-pending-awaiting-second-observation'); }
    state.cleanSamples = completionVerified ? state.cleanSamples + 1 : 0;
    if (state.cleanSamples >= 2) this.#close('reservations', at, 'two-clean-observations-and-completion-verified');
    return assess(completionVerified ? 'clean-observation' : 'completion-not-verified');
  }

  pendingNotifications() { return clone(this.state.outbox.filter(item => item.delivery !== 'confirmed')); }

  recordDelivery({ id, at, outcome }) {
    integer(at, 'at');
    if (!['confirmed', 'failed'].includes(outcome)) throw new TypeError('delivery outcome');
    const item = this.state.outbox.find(entry => entry.id === id);
    if (!item || at < item.at || at < this.state.now) throw new RangeError('delivery reference or time');
    this.state.now = at;
    if (item.delivery === 'confirmed') return 'already-confirmed';
    item.attempts++; item.lastAttemptAt = at;
    item.delivery = outcome === 'confirmed' ? 'confirmed' : 'failed';
    return item.delivery;
  }

  snapshot() { return clone(this.state); }
}
