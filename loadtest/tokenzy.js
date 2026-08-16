// k6 load test for tokenzy.
//
// One workload per run, selected with SCENARIO, so the numbers for each are
// unambiguous rather than averaged together:
//
//   mint       POST /v1/tokens          → 201, exercises the single writer
//   consume    POST /v1/consume         → 200, the hot path, one token per request
//   reuse      POST /v1/consume         → 200 invalid_token, the rejection path
//   contend    POST /v1/consume         → many VUs racing for ONE single-use token
//   manage     GET  /v1/manage/tokens   → 200, the admin listing
//   mixed      80% consume, 20% mint — readers and the single writer together
//
// contend is the one that is not about throughput. It is a correctness check
// under load: every VU spends the whole run attacking a single maxUses=1 token,
// and the run passes only if exactly one request in the entire test succeeded.
// Any other number means the atomic UPDATE stopped being atomic.
//
// Usage:
//   k6 run -e WRITE_KEY=... -e CONSUME_KEY=... -e SCENARIO=consume loadtest/tokenzy.js
//
// run.sh builds a server, mints keys and runs every workload.

import http from 'k6/http';
import { check, fail } from 'k6';
import { Counter } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const WRITE_KEY = __ENV.WRITE_KEY;
const CONSUME_KEY = __ENV.CONSUME_KEY || WRITE_KEY;
const ADMIN_KEY = __ENV.ADMIN_KEY || WRITE_KEY;
const SCENARIO = __ENV.SCENARIO || 'consume';
const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || '20s';

// TTL for tokens minted during the run. Long enough that nothing expires
// mid-test and turns a healthy consume into a spurious rejection.
const TTL_SECONDS = Number(__ENV.TTL_SECONDS || 3600);

const writeHeaders = { 'X-App-Key': WRITE_KEY, 'Content-Type': 'application/json' };
const consumeHeaders = { 'X-App-Key': CONSUME_KEY, 'Content-Type': 'application/json' };
const adminHeaders = { 'X-App-Key': ADMIN_KEY };

// Redemptions that actually spent a token. In `contend` this must end at 1.
const accepted = new Counter('tokens_accepted');
const rejected = new Counter('tokens_rejected');

export const options = {
  scenarios: {
    [SCENARIO]: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
      exec: SCENARIO,
      gracefulStop: '5s',
    },
  },
  // Reported for information; the run is not treated as failed on a miss,
  // because the point here is to measure rather than to gate. The exception is
  // contend, whose whole purpose is the assertion in handleSummary.
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

// issue mints one token and returns its plaintext, or fails the check.
function issue(payload) {
  const res = http.post(
    `${BASE}/v1/tokens`,
    JSON.stringify({ payload, maxUses: 1, ttlSeconds: TTL_SECONDS }),
    { headers: writeHeaders },
  );
  if (res.status !== 201) return null;
  return res.json('token');
}

export function setup() {
  if (!WRITE_KEY) fail('WRITE_KEY is required');

  const probe = issue({ probe: true });
  if (!probe) fail('setup: could not issue a token — check the keys');

  // contend needs one token that every VU will fight over for the whole run.
  // It is deliberately never re-minted: the assertion is that the service lets
  // exactly one of the millions of attempts through.
  let contested = null;
  if (SCENARIO === 'contend') {
    contested = issue({ contended: true });
    if (!contested) fail('setup: could not issue the contended token');
  }

  // reuse needs a token that is already spent, so every request in the run is
  // a rejection and the run measures the failure path on its own.
  let spent = null;
  if (SCENARIO === 'reuse') {
    spent = issue({ spent: true });
    const first = http.post(`${BASE}/v1/consume`, JSON.stringify({ token: spent }),
      { headers: consumeHeaders });
    if (first.status !== 200 || first.json('valid') !== true) {
      fail(`setup: could not spend the token first: ${first.body}`);
    }
  }

  return { contested, spent };
}

// mint is the write path: one new token per iteration, all through the single
// writer connection.
export function mint() {
  const res = http.post(
    `${BASE}/v1/tokens`,
    JSON.stringify({
      payload: { vu: __VU, iter: __ITER, note: 'k6 load test' },
      maxUses: 1,
      ttlSeconds: TTL_SECONDS,
    }),
    { headers: writeHeaders },
  );
  check(res, { 'minted': (r) => r.status === 201 });
}

// consume is the path the whole service exists for: mint one token, spend it.
//
// Both halves are measured together on purpose. A redemption cannot happen
// without an issuance, so timing them in isolation would describe a workload
// nobody runs.
export function consume() {
  const token = issue({ vu: __VU, iter: __ITER });
  if (!token) {
    check(null, { 'issued': () => false });
    return;
  }

  const res = http.post(`${BASE}/v1/consume`, JSON.stringify({ token }),
    { headers: consumeHeaders });

  const ok = res.status === 200 && res.json('valid') === true;
  check(res, { 'redeemed': () => ok });
  if (ok) accepted.add(1); else rejected.add(1);
}

// reuse hammers a token that is already spent. It is the shape a replayed link
// takes in the wild, and it should be cheap: the rejection is decided by the
// same single UPDATE matching zero rows.
export function reuse(data) {
  const res = http.post(`${BASE}/v1/consume`, JSON.stringify({ token: data.spent }),
    { headers: consumeHeaders });
  check(res, {
    'answered 200': (r) => r.status === 200,
    'refused': (r) => r.json('valid') === false,
  });
}

// contend is the correctness workload: every VU races for the same single-use
// token for the whole run. Throughput is beside the point — what matters is the
// count in the summary.
export function contend(data) {
  const res = http.post(`${BASE}/v1/consume`, JSON.stringify({ token: data.contested }),
    { headers: consumeHeaders });

  if (res.status === 200 && res.json('valid') === true) {
    accepted.add(1);
  } else {
    rejected.add(1);
  }
  check(res, { 'answered 200': (r) => r.status === 200 });
}

// manage is the admin listing: a cursor page over the tokens table, which is
// the query that has to stay fast as the table grows.
export function manage() {
  const res = http.get(`${BASE}/v1/manage/tokens?limit=50`, { headers: adminHeaders });
  check(res, { 'listed': (r) => r.status === 200 });
}

// mixed is the realistic shape: mostly redemptions, with a steady trickle of
// issuance competing for the same single writer connection.
export function mixed() {
  if (__ITER % 5 === 0) {
    mint();
    return;
  }
  consume();
}

// handleSummary turns contend into a pass/fail rather than a table of numbers.
export function handleSummary(data) {
  const stdout = textSummary(data);

  if (SCENARIO === 'contend') {
    const wins = data.metrics.tokens_accepted ? data.metrics.tokens_accepted.values.count : 0;
    const losses = data.metrics.tokens_rejected ? data.metrics.tokens_rejected.values.count : 0;
    const verdict = wins === 1
      ? `PASS: exactly 1 redemption succeeded out of ${wins + losses} attempts`
      : `FAIL: ${wins} redemptions succeeded out of ${wins + losses} attempts — expected exactly 1`;
    return { stdout: `${stdout}\n${verdict}\n` };
  }
  return { stdout };
}

// A minimal stand-in for k6's built-in summary renderer, so this file needs no
// import from a remote URL — the load test should not depend on the network
// being up to print its own results.
function textSummary(data) {
  const lines = [];
  for (const name of Object.keys(data.metrics).sort()) {
    const m = data.metrics[name];
    const v = m.values;
    if (v.count !== undefined && v.avg === undefined) {
      lines.push(`${name}: count=${v.count} rate=${(v.rate || 0).toFixed(2)}/s`);
    } else if (v.avg !== undefined) {
      lines.push(
        `${name}: avg=${v.avg.toFixed(2)}ms med=${v.med.toFixed(2)}ms ` +
        `p(95)=${v['p(95)'].toFixed(2)}ms p(99)=${v['p(99)'].toFixed(2)}ms max=${v.max.toFixed(2)}ms`,
      );
    } else if (v.rate !== undefined) {
      lines.push(`${name}: rate=${(v.rate * 100).toFixed(2)}%`);
    }
  }
  return lines.join('\n');
}
