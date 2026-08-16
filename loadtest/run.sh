#!/usr/bin/env bash
# Builds tokenzy and runs each k6 workload against its own fresh database.
#
#   ./loadtest/run.sh [output-dir]
#
# Every workload gets a fresh database and a restarted server. That isolation
# matters here more than usual: the mint workload inserts hundreds of thousands
# of tokens, and reusing its database for the next run would measure a table no
# real environment has.
#
# The server's request log goes to a file, so these numbers include the cost of
# logging every request.
#
# NOTE: the databases this creates hold real plaintext tokens. They live under
# the output directory, which is gitignored — leave them there, and delete the
# directory when you are done.

set -euo pipefail

cd "$(dirname "$0")/.."

OUT="${1:-loadtest/results}"
PORT="${PORT:-8299}"
VUS="${VUS:-50}"
DURATION="${DURATION:-20s}"
BASE="http://127.0.0.1:${PORT}"
ADMIN_PASS="loadtest-password"

mkdir -p "$OUT"
BIN="$OUT/tokenzy"
DB="$OUT/loadtest.db"
COOKIES="$OUT/cookies.txt"

SERVER_PID=""
WRITE_KEY=""
CONSUME_KEY=""
ADMIN_KEY=""

stop_server() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}
trap stop_server EXIT

start_fresh_server() { # $1: log suffix
  stop_server
  rm -f "$DB" "$DB-wal" "$DB-shm" "$COOKIES"

  # Retention is pushed out of the way: the cleanup sweep deleting tokens
  # mid-run would be measuring the janitor, not the service.
  TOKENZY_ADMIN_USERNAME=admin \
  TOKENZY_ADMIN_PASSWORD="$ADMIN_PASS" \
  TOKENZY_SEED_DATA=1 \
  TOKENZY_CLEANUP_INTERVAL=1h \
    "$BIN" serve -port "$PORT" -db "$DB" > "$OUT/server-$1.log" 2>&1 &
  SERVER_PID=$!

  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null; then break; fi
    sleep 0.25
  done
  curl -fsS -o /dev/null "$BASE/healthz"

  curl -fsS -c "$COOKIES" -o /dev/null -d "username=admin&password=$ADMIN_PASS" "$BASE/ui/login"
  WRITE_KEY="$(mint_key write)"
  CONSUME_KEY="$(mint_key consume)"
  ADMIN_KEY="$(mint_key admin)"
  [ -n "$WRITE_KEY" ] && [ -n "$CONSUME_KEY" ] && [ -n "$ADMIN_KEY" ] \
    || { echo "could not mint keys" >&2; exit 1; }
}

mint_key() { # $1: scope -> plaintext key
  curl -fsS -b "$COOKIES" -H 'HX-Request: true' -d "scope=$1&label=k6" \
    "$BASE/ui/p/demo/prod/keys" | grep -oE "tk_$1_prod_[a-z0-9]+" | head -1
}

run_k6() { # $1: scenario, $2: tag for output files
  k6 run \
    -e "BASE_URL=$BASE" -e "WRITE_KEY=$WRITE_KEY" -e "CONSUME_KEY=$CONSUME_KEY" \
    -e "ADMIN_KEY=$ADMIN_KEY" -e "SCENARIO=$1" -e "VUS=$VUS" -e "DURATION=$DURATION" \
    --summary-export "$OUT/$2.json" \
    --quiet \
    loadtest/tokenzy.js > "$OUT/$2.txt" 2>&1 || true
  grep -E "http_req_duration|http_reqs|http_req_failed|checks|tokens_|PASS|FAIL" "$OUT/$2.txt" || true
}

preload_tokens() { # $1: how many tokens to insert first
  seq 1 "$1" | xargs -P 8 -I{} curl -fsS -o /dev/null -X POST \
    -H "X-App-Key: $WRITE_KEY" -H 'Content-Type: application/json' \
    -d '{"payload":{"n":{},"note":"preload"},"ttlSeconds":3600}' \
    "$BASE/v1/tokens"
}

echo "==> building"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BIN" .

echo "==> ${VUS} VUs, ${DURATION} per workload, fresh database each time"
for scenario in mint consume reuse manage mixed; do
  echo
  echo "--- $scenario ---"
  start_fresh_server "$scenario"
  run_k6 "$scenario" "$scenario"
  if [ "$scenario" = "mint" ]; then
    echo "database after mint workload: $(du -h "$DB" | cut -f1)"
  fi
done

# The one that is a correctness check rather than a measurement: every VU
# spends the whole run racing for one single-use token, and the summary asserts
# that exactly one of them won.
echo
echo "--- contend (correctness: exactly one redemption may succeed) ---"
start_fresh_server contend
run_k6 contend contend

# How the admin listing holds up as the table grows, which is the query that
# decides whether the panel stays usable in a busy environment.
for n in 1000 10000; do
  echo
  echo "--- manage listing with ~$n tokens ---"
  start_fresh_server "scale$n"
  preload_tokens "$n"
  run_k6 manage "scale$n"
done

echo
echo "==> results in $OUT"
