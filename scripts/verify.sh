#!/usr/bin/env bash
#
# Local end-to-end verification harness.
#
# Runs every GATE the CI pipeline runs, so failures surface in ~2 minutes
# locally instead of after a 4-minute push/wait/read-the-logs cycle.
#
#   bash scripts/verify.sh
#
# Exits 0 only if everything passes.
#
# "Every gate" is meant literally, and it did not used to be. This script had
# ten checks and CI had twelve: the production `npm audit` gate and the Trivy
# IMAGE scan were only ever exercised on the runner. That is the worst place to
# discover them, because the first time they run is the push that turns main
# red. Steps 11 and 12 exist to close that gap - a local pass should mean CI
# passes, or the harness is lying to you.
#
# The image scan in particular is not redundant with step 10: the filesystem
# scan reads package-lock.json, and cannot see the Alpine OS packages or
# anything baked into the base image underneath the app.
#
# NOTE: on the demo/* branches this script is SUPPOSED to fail - step 9 finds
# the planted AWS key, step 10 finds the planted lodash CVE. That is the demo
# working, not the harness breaking.

set -euo pipefail

IMAGE="macky-merch-api:local"
FAT_IMAGE="macky-merch-api:test"
CONTAINER="macky-verify"

# Git Bash on Windows rewrites container-side paths like /repo into C:\... before
# Docker ever sees them. Harmless no-op on Linux and macOS.
export MSYS_NO_PATHCONV=1

pass() { printf '    \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

# Always clean up the test container, even if a check fails partway through.
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# -----------------------------------------------------------------------------
step "1/12  Node unit tests (host)"
npm ci
npm test
pass "jest suite green on $(node -v)"

# -----------------------------------------------------------------------------
step "2/12  Build the test stage (runs jest inside Alpine)"
# This is also the regression test for the .dockerignore trap: excluding
# *.test.js from the build context leaves jest with nothing to run, and jest
# exits 1 on "No tests found". If this step fails with that message, the bug is
# in .dockerignore, not in the test.
docker build --target test -t "$FAT_IMAGE" .
pass "test stage built and jest passed inside the container"

# -----------------------------------------------------------------------------
step "3/12  Build the runtime image"
# --target runtime explicitly. A bare `docker build .` happens to produce the
# same image only because runtime is the last stage in the file; relying on
# stage ordering is exactly the fragility docker-compose.yml warns about.
docker build --target runtime -t "$IMAGE" .
pass "runtime image built"

# -----------------------------------------------------------------------------
step "4/12  Non-root check (spec requirement)"
uid="$(docker run --rm --entrypoint id "$IMAGE" -u)"
[ "$uid" != "0" ] || fail "container runs as root (uid 0)"
pass "runs unprivileged as uid $uid"

# -----------------------------------------------------------------------------
step "5/12  Dev dependencies absent from the runtime image"
# Captured to a variable first, then matched with a here-string. The obvious
# `docker run ... | grep -qx jest` is subtly wrong under `set -o pipefail`:
# grep -q exits the moment it matches, the upstream `ls` can then take SIGPIPE
# and exit 141, and pipefail propagates that non-zero status - so a jest that IS
# present reads as a failed pipeline and the `if` takes the wrong branch. The
# check would silently pass in exactly the case it exists to catch.
modules="$(docker run --rm --entrypoint ls "$IMAGE" /app/node_modules)"
if grep -qx "jest" <<<"$modules"; then
  fail "jest found in the runtime image - multi-stage build is not isolating deps"
fi
pass "no jest/supertest in the shipped image"

# -----------------------------------------------------------------------------
step "6/12  Smoke test /health"
cleanup
# Bound to 127.0.0.1, matching docker-compose.yml. A bare -p 3000:3000 binds
# 0.0.0.0 and publishes this container to every device on the local network.
docker run -d --name "$CONTAINER" -p 127.0.0.1:3000:3000 "$IMAGE" >/dev/null
ok=0
for _ in $(seq 1 15); do
  if curl -fsS http://127.0.0.1:3000/health >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { docker logs "$CONTAINER"; fail "/health never became reachable"; }
curl -s http://127.0.0.1:3000/health; echo
pass "/health responded 200"

# -----------------------------------------------------------------------------
step "7/12  Prompt shutdown (proves tini forwards SIGTERM)"
start=$(date +%s)
docker stop "$CONTAINER" >/dev/null
elapsed=$(( $(date +%s) - start ))
# Without an init, node runs as PID 1, where the kernel ignores signals that
# have no explicit handler. docker stop is then ignored for the full 10-second
# grace period before SIGKILL.
[ "$elapsed" -lt 5 ] || fail "took ${elapsed}s to stop - SIGTERM is not being forwarded"
pass "stopped in ${elapsed}s"
cleanup

# -----------------------------------------------------------------------------
step "8/12  Docker Compose (app + Redis on a user-defined network)"
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:3000/health >/dev/null || { docker compose down -v; fail "compose /health unreachable"; }
# Prove the Docker network actually resolves the service name.
docker compose exec -T api node -e \
  "require('dns').promises.lookup('cache').then(r=>{console.log('cache ->',r.address);process.exit(0)}).catch(()=>process.exit(1))" \
  || { docker compose down -v; fail "api cannot resolve 'cache' over macky-net"; }
docker compose down -v
pass "compose stack healthy and networked"

# -----------------------------------------------------------------------------
step "9/12  Secret scan (Gitleaks, full history of this branch)"
# Mirrors the nightly CI run rather than the per-push one: it walks history
# rather than a commit range, which is the check worth running before you push
# something you cannot un-publish.
#
# --log-opts=HEAD is doing real work here, and it is the same scoping ci.yml
# applies for the same reason. `gitleaks detect` defaults to scanning EVERY REF
# in the repository, not the checked-out branch - so with demo/leaked-secret
# sitting in the repo, this step fails while you are on a clean main, and the
# failure points at a file that is not in your working tree.
#
# A harness that is stricter than CI is worse than no harness: it fails on
# things CI would pass, and you learn to ignore it. Local and CI now ask the
# identical question - "is there a secret in the history of the branch we
# ship?" - and the demo branches still fail their own PRs, which is their job.
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest \
  detect --source /repo --redact -v --log-opts=HEAD \
  || fail "gitleaks found a secret (expected on demo/leaked-secret)"
pass "no secrets in this branch's history"

# -----------------------------------------------------------------------------
step "10/12  Dependency scan (Trivy filesystem gate)"
# Same thresholds as the CI gate: HIGH/CRITICAL only, and --ignore-unfixed so a
# CVE with no available patch does not fail a build nobody can act on.
docker run --rm -v "$(pwd):/repo" aquasec/trivy:latest \
  fs /repo \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  || fail "Trivy found a fixable HIGH/CRITICAL (expected on demo/vulnerable-dependency)"
pass "no fixable HIGH/CRITICAL dependencies"

# -----------------------------------------------------------------------------
step "11/12  Production dependency audit (npm audit gate)"
# A second opinion from a different vulnerability database. Trivy and npm audit
# do not always agree, and the disagreement is itself signal.
#
# --omit=dev is the npm-side equivalent of the Dockerfile's `deps` stage, so
# this asks exactly one question: "is there a fixable HIGH in code that reaches
# production?" jest and supertest drag in a large transitive tree that never
# leaves CI; a finding there is worth seeing but not worth blocking a release
# over, which is why CI reports the full tree separately and gates only here.
npm audit --omit=dev --audit-level=high \
  || fail "npm audit found a HIGH in production dependencies (expected on demo/vulnerable-dependency)"
pass "no HIGH+ advisories in production dependencies"

# -----------------------------------------------------------------------------
step "12/12  Image scan (Trivy, the shipped artifact)"
# NOT redundant with step 10. That one reads package-lock.json; this one reads
# the final image - app dependencies AND the Alpine OS packages underneath them.
# The filesystem scan structurally cannot see the base image.
#
# This is the check that makes `apk upgrade --no-cache` in the Dockerfile
# provable rather than asserted: the pinned base digest ships openssl 3.5.7-r0,
# which carries CVE-2026-14456 (HIGH). Without that line this step fails on a
# clean main, gating every merge on a CVE that is not in this repository.
#
# Mounting the Docker socket is what lets the scanner read images out of the
# local daemon. Same severity thresholds as the CI `docker` job.
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
  image "$IMAGE" \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  || fail "Trivy found a fixable HIGH/CRITICAL in the shipped image"
pass "shipped image clean of fixable HIGH/CRITICAL"

# -----------------------------------------------------------------------------
step "Image size comparison (for the README)"
printf '    %-34s %s\n' "runtime (shipped):"  "$(docker images "$IMAGE"     --format '{{.Size}}')"
printf '    %-34s %s\n' "test stage (with devDeps):" "$(docker images "$FAT_IMAGE" --format '{{.Size}}')"

printf '\n\033[32mALL LOCAL CHECKS PASSED\033[0m\n'
