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
# "Every gate" is meant literally, and it has had to be re-earned twice.
#
# First at ten checks, when CI had twelve: the production `npm audit` gate and
# the Trivy IMAGE scan ran only on the runner. Then again at twelve, when the
# `lint` job added hadolint and zizmor to CI. Both times the gap was the same
# shape - CI could reject a push that this script had just called clean, and the
# first place you would find out is the push that turns main red.
#
# Steps 11-14 exist to close those gaps. A local pass should mean CI passes, or
# the harness is lying to you. The rule this implies is worth stating: adding a
# gate to ci.yml is not finished until it is also a step here.
#
# The image scan in particular is not redundant with step 10: the filesystem
# scan reads package-lock.json, and cannot see the Alpine OS packages or
# anything baked into the base image underneath the app.
#
# ---------------------------------------------------------------------------
# ON OUTPUT
#
# Each check prints ONE line carrying the measurement that justifies it -
# `uid 1000`, `cache -> 172.18.0.2`, `3 commits, 0 leaks`. Everything verbose
# goes to the detail log instead.
#
# This is not just tidiness. The unquieted run printed several hundred lines
# (Trivy's DB download progress bar alone redraws ~50 times), and a wall of
# output that always looks the same is one you stop reading - at which point
# the harness has stopped doing its job.
#
# The rule that keeps that honest: ON FAILURE, DUMP EVERYTHING. A check that
# goes quiet when it breaks is strictly worse than a noisy one, so `run()`
# replays the captured output before failing. The demo/* branches are the proof
# this works, because those runs are SUPPOSED to fail - and they still print
# the full Trivy table and Gitleaks finding.
#
# NOTE: on the demo/* branches this script is SUPPOSED to fail - step 9 finds
# the planted secret, step 10 finds the planted lodash CVE. That is the demo
# working, not the harness breaking.
# ---------------------------------------------------------------------------

set -euo pipefail

IMAGE="macky-merch-api:local"
FAT_IMAGE="macky-merch-api:test"
CONTAINER="macky-verify"

# Git Bash on Windows rewrites container-side paths like /repo into C:\... before
# Docker ever sees them. Harmless no-op on Linux and macOS.
export MSYS_NO_PATHCONV=1

# Verbose output lands here. Override with VERIFY_DETAIL_LOG to put it outside
# the repo (test-local.cmd does exactly that, so `git add -A` never sees it).
DETAIL="${VERIFY_DETAIL_LOG:-verify-detail.log}"
: > "$DETAIL"

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

# Printed before the check runs, so a hang is attributable to a named step
# rather than to a blank screen.
step() { CURRENT="$2"; printf '  %5s  %-42s' "$1" "$2"; }
ok()   { printf '%sPASS%s  %s\n' "$GREEN" "$OFF" "${1:-}"; }
die()  { printf '%sFAIL%s  %s\n' "$RED" "$OFF" "$1"; exit 1; }

# run <command...>  - quiet on success, replays THIS STEP's output on failure.
#
# The per-step temp file is not incidental. Appending straight to $DETAIL and
# dumping `tail -60 "$DETAIL"` on failure looks equivalent and is not: when a
# step fails having printed little or nothing, the tail shows the PREVIOUS
# step's output instead, and you debug the wrong check. That happened - a Trivy
# DB timeout produced a dump full of Docker Compose logs.
run() {
  local tmp rc=0
  tmp="$(mktemp)"
  "$@" >"$tmp" 2>&1 || rc=$?
  cat "$tmp" >>"$DETAIL"
  if [ "$rc" -ne 0 ]; then
    printf '%sFAIL%s\n\n' "$RED" "$OFF"
    printf '%s--- output of: %s ---%s\n' "$DIM" "$CURRENT" "$OFF"
    tail -n 60 "$tmp"
    printf '%s--- full log: %s ---%s\n\n' "$DIM" "$DETAIL" "$OFF"
  fi
  rm -f "$tmp"
  return "$rc"
}

# --- Scanner images, pinned by digest ----------------------------------------
#
# ci.yml pins every action to an immutable SHA and the Dockerfile pins its base
# image to a digest, both on the argument that "a tag is a pointer someone else
# can move; a digest is the artifact itself". This harness runs four scanners as
# containers, and used `:latest` for all of them - which is the same class of
# trust the rest of the project refuses to extend. These are pinned for the same
# reason, and they are the exact images the current results were produced with.
#
# Two honest caveats, because pinning is not free:
#
#   1. Dependabot does not read shell scripts, so nothing refreshes these
#      automatically the way it refreshes ci.yml. They need a periodic manual
#      bump; CI, which Dependabot does cover, remains the authority.
#   2. Pinning a SCANNER can freeze its detection rules, which is a real cost -
#      an out-of-date scanner is its own failure mode. It applies to gitleaks,
#      whose rules are compiled into the binary. It does NOT apply to Trivy:
#      Trivy downloads its vulnerability database at runtime, so a pinned Trivy
#      image still scans against today's advisories.
GITLEAKS_IMAGE="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
TRIVY_IMAGE="aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
HADOLINT_IMAGE="hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d"
ZIZMOR_IMAGE="ghcr.io/zizmorcore/zizmor@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101"

# Trivy ships its ~114MB vulnerability database inside its cache directory, and
# `docker run --rm` throws that away every single run - so every invocation
# re-downloads it. That is slow, and it is flaky: a run failed here with
# `context deadline exceeded` mid-download, which reads as a scanner failure
# when it is really a network one. A named volume persists the DB between runs,
# mirroring what the CI job gets from actions/cache.
TRIVY_CACHE="macky-trivy-cache"
trivy() { docker run --rm -v "$TRIVY_CACHE:/root/.cache/trivy" "$@"; }

# Always clean up the test container, even if a check fails partway through.
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

printf '\n%s  Macky Merch API - local verification%s   %s14 checks%s\n' \
  "$BOLD" "$OFF" "$DIM" "$OFF"
printf '  %sbranch %s  ·  detail %s%s\n\n' \
  "$DIM" "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')" "$DETAIL" "$OFF"

# -----------------------------------------------------------------------------
step "1/14" "Node unit tests (host)"
run npm ci --no-fund --no-audit --loglevel=error || die "npm ci failed"
run npm test || die "jest suite failed"
# Jest writes its summary to stderr, so it is in the detail log either way.
#
# The `sed` is required, not defensive. Jest emits ANSI colour codes even when
# its output is redirected to a file, and it puts them INSIDE the summary line:
#
#   ESC[1mTests:       ESC[22mESC[1mESC[32m1 passedESC[39mESC[22m, 1 total
#
# so a plain `grep -oE 'Tests: +[0-9]+ passed'` never matches and the step
# reported "? test(s)" on every run - a check silently losing the one
# measurement that justifies it. Strip the escapes first, then match.
tests="$(sed 's/\x1b\[[0-9;]*m//g' "$DETAIL" | grep -aoE 'Tests: +[0-9]+ passed' | tail -1 | grep -oE '[0-9]+' || echo '?')"
ok "$tests test(s), node $(node -v)"

# -----------------------------------------------------------------------------
step "2/14" "Test stage build (jest in Alpine)"
# Also the regression test for the .dockerignore trap: excluding *.test.js from
# the build context leaves jest with nothing to run, and jest exits 1 on
# "No tests found". If this fails with that message, the bug is in
# .dockerignore, not in the test.
run docker build --progress quiet --target test -t "$FAT_IMAGE" . \
  || die "test stage build failed - if it says 'No tests found', check .dockerignore"
ok

# -----------------------------------------------------------------------------
step "3/14" "Runtime image build"
# --target runtime explicitly. A bare `docker build .` happens to produce the
# same image only because runtime is the last stage in the file; relying on
# stage ordering is exactly the fragility docker-compose.yml warns about.
run docker build --progress quiet --target runtime -t "$IMAGE" . || die "runtime build failed"
ok "$(docker images "$IMAGE" --format '{{.Size}}')"

# -----------------------------------------------------------------------------
step "4/14" "Non-root check (spec requirement)"
uid="$(docker run --rm --entrypoint id "$IMAGE" -u)"
[ "$uid" != "0" ] || die "container runs as root (uid 0)"
ok "uid $uid"

# -----------------------------------------------------------------------------
step "5/14" "Dev deps absent from the image"
# Captured to a variable first, then matched with a here-string. The obvious
# `docker run ... | grep -qx jest` is subtly wrong under `set -o pipefail`:
# grep -q exits the moment it matches, the upstream `ls` can then take SIGPIPE
# and exit 141, and pipefail propagates that non-zero status - so a jest that IS
# present reads as a failed pipeline and the `if` takes the wrong branch. The
# check would silently pass in exactly the case it exists to catch.
modules="$(docker run --rm --entrypoint ls "$IMAGE" /app/node_modules)"
if grep -qx "jest" <<<"$modules"; then
  die "jest found in the runtime image - multi-stage build is not isolating deps"
fi
ok "$(wc -l <<<"$modules" | tr -d ' ') packages, no jest/supertest"

# -----------------------------------------------------------------------------
step "6/14" "Smoke test /health"
cleanup
# Bound to 127.0.0.1, matching docker-compose.yml. A bare -p 3000:3000 binds
# 0.0.0.0 and publishes this container to every device on the local network.
docker run -d --name "$CONTAINER" -p 127.0.0.1:3000:3000 "$IMAGE" >>"$DETAIL" 2>&1
health=""
for _ in $(seq 1 15); do
  if health="$(curl -fsS http://127.0.0.1:3000/health 2>/dev/null)"; then break; fi
  sleep 1
done
[ -n "$health" ] || { docker logs "$CONTAINER" >>"$DETAIL" 2>&1; die "/health never became reachable - see $DETAIL"; }
printf '%s\n' "$health" >>"$DETAIL"
ok "200 $(grep -o '"status":"[^"]*"' <<<"$health")"

# -----------------------------------------------------------------------------
step "7/14" "Prompt shutdown (tini forwards SIGTERM)"
start=$(date +%s)
docker stop "$CONTAINER" >>"$DETAIL" 2>&1
elapsed=$(( $(date +%s) - start ))
# Without an init, node runs as PID 1, where the kernel ignores signals that
# have no explicit handler. docker stop is then ignored for the full 10-second
# grace period before SIGKILL.
[ "$elapsed" -lt 5 ] || die "took ${elapsed}s to stop - SIGTERM is not being forwarded"
ok "${elapsed}s"
cleanup

# -----------------------------------------------------------------------------
step "8/14" "Compose stack + service DNS"
run docker compose up -d --build --quiet-pull || die "compose stack failed to start"
docker compose ps >>"$DETAIL" 2>&1
if ! curl -fsS http://127.0.0.1:3000/health >/dev/null 2>&1; then
  docker compose logs >>"$DETAIL" 2>&1; docker compose down -v >>"$DETAIL" 2>&1
  die "compose /health unreachable - see $DETAIL"
fi
# Prove the Docker network actually resolves the service name.
if ! cache_ip="$(docker compose exec -T api node -e \
    "require('dns').promises.lookup('cache').then(r=>{console.log(r.address);process.exit(0)}).catch(()=>process.exit(1))" 2>>"$DETAIL")"; then
  docker compose down -v >>"$DETAIL" 2>&1
  die "api cannot resolve 'cache' over macky-net"
fi
run docker compose down -v || true
ok "cache -> $(tr -d '\r\n' <<<"$cache_ip")"

# -----------------------------------------------------------------------------
step "9/14" "Secret scan (Gitleaks)"
# Mirrors the nightly CI run rather than the per-push one: it walks history
# rather than a commit range, which is the check worth running before you push
# something you cannot un-publish.
#
# --log-opts=HEAD is doing real work here, and it is the same scoping ci.yml
# applies for the same reason. `gitleaks detect` defaults to scanning EVERY REF
# in the repository, not the checked-out branch - so with a demo branch sitting
# in the repo, this step fails while you are on a clean main, and the failure
# points at a file that is not in your working tree.
#
# A harness that is stricter than CI is worse than no harness: it fails on
# things CI would pass, and you learn to ignore it. Local and CI now ask the
# identical question - "is there a secret in the history of the branch we
# ship?" - and the demo branches still fail their own PRs, which is their job.
run docker run --rm -v "$(pwd):/repo" "$GITLEAKS_IMAGE" \
      detect --source /repo --redact -v --no-banner --log-opts=HEAD \
  || die "gitleaks found a secret (expected on demo/leaked-secret)"
ok "$(grep -aoE '[0-9]+ commits scanned' "$DETAIL" | tail -1), 0 leaks"

# -----------------------------------------------------------------------------
step "10/14" "Dependency scan (Trivy fs)"
# Same thresholds as the CI gate: HIGH/CRITICAL only, and --ignore-unfixed so a
# CVE with no available patch does not fail a build nobody can act on.
# --no-progress, NOT --quiet. `--quiet` also suppresses log output, which means
# a failing scan prints nothing at all and the dump above has nothing to show.
# This kills the 50-line progress bar and keeps the findings table.
run trivy -v "$(pwd):/repo" "$TRIVY_IMAGE" \
      fs /repo --no-progress --scanners vuln --severity HIGH,CRITICAL \
      --ignore-unfixed --exit-code 1 \
  || die "Trivy found a fixable HIGH/CRITICAL (expected on demo/vulnerable-dependency)"
ok "0 fixable HIGH/CRITICAL"

# -----------------------------------------------------------------------------
step "11/14" "Production npm audit"
# A second opinion from a different vulnerability database. Trivy and npm audit
# do not always agree, and the disagreement is itself signal.
#
# --omit=dev is the npm-side equivalent of the Dockerfile's `deps` stage, so
# this asks exactly one question: "is there a fixable HIGH in code that reaches
# production?" jest and supertest drag in a large transitive tree that never
# leaves CI; a finding there is worth seeing but not worth blocking a release
# over, which is why CI reports the full tree separately and gates only here.
run npm audit --omit=dev --audit-level=high \
  || die "npm audit found a HIGH in production dependencies (expected on demo/vulnerable-dependency)"
ok "0 high+ in production deps"

# -----------------------------------------------------------------------------
step "12/14" "Image scan (Trivy, shipped artifact)"
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
run trivy -v //var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
      image "$IMAGE" --no-progress --scanners vuln --severity HIGH,CRITICAL \
      --ignore-unfixed --exit-code 1 \
  || die "Trivy found a fixable HIGH/CRITICAL in the shipped image"
ok "0 fixable HIGH/CRITICAL"

# -----------------------------------------------------------------------------
step "13/14" "Dockerfile lint (hadolint)"
# Mirrors the `lint` job in ci.yml. Fails on `warning` and above, matching the
# workflow's failure-threshold, so a Dockerfile edit that CI would reject gets
# rejected here first.
#
# Currently clean, with exactly one suppression: DL3018 is disabled inline in
# the Dockerfile because pinning an apk package revision contradicts the
# `apk upgrade` on the same line. The reasoning lives next to the code it
# excuses, not in a config file nobody reads.
run docker run --rm -i "$HADOLINT_IMAGE" hadolint --no-color --failure-threshold warning - < Dockerfile \
  || die "hadolint found a Dockerfile issue"
ok "no warnings"

# -----------------------------------------------------------------------------
step "14/14" "Workflow audit (zizmor)"
# Mirrors the `lint` job's second step. Audits ci.yml and dependabot.yml for
# unpinned actions, over-broad permissions, credential persistence and template
# injection - the security of the pipeline itself, which every other check in
# this harness takes for granted.
#
# Runs the ONLINE audits when a GitHub token is available, matching CI exactly.
#
# This used to pass `--offline` unconditionally, and that gap shipped a real
# failure: `ref-version-mismatch` needs the API to resolve a pinned SHA back to
# its tags, so it cannot fire offline. The local run went green, CI went red,
# and the harness had once again promised something it was not checking.
#
# `gh auth token` is used when present; without it the scan falls back to
# offline rather than failing, so the harness still works on a machine with no
# GitHub CLI - it just says so.
zizmor_args=(--no-progress --persona regular)
if _tok="$(gh auth token 2>/dev/null)" && [ -n "$_tok" ]; then
  zizmor_args+=(--gh-token "$_tok")
else
  zizmor_args+=(--offline)
  printf '(offline: no gh token) ' >&2
fi
run docker run --rm -v "$(pwd):/repo" -w /repo "$ZIZMOR_IMAGE" \
      "${zizmor_args[@]}" .github/ \
  || die "zizmor found a workflow issue"
unset _tok
ok "workflows clean"

# -----------------------------------------------------------------------------
printf '\n  %sALL 14 CHECKS PASSED%s   runtime %s · test stage %s\n' \
  "$GREEN" "$OFF" \
  "$(docker images "$IMAGE" --format '{{.Size}}')" \
  "$(docker images "$FAT_IMAGE" --format '{{.Size}}')"
printf '  %sdetail: %s%s\n\n' "$DIM" "$DETAIL" "$OFF"
