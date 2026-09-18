# syntax=docker/dockerfile:1

###############################################################################
# Stage 1 - deps: PRODUCTION dependencies only.
#
# Kept as its own stage so the runtime image never sees jest/supertest and
# their transitive tree. Measured: 273 packages in the test stage vs 67 in the
# runtime image - 206 fewer, worth 62MB. Fewer packages shipped = smaller image
# AND a smaller CVE surface for Trivy to find things in.
###############################################################################
# The digest is the actual reproducibility guarantee. `node:24-alpine` is a
# MUTABLE tag - Docker Hub re-pushes it on every patch release (it moved on
# 2026-09-09), so `FROM node:24-alpine` yields different bytes on different
# days. That is the same objection this project raises against `node:latest`,
# only slower-moving; a tag is a pointer, and only a digest is an identity.
#
# The tag is kept alongside for human readability, and Dependabot's `docker`
# ecosystem (.github/dependabot.yml) bumps the digest weekly, so pinning does
# not mean going stale.
FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS deps

WORKDIR /app

# Copy manifests ONLY (not the whole source tree).
# Docker caches layers by their inputs, so this RUN is re-executed only when
# package.json / package-lock.json actually change. Editing server.js does not
# trigger a 30-second reinstall.
COPY package.json package-lock.json ./

# `npm ci` (not `npm install`):
#   - installs the EXACT tree in package-lock.json, ignoring semver ranges
#   - deletes node_modules first, so builds are reproducible
#   - hard-fails if package.json and the lockfile have drifted apart
# `--omit=dev` drops jest/supertest. `npm cache clean` reclaims ~40MB that
# would otherwise be baked into this layer forever.
RUN npm ci --omit=dev && npm cache clean --force


###############################################################################
# Stage 2 - test: full dependency tree + Jest.
#
# This stage is NOT part of the runtime image's ancestry, so a plain
# `docker build .` skips it entirely (BuildKit only builds stages the target
# actually depends on). CI invokes it explicitly:
#
#     docker build --target test .
#
# That makes the image build itself a test gate, and runs Jest against the
# exact Alpine/musl userland that ships to production - not just the CI
# runner's Ubuntu/glibc.
###############################################################################
FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS test

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

RUN npm test


###############################################################################
# Stage 3 - runtime: the image that actually ships.
###############################################################################
FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS runtime

# One RUN, two jobs, in the order the command runs them.
#
# =============================================================================
# 1. `apk upgrade` - patch the base image's OS packages at build time.
# =============================================================================
#
# This line is load-bearing.
#
# Digest-pinning the base image buys reproducibility, but it freezes the OS
# packages at whatever state that digest was published in - so a pinned image is
# also a pinned-and-vulnerable one the moment a CVE lands upstream. Official
# images lag Alpine's security updates by days or weeks, and there is no version
# of "wait for the base image" that is faster than "patch it yourself at build
# time".
#
# Concretely, and measured rather than asserted (2026-09-17):
#
#   trivy image --severity HIGH,CRITICAL --ignore-unfixed <pinned base digest>
#     -> Total: 2 (HIGH: 2)
#        libcrypto3  CVE-2026-14456  3.5.7-r0 -> fixed in 3.5.8-r0
#        libssl3     CVE-2026-14456  3.5.7-r0 -> fixed in 3.5.8-r0
#
#   trivy image --severity HIGH,CRITICAL --ignore-unfixed macky-merch-api:local
#     -> Total: 0        (the shipped image carries libssl3-3.5.8-r0)
#
# So this one line is the difference between a base image with two fixable HIGH
# CVEs and a shipped image with none. Without it the image scan in CI fails on a
# clean main, gating every merge on a CVE that is not in this repository's code
# and cannot be fixed from it. `scripts/verify.sh` step 12 runs that same scan
# locally, so the claim is re-checked on every run rather than trusted.
#
# The honest trade-off: the apk repository is a moving target, so this reduces
# byte-for-byte reproducibility of the final image. That is the correct trade -
# the digest still pins the base layer, Node version and layout, while this line
# means "and current security patches on top". Reproducibility exists to make
# builds trustworthy, not to preserve known-vulnerable libraries.
#
# =============================================================================
# 2. `apk add tini` - a real init process for PID 1.
# =============================================================================
#
# tini reaps orphaned child processes and forwards signals.
#
# PID 1 is special: the kernel ignores signals that have no explicit handler
# installed. Node does not install a SIGTERM handler, so as PID 1 it ignores
# `docker stop` entirely - Docker waits out the full 10s grace period, then
# SIGKILLs. With tini at PID 1, node runs as a normal child, the default SIGTERM
# disposition applies, and the process exits immediately. ~1MB well spent.
#
# Precisely: this buys PROMPT, signal-correct shutdown - not connection
# draining. Draining in-flight requests would need `server.close()` inside
# server.js, and the starter repo forbids modifying it. Fast teardown is the
# part that is achievable from the container layer, and it is the part that
# makes deploys quick and `docker stop` honest.
#
# =============================================================================
# On the suppression below
# =============================================================================
#
# hadolint's DL3018 wants `apk add tini=0.19.0-r3` rather than a bare package
# name, on the general principle that unpinned installs are not reproducible.
# That principle is sound and it is the wrong call HERE, for a specific reason:
# it directly contradicts the `apk upgrade` on the same line.
#
# This RUN deliberately takes whatever Alpine currently ships, because the whole
# argument above is that current security patches beat frozen bytes. Pinning
# tini to an exact `-rN` package revision would also break the build outright
# the moment Alpine rebuilds the package, since old revisions are dropped from
# the repository index.
#
# So it is suppressed - narrowly, on one line, with the reasoning attached -
# rather than silenced globally in a config file. Same standard `.trivyignore`
# sets for vulnerability findings: an exception has to argue for itself.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && apk add --no-cache tini

# Remove the package managers. A container whose only job is `node server.js`
# has no use for npm, npx, yarn or corepack at runtime - and shipping them is
# actively harmful in two distinct ways:
#
#   1. CVEs you cannot fix. npm vendors its own dependency tree into the base
#      image at /usr/local/lib/node_modules/npm/node_modules. Trivy scans it and
#      counts it against this image, even though none of it is reachable from
#      the application and none of it appears in package-lock.json. When this
#      line was written the image scan reported 4 fixable HIGH findings there -
#      brace-expansion (CVE-2026-14257, CVE-2026-69152), ip-address
#      (CVE-2026-69192, SSRF) and tar (CVE-2026-73566) - none of which
#      `npm audit` or the filesystem scan could see, and none of which could be
#      fixed from this repository.
#
#      That count is a snapshot, not a constant: re-scanned on 2026-09-17 the
#      same paths came back clean, because the advisory database and the base
#      image both moved on. The number is dated deliberately rather than
#      deleted - the argument does not depend on it. What is permanent is the
#      shape of the problem: shipping someone else's dependency tree means
#      inheriting its findings, on their schedule, with no remedy available from
#      this repo except "wait for a new base image" or "don't ship it".
#
#   2. It is a ready-made install tool. An attacker with code execution in this
#      container would otherwise have a working package manager and network
#      egress sitting right there.
#
# Consistent with the argument for Alpine over Debian, one level up: the most
# reliable way to not have a vulnerability is to not have the package.
#
# Note what this does and does not buy. The entire node-pkg class of findings
# disappears from the scan, and the files are gone from the final filesystem -
# but the image does NOT get 18MB smaller, because deleting in a later layer
# cannot reclaim bytes from an earlier one. It is the same property .dockerignore
# exists to work around, seen from the other side: a layer is append-only, so
# `rm` writes a whiteout rather than freeing space. Removing it from the base
# image would require rebuilding the base image.
RUN rm -rf \
      /usr/local/lib/node_modules/npm \
      /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm \
      /usr/local/bin/npx \
      /usr/local/bin/corepack \
      /usr/local/bin/yarn \
      /usr/local/bin/yarnpkg \
      /opt/yarn-*

# Signals "production" to Express and the wider npm ecosystem: disables verbose
# error pages, enables view caching, and is read by many libraries.
ENV NODE_ENV=production

WORKDIR /app

# --chown at COPY time rather than a later `RUN chown -R`.
# A separate RUN would copy the ENTIRE node_modules tree into a second layer
# just to change ownership bits, roughly doubling the image size.
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node server.js ./

# NOTE: server.test.js is deliberately NOT copied. Test code is not runtime
# code - shipping it enlarges the image and widens the attack surface for
# nothing.
#
# This is an allow-list COPY, and that is the point: it is the ONLY correct
# place to exclude test code. Doing it in .dockerignore instead would break the
# `test` stage above, which needs the spec files in the build context in order
# to have anything to run. One context, three stages, different needs.

# The `node` user (uid 1000, gid 1000) ships with the official image, so there
# is no need to create one. Everything above this line ran as root; everything
# from here - including the app - runs unprivileged.
# Required by the exam spec, and it means a container escape starts from an
# unprivileged account instead of root.
#
# Written numerically rather than as `USER node`, which is the same account -
# `id node` in this base image returns uid=1000(node) gid=1000(node).
#
# The numeric form is strictly more useful to whatever runs the container.
# A name only means something to a process that can read /etc/passwd INSIDE the
# image, so an orchestrator enforcing "must not run as root" cannot evaluate
# `node` without starting the container first. Kubernetes' `runAsNonRoot` admits
# exactly this: given a username it cannot verify the UID is non-zero, and
# refuses to schedule the pod. A number is checkable from the manifest alone.
# hadolint's DL3066 makes the same point about host-side resolvability.
#
# Both halves are given (`1000:1000`) so the primary group is pinned too, rather
# than inherited from whatever the runtime decides to default to.
USER 1000:1000

# Documentation only - EXPOSE publishes nothing by itself. The actual mapping
# is `docker run -p`, which keeps the port a deploy-time decision.
EXPOSE 3000

# Uses Node 24's built-in global fetch(), so the image needs no curl or wget -
# two fewer binaries an attacker could use to pull a payload.
#
# Exec form (a JSON array), not shell form. Shell form wraps the command in
# `/bin/sh -c`, which forks an extra process every 30 seconds for the life of
# the container and puts a shell between Docker and the thing being measured.
# Exec form runs node directly. It also matches the healthcheck in
# docker-compose.yml, which was already written this way - the two now express
# the identical check in the identical syntax. (hadolint DL3025.)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# ENTRYPOINT + CMD split: tini is always PID 1, but the command stays
# overridable (`docker run <image> node --version`) for debugging.
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
