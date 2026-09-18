# Macky Merch API — Secure Delivery Pipeline

![CI](https://github.com/Jeck-bot/devsecops-exam-starter/actions/workflows/ci.yml/badge.svg)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Jeck-bot/devsecops-exam-starter/badge)](https://scorecard.dev/viewer/?uri=github.com/Jeck-bot/devsecops-exam-starter)

LSCS DevSecOps Engineering Challenge — 41st LSCS, Term 1.

A baseline Express API (`/health`, one Jest test) wrapped in a containerised, automated, security-gated
delivery pipeline. The application code is unchanged; **the pipeline is the deliverable.**

### Where the required answers live

| Spec requirement | Answered in |
|---|---|
| Setup instructions — build and run the container locally | [Setup instructions](#setup-instructions) |
| Why this base image, and not `node:latest` | [Why `node:24-alpine`](#why-node24-alpine) |
| Which security scanner, and why that one | [Security integration](#security-integration) |
| Vulnerability demonstration — the pipeline catching a planted flaw | [Vulnerability demonstration](#vulnerability-demonstration) |
| Challenges faced | [Challenges faced](#challenges-faced) |

**Contents:** [Pipeline at a glance](#pipeline-at-a-glance) · [Setup](#setup-instructions) ·
[Architecture](#architectural-explanation) · [CI/CD](#cicd-pipeline) ·
[Security](#security-integration) · [Vulnerability demo](#vulnerability-demonstration) ·
[What this does *not* cover](#api-security-what-this-pipeline-does-not-cover) ·
[Bonus features](#bonus-features) · [Challenges](#challenges-faced) ·
[Checklist](#submission-checklist)

> Sections marked **▸** are collapsible. The argument is always in the open text; the folded blocks
> hold the supporting evidence — measurements, log output, regexes, and the options that were
> considered and rejected. Nothing is hidden because it's weak.

---

## Pipeline at a glance

```
 push / pull_request -> main              nightly schedule (02:00 UTC)
            │                                        │
  ┌─────────┼──────────────┬───────────┬──────────┐  │
  ▼         ▼              ▼           ▼          ▼  │
 test    secret-scan  dependency-scan codeql    lint ◄┘  parallel — fail fast
 (22,24)  Gitleaks    Trivy fs +      JS static  hadolint
                      npm audit       analysis   + zizmor
  │
  └────────────► docker
                 ├─ build --target test   (jest inside Alpine)
                 ├─ build runtime
                 ├─ assert non-root       ← enforces the spec, every commit
                 ├─ assert no devDeps     ← enforces the multi-stage split
                 ├─ smoke-test /health
                 ├─ Trivy image scan
                 └─ SBOM (CycloneDX)      ← inventory, not a gate

 push -> main / nightly only
  └─ scorecard   OpenSSF supply-chain posture — informational, never gates
```

Six jobs on a pull request. Five start immediately; `docker` alone waits — on `test`, so build minutes
aren't spent on code that's already broken. The scanners deliberately do **not** gate each other, so one
red run reports every distinct problem at once rather than revealing them one push at a time.

`lint` is the odd one out, and deliberately so: every other job scans the application or its
dependencies, and **none of them would notice if the pipeline itself were the insecure part.** The
Dockerfile and `ci.yml` are where most of this project's security decisions actually live, and they run
privileged. A repository that scans its code but never scans its build has a blind spot precisely where
it can least afford one.

---

## Setup instructions

**Quickest path** — `make help` lists every entry point:

```bash
make up                                  # app + Redis, built and running
curl http://127.0.0.1:3000/health
make down
```

The `Makefile` is a thin convenience layer; every target wraps one of the commands below, so nothing
is hidden behind it and nothing breaks if you don't have `make`.

### Run with Docker

```bash
docker build -t macky-merch-api:local .
docker run --rm -p 127.0.0.1:3000:3000 macky-merch-api:local

curl http://127.0.0.1:3000/health
# {"status":"OK","message":"Macky Merch API is running smoothly."}
```

> Bound to `127.0.0.1` rather than the usual `-p 3000:3000`, which binds `0.0.0.0` and publishes the
> container to every device on the local network.

> `/health` is the only route. `GET /` returning 404 is expected behaviour, not a fault.

### Run with Docker Compose (app + Redis)

```bash
docker compose up -d --build
docker compose ps           # both services should report (healthy)
curl http://127.0.0.1:3000/health
docker compose down -v
```

### Run without Docker

```bash
npm ci
npm test
npm start
```

### Verify everything at once

```bash
bash scripts/verify.sh
```

Fourteen checks: host tests → test-stage build → runtime build → non-root assertion → dev-dependency
isolation → `/health` smoke test → prompt shutdown → the Compose stack with DNS resolution → a
full-history Gitleaks scan → a Trivy dependency gate → the production `npm audit` gate → a Trivy
scan of the shipped image → hadolint → zizmor. Exits 0 only if all pass.

That list is deliberately identical to the set of gates in `ci.yml`, and it has had to be re-earned
twice. First when `npm audit --omit=dev` and the image scan were CI-only; again when `lint` added
hadolint and zizmor. Both times the gap had the same shape — CI could reject a push this script had
just called clean, and the first place you'd find out is the push that turns `main` red.

The rule that falls out of it: **adding a gate to `ci.yml` isn't finished until it's also a step here.**
A harness that covers *most* of the pipeline tells you the least on exactly the days you need it most.

---

## Architectural explanation

### Why `node:24-alpine`?

**Why not `node:latest`** — it's an unpinned moving target. The same `docker build` produces different
images on different days, and it will silently carry you across a major version bump the moment one is
released. Reproducible builds require a pinned tag.

**Why not `node:18-alpine`** (the example in the spec)? Because Node 18 reached end of life on
2025-04-30, and an EOL runtime receives **no security patches at all**. Pinning to it means every future
CVE in the Node runtime is permanently unfixed — which would quietly undermine the entire point of
bolting a vulnerability scanner on downstream. Node 24 is the current Active LTS line and matches the
local development runtime (v24.21.0), so "works on my machine" and "works in the image" mean the same
thing.

**Why Alpine over the Debian-based tags?** `node:24-alpine` is **235 MB** on disk against **~1.1 GB**
for `node:24` — roughly 4.7× smaller. Size is the visible benefit; the security benefit is the real one.
Alpine ships a fraction of the OS packages, and **a package that isn't installed cannot have a CVE.**
Smaller base → smaller attack surface → a shorter Trivy report that people actually read.

**Why the digest and not just the tag?** The argument against `node:latest` is an argument about
mutability, and it applies to `node:24-alpine` too — just more slowly. That tag is re-pushed on every
patch release, so `FROM node:24-alpine` still means "whatever that name points at today". A tag is a
pointer; only a digest is an identity.

<details>
<summary><b>▸ The Node release schedule, the size numbers, and the musl trade-off</b></summary>

| Release line | Status | End of life |
|---|---|---|
| Node 18 (Hydrogen) | **EOL** | 2025-04-30 |
| Node 20 (Iron) | **EOL** | 2026-04-30 |
| Node 22 (Jod) | Maintenance LTS | 2027-04-30 |
| **Node 24 (Krypton)** | **Active LTS** | 2028-04-30 |

*(Dates from the official `nodejs/Release` schedule. Node 24 enters Maintenance on 2026-10-20, when Node
26 becomes Active LTS — so this table has a known expiry, which is the point of writing the dates down
rather than the word "current".)*

Base image sizes, measured rather than estimated:

| Base image | Compressed (pull) | On disk |
|---|---|---|
| `node:24` (Debian) | 410 MB | ~1.1 GB |
| `node:24-alpine` | **59 MB** | **235 MB** |

> Worth stating explicitly because the two numbers get conflated constantly: Docker Hub reports
> *compressed* size, `docker images` reports *uncompressed on-disk* size. They differ by about 4×, so
> quoting one against the other makes a base image look far better or worse than it is.

**The honest trade-off:** Alpine uses musl libc rather than glibc. Native C++ addons occasionally
misbehave under musl, and there have been reported DNS-resolution edge cases. That risk is acceptable
here because the dependency tree is pure JavaScript (Express and its transitive deps compile nothing) —
and the `test` build stage runs Jest *inside* Alpine, so any musl incompatibility fails the build rather
than reaching production.

**The digest in full:**

```dockerfile
FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS deps
```

That tag moved on 2026-09-09 during this build. Pinning the digest is what makes the build actually
reproducible, and Dependabot's `docker` ecosystem bumps it weekly so pinning doesn't mean going stale.

</details>

### Why a multi-stage build?

Three stages, each with one job:

| Stage | Purpose | Ships? |
|---|---|---|
| `deps` | `npm ci --omit=dev` — production dependencies only | node_modules only |
| `test` | full dep tree + `npm test` | ❌ never |
| `runtime` | tini + prod deps + `server.js` | ✅ |

The `test` stage isn't in the runtime stage's ancestry, so a plain `docker build .` skips it entirely.
CI builds it deliberately with `--target test`, which turns the image build into a test gate — and runs
Jest against the exact musl userland that ships, not the CI runner's Ubuntu.

Measured result (`docker images`, uncompressed):

| Image | Size | Packages in `/app/node_modules` |
|---|---|---|
| `test` stage (with devDependencies) | 312 MB | 273 |
| `runtime` stage (shipped) | **250 MB** | **67** |
| Difference | **62 MB** | **206 fewer** |

Everything jest and supertest drag in — **206 packages** — is absent from the shipped image. Each one
would have been code an attacker could potentially reach.

The pipeline **asserts** the split rather than trusting it: the `docker` job runs `ls /app/node_modules`
inside the built image and fails if `jest` is present. Without that check, dropping `--omit=dev` from the
`deps` stage would still build, still serve traffic, and still pass every other test — it would just
quietly ship 206 extra packages.

<details>
<summary><b>▸ Where the 250 MB actually goes — the application is 0.01% of its own image</b></summary>

| Layer | Size |
|---|---|
| `node:24-alpine` base | 235 MB |
| `apk upgrade` + tini | 6.6 MB |
| production `node_modules` (67 packages) | 4.6 MB |
| `rm` of the bundled package managers | 29 kB |
| `server.js` + `package.json` | 25 kB |

That ratio is worth internalising: the base image *is* the attack surface, which is why the choice
between Alpine and Debian — and what gets stripped out of the base, below — matters more than anything
done in the application layer above it.

</details>

### Why the runtime stage patches and strips its own base image

Two lines in the runtime stage exist because **the image scan failed on a clean `main`** — no vulnerable
application dependency, `npm audit` green, the Trivy filesystem scan reporting `package-lock.json: 0`, and
the image gate still red. Both findings came from the base image, and neither was fixable from anything in
this repository.

**1. `rm -rf` the bundled package managers.** Trivy counted HIGH findings that appear nowhere in
`package-lock.json` — they live in **npm's own vendored dependency tree**, shipped inside the official
Node image. A container whose only job is `node server.js` needs no package manager at runtime, so npm,
npx, yarn and corepack are deleted. That removes the entire `node-pkg` class of findings legitimately
rather than by suppression, and takes a ready-made install tool away from an attacker who gains code
execution. Same argument as Alpine-over-Debian, one level down: *the most reliable way not to have a
vulnerability is not to have the package.*

**2. `apk upgrade --no-cache` — where digest pinning bites back.** Pinning a digest freezes the OS
packages at whatever state that digest was published in, so **a pinned image is also a
pinned-and-vulnerable one** the moment a CVE lands upstream. Official images trail Alpine's security
updates by days or weeks, and there is no version of "wait for a new base image" that beats patching at
build time. Measured on this exact digest: the base carries **2 fixable HIGH**, the shipped image
carries **0**.

Nothing is in `.trivyignore`. Both problems were fixed, not silenced.

<details>
<summary><b>▸ The measurements, and what stripping npm does <i>not</i> buy you</b></summary>

The npm findings at the time of writing were `brace-expansion` (CVE-2026-14257, CVE-2026-69152),
`ip-address` (CVE-2026-69192, an SSRF) and `tar` (CVE-2026-73566), all under
`/usr/local/lib/node_modules/npm/node_modules/`. Re-scanned later those came back clean — advisory
databases move, so that count is a dated observation, not a constant. The argument doesn't depend on it:
shipping someone else's dependency tree means inheriting its findings on their schedule.

> Worth being precise about what the `rm` does **not** do: the image doesn't get 18 MB smaller. Deleting
> in a later layer cannot reclaim bytes from an earlier one — `rm` writes a whiteout, and the data stays
> in the base layer. Same append-only property that makes `.dockerignore` necessary, seen from the other
> side. The files are gone from the final filesystem (so Trivy no longer finds them) but not from the
> image's history.

The OpenSSL finding, which *does* still reproduce:

```
# the pinned base digest
trivy image --severity HIGH,CRITICAL --ignore-unfixed node:24-alpine@sha256:50c8e8...
  Total: 2 (HIGH: 2)
  libcrypto3  CVE-2026-14456  3.5.7-r0 -> fixed in 3.5.8-r0
  libssl3     CVE-2026-14456  3.5.7-r0 -> fixed in 3.5.8-r0

# the image we ship
trivy image --severity HIGH,CRITICAL --ignore-unfixed macky-merch-api:local
  Total: 0        (libssl3-3.5.8-r0)
```

The honest trade-off: `apk` is a moving target, so this reduces byte-for-byte reproducibility of the
final image. That's the correct trade. The digest still pins the base layer, the Node version and the
filesystem layout; this line adds "…and current security patches on top". Reproducibility exists to make
builds trustworthy, not to preserve known-vulnerable libraries.

`scripts/verify.sh` step 12 runs that same scan locally, so the claim is re-checked on every run rather
than trusted.

</details>

### Why non-root, and why tini?

```dockerfile
USER node
```

Everything before this line runs as root (installing tini needs it); everything after — including the
application — does not. The `node` user (uid 1000) ships with the official image, so no `useradd` is
needed.

This matters because container isolation is not a security boundary you should bet on. If the app is
compromised, root inside the container is a far better launchpad for a kernel-exploit escape than an
unprivileged account. It also blocks the mundane failure modes: writing to `/etc`, installing packages,
binding privileged ports.

The pipeline **asserts** this rather than trusting it — the `docker` job runs `id -u` inside the built
image every commit and fails if it returns `0`.

**tini** solves a separate problem. PID 1 is special: the kernel ignores signals that have no explicit
handler installed. Node doesn't install a SIGTERM handler, so as PID 1 it ignores `docker stop`
entirely — Docker waits the full 10-second grace period, then SIGKILLs, making every deploy slow. tini
sits at PID 1, forwards signals, and reaps zombies, for about 1 MB. Measured: the container stops in
**2 s** instead of 10.

<details>
<summary><b>▸ The assertion, and what tini does <i>not</i> buy</b></summary>

```yaml
- name: Assert the container does not run as root
  run: |
    uid=$(docker run --rm --entrypoint id "${IMAGE_NAME}:${GITHUB_SHA}" -u)
    if [ "$uid" = "0" ]; then exit 1; fi
```

**Stated precisely:** tini buys *prompt, signal-correct* shutdown — **not** connection draining.
Draining in-flight requests requires `server.close()` inside `server.js`, and the starter repo forbids
modifying it. Fast teardown is the part achievable from the container layer, and it's the part that
makes `docker stop` honest; the rest is noted in
[API security](#api-security-what-this-pipeline-does-not-cover) below.

</details>

### Why `npm ci` and not `npm install`?

The spec's checklist says `npm install`; the pipeline uses `npm ci`, which is the deterministic form of
the same operation:

| | `npm install` | `npm ci` |
|---|---|---|
| Source of truth | `package.json` ranges | `package-lock.json` exactly |
| Can silently upgrade a dep | **yes** (`^4.18.2` → `4.19.x`) | no |
| Lockfile drift | rewrites it | **fails the build** |
| `node_modules` | patches in place | wipes first |

`^4.18.2` matching a version published after CI went green is precisely how a supply-chain compromise
reaches production through a "passing" pipeline. `npm ci` makes the tested tree and the shipped tree
provably identical.

### Why `.dockerignore`?

**Docker does not read `.gitignore`.** The starter's `.gitignore` excludes `node_modules` from git, and
Docker cheerfully ignores that and uploads it anyway.

Three reasons it matters, in ascending order of importance:

1. **Speed** — the whole context is tarred and sent to the daemon before the first instruction runs.
2. **Caching** — any change to any non-ignored file invalidates `COPY` layers.
3. **Security** — a `COPY . .` bakes whatever it finds into a layer. **Deleting it in a later layer does
   not remove it** — it stays readable via `docker history` and `docker save`. `.git` is the sharp edge
   here: it holds the full history, so a secret committed and later removed still ships inside the image.

<details>
<summary><b>▸ The entry that is deliberately <i>absent</i>, and why adding it breaks every build</b></summary>

It's tempting to add `*.test.js`, since the runtime image obviously has no business carrying test code.
That is a trap. `.dockerignore` filters the **build context**, which is shared by *every* stage — so
excluding the spec files also hides them from the `test` stage, where Jest then finds nothing to run and
exits 1 on `No tests found`. The result is a Dockerfile that fails to build on every single commit.

Test code is kept out of the shipped image by a stronger mechanism instead: the runtime stage copies an
explicit **allow-list**, not everything-minus-a-deny-list.

```dockerfile
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node server.js ./
```

Nothing leaks in by accident, because nothing gets in unless it's named. One build context, three
stages, different needs — and the deny-list is the wrong tool for the only stage that matters.

There's also a correctness angle on Windows: the host `node_modules` contains Windows-native binaries
that cannot execute on Alpine. Excluding it forces `npm ci` to build a correct Linux tree.

</details>

---

## CI/CD pipeline

`.github/workflows/ci.yml`, triggered on push and pull request to `main`, plus manual dispatch and a
nightly schedule.

| Job | Does | A failure means |
|---|---|---|
| `test` | `npm ci` + `npm test` on Node 22 and 24 | the code is broken |
| `secret-scan` | Gitleaks over the event's commits (full history nightly) | a credential was committed |
| `dependency-scan` | Trivy `fs` + `npm audit` | a dependency has a fixable HIGH/CRITICAL CVE |
| `codeql` | GitHub static analysis (`security-extended`) | a dataflow vulnerability in the source |
| `lint` | hadolint on the Dockerfile, zizmor on the workflows | the *pipeline* has a defect |
| `docker` | builds both stages, asserts non-root and dep isolation, smoke-tests `/health`, scans the image, emits an SBOM | the artefact is invalid or vulnerable |
| `scorecard` | OpenSSF supply-chain posture — `main`/nightly only | *(never gates — informational)* |

Deliberate choices worth calling out:

- **`permissions: contents: read` at the top.** The `GITHUB_TOKEN` starts read-only; only
  `dependency-scan`, `codeql` and `scorecard` opt into `security-events: write` for SARIF. The `docker`
  and `lint` jobs ask for nothing extra, because they upload none — an unused grant is just latent blast
  radius.
- **Every third-party action pinned to a full commit SHA**, tag in a trailing comment. This is the control
  that actually backs the line above: least privilege limits what a compromised action can *do*; SHA
  pinning limits what can *become* a compromised action. `@v7` is a pointer the upstream owner can move at
  any time — a SHA is the artifact itself, not a name for it. Dependabot's `github-actions` ecosystem
  bumps them weekly, so this doesn't mean running stale actions.
- **`persist-credentials: false` on every checkout.** By default `actions/checkout` writes the job token
  into `.git/config`, where it stays readable by every later step. Nothing here pushes, so there's no
  reason to keep it — least privilege applied to credentials, not just permissions.
- **`timeout-minutes` on every job.** Without one, a hung job runs to GitHub's 6-hour ceiling, burning
  runner minutes and holding the concurrency group open.
- **`concurrency` that cancels PR runs only.** `cancel-in-progress: ${{ github.event_name == 'pull_request' }}`.
  Superseding an obsolete PR run saves minutes; cancelling a run on `main` would leave its head commit
  neither green nor red, which blocks merges under branch protection *and* destroys the "main is green"
  evidence this pipeline exists to produce.
- **`fetch-depth: 0` on the secret scan.** Required — see the scoping note below.
- **A nightly `schedule`.** Not redundant with push runs: it's the only thing that catches what changes
  while your code doesn't. See [Security integration](#security-integration).
- **Matrix on Node 22 and 24, `fail-fast: false`.** Confirms the app isn't accidentally coupled to one
  runtime, and tells you whether a failure is version-specific or universal.
- **`docker needs: [test]`.** Fail cheap before failing expensive.

---

## Security integration

Five scanners, chosen to cover different axes rather than duplicate each other. The spec asks for *at
least one*; these were added because each closes a gap the others structurally cannot see, not to run up
a count.

| Threat | Tool | Job | Blocking |
|---|---|---|---|
| Vulnerable npm package | Trivy `fs` + `npm audit` | `dependency-scan` | ✅ |
| CVE in base-image OS packages | Trivy `image` | `docker` | ✅ |
| CVE in packages bundled *inside* the base image | Trivy `image` | `docker` | ✅ |
| Secret in the working tree | Trivy `secret` | `dependency-scan` | report |
| Secret in the commits being pushed | Gitleaks | `secret-scan` | ✅ |
| Secret **anywhere in git history** | Gitleaks (nightly) | `secret-scan` | ✅ |
| Uncatalogued dataflow vulnerability | CodeQL | `codeql` | ✅ |
| Insecure **Dockerfile** construction | hadolint | `lint` | ✅ |
| Insecure **workflow** construction | zizmor | `lint` | ✅ |
| "What is actually inside the shipped image?" | Trivy CycloneDX SBOM | `docker` | artefact |
| Repository-level supply-chain posture | OpenSSF Scorecard | `scorecard` | report |
| Dockerfile / Compose misconfiguration | Trivy `misconfig` | `dependency-scan` | report |

**Why Trivy?** One static binary covering four scan classes — dependencies, OS packages, secrets, and
IaC misconfiguration — with no server to run and no account to create. Critically, it scans **both** the
source tree and the built image. Those find different things: `npm audit` cannot see a CVE in the Alpine
`openssl` package, and a source-tree scan cannot see what the base image dragged in.

**Why Gitleaks as well?** Trivy's secret scanner reads the *current working tree*. Gitleaks reads *commit
history*. Since `git` never really forgets, a credential deleted three commits ago is still extractable by
anyone who clones the repo — and it's the single most common way secrets actually leak. Trivy structurally
cannot cover that axis.

**Why CodeQL as the third?** Trivy and Gitleaks both ask *"is there a known-bad known thing here?"* — a
package with a CVE, a string matching a credential pattern. Both work from a list, so neither can find a
bug nobody has catalogued yet. CodeQL builds a dataflow graph of the source and looks for untrusted input
reaching a dangerous sink. Three tools, three genuinely different failure modes. (`security-extended` is
justified here because the codebase is ~20 lines: the usual objection to that suite is false-positive
volume, and there is no volume.)

### Who scans the pipeline?

Those three all scan the *application*. None of them would notice if the insecure thing were the build
itself — and the build is privileged code: it runs with a repository token, pulls third-party actions,
and produces the artefact everything else is busy validating. That's the blind spot `lint` covers.

**hadolint** lints the Dockerfile. It found three things, and the split between them is the point:

| Finding | Verdict |
|---|---|
| `DL3025` — shell-form `HEALTHCHECK` | **Fixed.** Exec form avoids forking `/bin/sh` every 30s for the life of the container, and now matches the healthcheck `docker-compose.yml` already used. |
| `DL3066` — `USER node` is non-numeric | **Fixed.** `USER 1000:1000` is the same account, but a name only resolves *inside* the image. Kubernetes' `runAsNonRoot` cannot verify a username is non-zero and refuses to schedule the pod; a number is checkable from the manifest. |
| `DL3018` — unpinned `apk add tini` | **Suppressed, with the reasoning inline.** |

That last one is the interesting one. DL3018 wants `apk add tini=0.19.0-r3`, and the rule is generally
right — but here it contradicts the `apk upgrade` on the same line, which exists specifically to take
current security patches. Pinning an exact `-rN` revision would also break the build outright the moment
Alpine rebuilds the package, since old revisions drop out of the index. So it's disabled on one line,
next to the code it excuses, rather than globally in a config file. Same standard `.trivyignore` sets: an
exception has to argue for itself.

**zizmor** audits the workflows — unpinned actions, over-broad `permissions`, credential persistence,
and `${{ }}` expressions interpolated into `run:` blocks where they could inject shell. It is the tool
that independently checks the claims this README makes. Arguing that a pipeline is hardened is cheap;
having a purpose-built auditor agree is not. `ci.yml` currently reports **no findings**.

It did flag something, though — in `dependabot.yml`, and it's the most counter-intuitive control here:

> **`cooldown`, or: the remediation path is itself attack surface.**
>
> Every other control in this repository pushes toward updating *faster*. Cooldown pushes the other way,
> because package compromises are overwhelmingly **opportunistic** — an attacker who gets a malicious
> version published expects it to be yanked within hours once someone notices. The window they're
> actually farming is the one where automation pulls the release before any human has looked at it. A
> pipeline that auto-bumps to a version published twenty minutes ago isn't being diligent; it's
> volunteering to be the canary.
>
> **What makes this safe to adopt:** cooldown does not apply to security updates. Per GitHub's Dependabot
> reference, *"This default cooldown does not apply to security updates"* — advisory-driven fixes bypass
> it entirely. So it slows down *"there is a newer version"* and never slows down *"the version you have
> is vulnerable."* Those are different events and only one is urgent. Set to 7 days here (14 for majors);
> Dependabot's built-in default is 3.

### The SBOM, and why an inventory outlives a scan

The `docker` job emits a CycloneDX SBOM of the finished image and uploads it as a build artefact.

Trivy already scans that image two steps earlier, so why bother? Because a scan answers *"is anything
vulnerable **today**"*, against today's advisory database — a point-in-time verdict that starts decaying
immediately. An SBOM answers *"what is in here"*, which doesn't decay. When a CVE drops next month, the
question is whether this image is affected, and an inventory answers it in seconds without a rebuild or
a rescan of an image nobody kept.

It's generated with the `trivy-action` already pinned above rather than by adding a dedicated SBOM
action. This project's whole argument is that every third-party action is supply-chain surface; pulling
in another vendor to emit a file the existing scanner already produces would undercut it.

### Scorecard — the one verdict this repo didn't write itself

Every other check here was designed by the same person who designed the thing being checked. OpenSSF
Scorecard is the outside opinion: it grades the repository against recognised supply-chain criteria —
pinned dependencies, least-privilege tokens, branch protection, a security policy, maintained
dependencies, CI tests.

**It never gates**, and it runs only on `main` and the nightly schedule. Two reasons: it measures
repository *settings* as much as file contents, so per-PR runs would score the same posture repeatedly;
and several checks legitimately cannot score full marks here — `Fuzzing` and `Signed-Releases` don't
apply to a coursework fork with no releases, and `Branch-Protection` reads low because the default token
can't read protection settings without an admin-scoped PAT. **A gate that fails for reasons nobody can
act on is the exact anti-pattern this repository argues against everywhere else**, so it reports instead.

### Gitleaks scope — stated precisely, because it's easy to get wrong

`gitleaks-action` does **not** scan the full history on every run. Reading its source, `Scan()` appends
`--log-opts=--no-merges --first-parent <base>^..<head>` depending on the event:

| Event | What is scanned |
|---|---|
| `push` | only the commits in that push |
| `pull_request` | only the commits in that PR |
| `schedule` | the full history **of `main`** |
| `workflow_dispatch` | the full history of the dispatched ref |

So the per-commit runs catch a secret *as it is introduced* — that's what makes the `demo/leaked-secret`
PR go red — and the **nightly `schedule` run** is what actually covers *"a credential committed and
deleted months ago, still recoverable by anyone who clones this repo."* You need both; either alone leaves
a real gap, and it would be easy to ship only the first while believing you had the second.

`fetch-depth: 0` is required either way: `checkout` defaults to a shallow clone, and resolving `<base>^`
needs the parent commit to exist locally. With the default depth the scan errors out or silently degrades
to a single commit.

<details>
<summary><b>▸ Why the nightly run scans <code>main</code> and not every ref — a bug the harness found</b></summary>

The bottom two rows say *"the full history of `main`"* rather than *"the entire history,"* and that
distinction was not a design decision up front — it was a bug found by running the harness.

`gitleaks detect` defaults to walking **every ref in the repository**, not the checked-out branch. Combine
that with `fetch-depth: 0` — which fetches every branch as `refs/remotes/origin/*` — and a nightly run
sitting on a clean `main` also walks `demo/leaked-secret` and fails on the fake key deliberately planted
there. Measured in a clone with `main` checked out and the demo branch present only as a remote-tracking
ref: **4 commits scanned, 2 leaks reported**, on a `main` that has 3 commits and is clean.

The failure mode is nasty precisely because it is *correct*. The key really is in the repository, and the
scanner really did find it. But the run is red on a branch containing nothing wrong, pointing at a file
that is not in the working tree — and it directly contradicts the "`main` is green" evidence that putting
the demos on separate branches exists to produce in the first place.

The fix is `--log-opts=HEAD` on the scheduled run, which scopes the walk to that ref's ancestry:

- a secret that ever landed on `main` **is** still caught — it is an ancestor of `main`;
- the demo branches are never merged, so they are not ancestors and are not scanned;
- they still fail their own PRs via the per-commit path above, which is their entire job.

This is why the scheduled step invokes the digest-pinned `gitleaks` container directly instead of the
action: the action exposes no way to pass `--log-opts`. `scripts/verify.sh` step 9 applies the same
scoping, so the local harness and CI ask the identical question. A harness that is *stricter* than CI is
worse than none — it fails on things CI would pass, and you learn to ignore it.

</details>

### Why gate on HIGH/CRITICAL only, and `ignore-unfixed: true`?

A gate that fires constantly gets disabled. Failing builds on LOW/MEDIUM findings — or on CVEs with no
available patch — produces noise nobody can action, and trains engineers to reach for blanket ignores. The
threshold is set where a failure means *"there is something you can actually fix right now."*

**Report and gate are separate steps** on purpose: the Trivy table always prints, even on a green build,
so the current state stays visible rather than only surfacing at the moment it blocks someone.

`npm audit` is split the same way, but along a different axis:

| Step | Scope | Blocking |
|---|---|---|
| `npm audit - full tree (report)` | includes devDependencies | no |
| `npm audit - production dependencies (gate)` | `--omit=dev` | ✅ |

The gate asks exactly one question: *is there a fixable HIGH in code that reaches production?* A HIGH in a
Jest transitive dependency is worth seeing, but blocking a release over code that never leaves the CI
runner is how a gate loses credibility. This is the npm-side equivalent of the Dockerfile's `deps` stage —
and it's why the deliberate lodash vulnerability goes into `dependencies`, not `devDependencies`.

### Why nightly

Two things change while your source code doesn't: **newly disclosed CVEs** (a dependency clean at merge
time can be CRITICAL a week later with no commit in between — push-triggered scanning can only tell you
about code you just wrote), and **git history** (the scheduled run is the only one that sees all of
`main`'s history rather than just the triggering event's commits).

<details>
<summary><b>▸ A note on <code>github-pat</code> — a plausible-sounding justification that was wrong</b></summary>

An earlier revision passed `github-pat: ${{ secrets.GITHUB_TOKEN }}` to the Trivy steps, believing it
authenticated the vulnerability-DB pull from ghcr.io and avoided `TOOMANYREQUESTS`. It does not. Reading
`trivy-action`'s `entrypoint.sh`, `INPUT_GITHUB_PAT` is only read inside
`if [ "$TRIVY_FORMAT" = "github" ]` — it authenticates an *upload* to the Dependency Snapshot API,
nothing else. The input was removed.

What actually mitigates the rate limit is already in place: the action restores the DB through
`actions/cache` under a date-based key, so at most the first run of each day downloads anything, and the
later passes reuse the binary via `skip-setup-trivy`.

Recorded because a plausible-sounding, wrong justification in a config comment is worse than no comment —
it stops anyone from checking.

</details>

### Remediation, not just detection

`.trivyignore` is committed but **empty**, with a header requiring every future entry to carry a CVE ID, a
specific non-exploitability justification, a review date, and an approver — plus a pointer to
`.trivyignore.yaml`, whose `expired_at` field makes Trivy enforce the expiry itself rather than trusting
someone to notice.

`.github/dependabot.yml` covers npm packages, the Docker base image, and the GitHub Actions themselves.
Trivy is *detective* — it reports that a vulnerable package is already present. Dependabot is
*preventative* — it opens the PR that removes it. A scanner without a remediation path just produces a red
build nobody can fix.

---

## Vulnerability demonstration

The spec requires deliberately introducing a flaw and proving the pipeline catches it. Both offered
options are demonstrated, on two branches with **open, failing PRs** as evidence.

**Why not on `main`?** A default branch with a permanently red pipeline reads as a broken repo, and it
contradicts the branch-protection bonus — whose entire purpose is preventing exactly that from merging.
This way both facts are demonstrable: `main` is green, and the gates genuinely bite.

### Demo A — vulnerable dependency (`demo/vulnerable-dependency`)

PR: **[#1 — DEMO — DO NOT MERGE: deliberately vulnerable lodash@4.17.20](https://github.com/Jeck-bot/devsecops-exam-starter/pull/1)** (left open and failing, on purpose)

`lodash@4.17.20`, pinned exactly, added to `dependencies`:

| | |
|---|---|
| CVE | **CVE-2021-23337** |
| Flaw | Command injection via `_.template` |
| Severity | **HIGH** (CVSS 7.2) |
| Fixed in | `4.17.21` |

The "fixed in" row is load-bearing. Because the gate runs with `ignore-unfixed: true`, a CVE with no
available patch would be filtered out and the demo would silently pass. **A vulnerable package is not
sufficient — it has to be a fixable one.** It also went into `dependencies` rather than
`devDependencies`, so it survives the `--omit=dev` gate, reaches the production image, and gets caught a
second time by the image scan.

**Result — three independent failures:**

| Check | Verdict |
|---|---|
| `Dependency scan (Trivy + npm audit)` | ❌ fail |
| `Docker build & image scan` | ❌ fail |
| `Trivy` (code scanning alert, from the SARIF upload) | ❌ fail |
| `Unit tests (Node 22)` / `(Node 24)` | ✅ pass |
| `Secret scan (Gitleaks)` | ✅ pass |
| `Static analysis (CodeQL)` | ✅ pass |

![Vulnerable dependency PR](docs/img/pr-vuln-dependency.png)

That split matters as much as the failures do. A dependency CVE *should not* break the unit tests or
trip the secret scanner — if it did, the gates would be measuring something other than what they claim.

Two scanners reading two different databases both flagged it, and Trivy additionally found
**`CVE-2026-4800`** — a second advisory the demo was not designed around. The scanner found more than the
author knew about, which is the entire argument for running one.

<details>
<summary><b>▸ The CI logs, verbatim — Trivy's table and <code>npm audit</code> agreeing independently</b></summary>

From the `Trivy - FAIL on HIGH/CRITICAL` step of [run 35212574910](https://github.com/Jeck-bot/devsecops-exam-starter/actions/runs/35212574910):

```
package-lock.json (npm)
=======================
Total: 2 (HIGH: 2, CRITICAL: 0)

┌─────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬──────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │                            Title                             │
├─────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ lodash  │ CVE-2021-23337 │ HIGH     │ fixed  │ 4.17.20           │ 4.17.21       │ nodejs-lodash: command injection via template                │
│         │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-23337                   │
│         ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│         │ CVE-2026-4800  │          │        │                   │ 4.18.0        │ lodash: lodash: Arbitrary code execution via untrusted input │
│         │                │          │        │                   │               │ in template imports                                          │
│         │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-4800                    │
└─────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴──────────────────────────────────────────────────────────────┘

##[error]Process completed with exit code 1.
```

And from `npm audit - production dependencies (gate)` in the same job — a second database, reached
independently, agreeing:

```
# npm audit report

lodash  <=4.17.23
Severity: high
Command Injection in lodash - https://github.com/advisories/GHSA-35jh-r3h4-6jhm
Regular Expression Denial of Service (ReDoS) in lodash - https://github.com/advisories/GHSA-29mw-wpgm-hmr9
lodash vulnerable to Code Injection via `_.template` imports key names - https://github.com/advisories/GHSA-r5fr-rjxr-66jc
lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit` - https://github.com/advisories/GHSA-f23m-r3pf-42rh
fix available via `npm audit fix --force`
Will install lodash@4.18.1, which is outside the stated dependency range
node_modules/lodash
```

</details>

![Trivy CVE detail](docs/img/trivy-cve-detail.png)

### Demo B — leaked secret (`demo/leaked-secret`)

PR: **[#3 — DEMO — DO NOT MERGE: fake API token committed to trip the secret scanner](https://github.com/Jeck-bot/devsecops-exam-starter/pull/3)** (left open and failing, on purpose)

A fake high-entropy token committed to `config/api-credentials.sample.env`. It was never valid and grants
access to nothing.

**Not `.env`** — the starter's `.gitignore` excludes that exact name, so the file would never have been
committed and the scanner would have had nothing to find. A planted secret that git silently refuses to
track is the most embarrassing way for this demo to "pass".

**Not an AWS key either**, and that turned out to be the more interesting half. The first version planted
a realistic `AKIA…` key and **could not be pushed at all** — see
[The control outside the pipeline](#the-control-outside-the-pipeline). So it was rebuilt to target a real
gap: GitHub push protection matches **provider** patterns only (narrow by design — a false positive blocks
an engineer's push), while Gitleaks also carries `generic-api-key`, which fires on any high-entropy value
bound to a secret-shaped name. A token in no vendor's format pushes cleanly and Gitleaks catches it
anyway. Verified before being relied on: `RuleID: generic-api-key`, entropy **4.66**.

**Result — one job fails, and only one:**

| Check | Verdict |
|---|---|
| `Secret scan (Gitleaks)` | ❌ fail |
| `Dependency scan (Trivy + npm audit)` | ✅ pass |
| `Docker build & image scan` | ✅ pass |
| `Unit tests (Node 22)` / `(Node 24)` | ✅ pass |
| `Static analysis (CodeQL)` | ✅ pass |

![Leaked secret PR](docs/img/pr-leaked-secret.png)

`Dependency scan` passing is an assertion, not a formality: its gate step runs `scanners: vuln` only, so
a secret surfacing there would mean that step is misconfigured.

![Gitleaks detail](docs/img/gitleaks-detail.png)

<details>
<summary><b>▸ The Gitleaks finding, verbatim from CI</b></summary>

From the `Secret scan (Gitleaks)` job of
[run 35221770125](https://github.com/Jeck-bot/devsecops-exam-starter/actions/runs/35221770125):

```
Finding:     MACKY_INTERNAL_API_TOKEN=REDACTED
Secret:      REDACTED
RuleID:      generic-api-key
Entropy:     4.663533
File:        config/api-credentials.sample.env
Line:        50
Commit:      3a187bd01df76a03538b73453cde2cf0dd01452a

1 commits scanned.
leaks found: 1
```

Note `Secret: REDACTED` — `--redact` is on, so the pipeline proves the catch without reprinting the
credential into CI logs that are themselves world-readable on a public repo. A secret scanner that leaks
the secret into its own output has not helped.

It also deliberately does **not** imitate a vendor prefix. Faking a `sk_live_`-shaped string for a
service we don't use would be a worse artefact *and* would risk tripping the very control being routed
around, for nothing.

</details>

<details>
<summary><b>▸ Preserved: the AWS-key analysis from the first attempt</b> — the reasoning still stands, it just could not be pushed</summary>

The original planted key avoided a trap that silently produces a false pass:

**Not `AKIAIOSFODNN7EXAMPLE`** — AWS's canonical documentation key. Gitleaks allowlists it *explicitly*:
the `aws-access-token` rule carries `allowlists.regexes = ['''.+EXAMPLE$''']`, precisely because that
string appears in every tutorial. Using it means the scan passes and you conclude the pipeline works when
it does not.

The replacement was checked against the scanner's *actual current rule* rather than a remembered version:

| Check | Value |
|---|---|
| Rule regex (gitleaks 8.24.3 — the version the action pins) | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16})\b` |
| Rule regex (current gitleaks) | `...[A-Z2-7]{16}` — **base32**, narrower |
| Shannon entropy | 4.22 (rule requires > 3) |
| Path allowlisted? | No |

Upstream narrowed that trailing character class from `[A-Z0-9]` to base32 `[A-Z2-7]`. The planted key
contained only `2`, `3`, `4`, `7`, so it satisfied both and survived the change — but a regenerated key
containing a `0`, `1`, `8`, or `9` would match the old rule, fail the current one, and produce a silent
green build. Same failure mode as the documentation-key trap, one layer deeper.

That analysis was independently vindicated: GitHub's secret scanner — a different implementation by a
different vendor — flagged the same string on sight. The key was realistic enough to be unpushable, which
is the strongest possible confirmation that it was not a toy.

</details>

### The control outside the pipeline

This section exists because pushing Demo B **failed**, and the reason was more interesting than the demo.

`git push` never reached CI. GitHub Push Protection rejected it server-side with `GH013`, naming both
planted strings by file and line. Three things follow:

**1. Detective and preventative controls sit at different points in time.** Everything in `ci.yml` runs
*after* a push — it can only tell you a secret has already been published. Push protection runs *before*
one and refuses the write.

| Control | When | Can it stop the leak? |
|---|---|---|
| Push protection | before the object reaches the remote | **yes** |
| `secret-scan` on push/PR | after | no — reports it |
| nightly `secret-scan` | much later | no — reports it |

This pipeline was designed as though it were the outermost layer. It is not, and this README described
the repository's posture incompletely until being blocked proved otherwise.

**2. It independently validates the planted key.** Demo B's original AWS key was chosen by reasoning
about Gitleaks' regex. GitHub's scanner is a separate implementation by a different vendor and flagged
the same string on sight — including the secret access key that Gitleaks only catches via its generic
entropy rule. Two independent detectors agreeing beats the regex analysis alone.

**3. You cannot simply turn it off** — the API call to disable it succeeds, reads back `disabled`, and
the push is rejected anyway. On a public repo the provider-pattern rule is enforced at platform level.
That is the correct design: a control an admin can quietly switch off for sixty seconds is barely a
control.

So the demo was **rebuilt rather than forced through** — around the provider/generic gap described in
Demo B above. Nothing was disabled, nothing was bypassed, push protection is still `enabled`, and the
pipeline's own secret gate is demonstrated failing a real PR.

<details>
<summary><b>▸ The rejection verbatim, and the disable attempt</b></summary>

```
remote: error: GH013: Repository rule violations found for refs/heads/demo/leaked-secret.
remote:
remote: - GITHUB PUSH PROTECTION
remote:   —————————————————————————————————————————
remote:     Resolve the following violations before pushing again
remote:
remote:     - Push cannot contain secrets
remote:
remote:       —— Amazon AWS Access Key ID ——————————————————————————
remote:        locations:
remote:          - commit: f7c495ddde0e0a66bf9e017700fa5641d46bd1d7
remote:            path: config/aws-credentials.sample.env:22
remote:
remote:       —— Amazon AWS Secret Access Key ——————————————————————
remote:        locations:
remote:          - commit: f7c495ddde0e0a66bf9e017700fa5641d46bd1d7
remote:            path: config/aws-credentials.sample.env:23
remote:
remote: ! [remote rejected] demo/leaked-secret -> demo/leaked-secret (push declined due to repository rule violations)
```

The obvious escape hatch is to disable push protection, push, and re-enable. That is one API call:

```bash
gh api -X PATCH repos/OWNER/REPO \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=disabled'
```

The call succeeds. Reading the setting back confirms
`"secret_scanning_push_protection":{"status":"disabled"}`. **The push is still rejected**, with the
identical `GH013`. The toggle governs the repository's own configuration; it does not buy an opt-out
from the platform-level rule.

The remaining sanctioned route is the per-secret unblock URL in the rejection message, which requires a
human to state a reason. That is the right escape hatch for a genuine false positive, but reaching for
it here would have meant weakening a real control to stage a demonstration of a weaker one.

> The lesson that generalises past this exam: **to test a detective control you often have to stand down
> a preventative one — and the discipline is in how narrowly you do it, and whether you put it back.**
> Here the answer was not to stand anything down at all.

</details>

### For contrast — `main` stays green

![Green pipeline on main](docs/img/main-green.png)

### A note on permanence

That fake key is now in the fork's history **permanently**. Deleting the file in a later commit does not
remove it — `git log -p` still shows it. That is exactly why `secret-scan` checks out with
`fetch-depth: 0`, and why the nightly full-history scan exists alongside the per-push one.

It is also the reason the nightly scan is scoped to `main`'s ancestry rather than every ref
(see [Security integration](#security-integration)). The key on `demo/leaked-secret` is
permanent in exactly the sense this section describes — so an unscoped nightly scan would report it
every night, forever, for a branch that is *supposed* to contain it. A finding that can never be
actioned is not a finding; it is a broken alarm, and a broken alarm gets muted along with the real ones.

It's also why the real-world response to a leaked credential is **rotate first, delete second**: the
secret is compromised the moment it's pushed, and removing the file only hides it from the current tree.
Ours is safe to leave because it was never valid.

---

## API security: what this pipeline does *not* cover

A secure delivery pipeline and a secure API are different problems, and it would be misleading to let a
green pipeline imply the second. The exam states backend code is not graded, and the starter repo says not
to modify `server.js` — so the following are deliberately **not implemented**, and listed here as the
honest boundary of what has been secured rather than as an oversight.

| Gap | Risk | Standard remedy |
|---|---|---|
| No security headers | Clickjacking, MIME sniffing, no HSTS | `helmet()` |
| No rate limiting | Brute force, trivial application-layer DoS | `express-rate-limit`, or at the ingress/CDN |
| No CORS policy | Express defaults to no CORS headers — safe today, but undefined rather than decided | explicit `cors({ origin: [...] })` |
| No authentication or authorisation | `/health` is public by design; any future route inherits nothing | JWT/OIDC middleware, deny-by-default routing |
| No connection draining | `docker stop` kills in-flight requests (tini makes it prompt, not graceful) | SIGTERM handler calling `server.close()` |
| No structured logging | No audit trail; ad-hoc logging risks writing secrets to stdout | `pino` with explicit redaction |
| No error handler | Express's default handler can leak stack traces | a terminal 4-arg error middleware |

Two things the baseline *does* get right and are worth not breaking: `express.json()` already caps request
bodies at 100kb (an unbounded body parser is a memory-exhaustion vector), and `/health` returns a fixed
object with no request data reflected into it.

The container layer mitigates some of this from underneath — non-root execution, all capabilities dropped,
a read-only root filesystem, and Redis unreachable from the host — but defence in depth is not a
substitute for the application-layer controls. **If this were a real service, the table above is the next
piece of work**, and the pipeline built here is what would keep it honest once written: CodeQL already
scans for the injection and dataflow classes those routes would introduce.

---

## Bonus features

| Bonus | Status | Evidence |
|---|---|---|
| Docker Compose (app + dummy DB on a network) | ✅ | `docker-compose.yml` |
| Multi-stage build | ✅ | `Dockerfile` — 3 stages, size table above |
| Branch protection | ✅ | screenshot below |

### Docker Compose

`api` + `cache` (Redis 7 Alpine) on a user-defined bridge network, `macky-net`. A user-defined bridge —
rather than the default one — gives automatic DNS resolution between services by name.

Hardening applied to both services: `no-new-privileges`, all capabilities dropped, and the API is
`read_only` with a tmpfs `/tmp`. The API publishes to `127.0.0.1:3000` rather than `0.0.0.0` — plain
`"3000:3000"` exposes it to every device on the network. **Redis publishes no port at all**: it's
reachable from `api` over `macky-net` but not from the host, because Redis has no authentication by
default and an exposed unauthenticated data store is a well-worn breach path.

**Why `user: "999:1000"` on the Redis service.** Dropping all capabilities and leaving the container to
start as root is a combination that does not work, for a non-obvious reason. The official Redis entrypoint
contains:

```sh
if [ "$1" = 'redis-server' -a "$(id -u)" = '0' ]; then
	exec gosu redis "$0" "$@"
fi
```

Because the `command:` begins with `redis-server`, a container starting as root takes that branch — and
`gosu` calls `setuid(2)`/`setgid(2)`, which require `CAP_SETUID`/`CAP_SETGID`. `cap_drop: ALL` removes
exactly those, so `gosu` fails, the container dies, its healthcheck never passes, and `api` — which waits
on `condition: service_healthy` — never starts at all. Setting `user:` explicitly makes `id -u` non-zero,
so the entrypoint skips the branch and execs Redis directly. That's strictly better than
`cap_add: [SETUID, SETGID]`: the process is never root at any point, not even briefly.

**Scope note, stated plainly:** `server.js` never reads `REDIS_URL`. That's deliberate — the starter
repo's README says not to modify core application functionality, and this track isn't graded on backend
code. The spec asks for a dummy database container *"connected via a Docker network"*, so the network
wiring is the deliverable, and it's verifiable rather than merely asserted:

```bash
docker compose exec api node -e "require('dns').promises.lookup('cache').then(console.log)"
# { address: '172.x.x.x', family: 4 }
```

### Branch protection

`main` requires all seven status checks to pass before merging, with **"do not allow bypassing"**
enabled — without that, repository admins silently bypass the rule and it protects nobody.

| Required check | Job |
|---|---|
| `Unit tests (Node 22)` | `test` (matrix) |
| `Unit tests (Node 24)` | `test` (matrix) |
| `Secret scan (Gitleaks)` | `secret-scan` |
| `Dependency scan (Trivy + npm audit)` | `dependency-scan` |
| `Static analysis (CodeQL)` | `codeql` |
| `Lint (Dockerfile + workflows)` | `lint` |
| `Docker build & image scan` | `docker` |

> Those are the job **`name:` values**, not the job IDs. GitHub registers a status check under the
> display name when one is set, so requiring `secret-scan` or `test (22)` silently protects nothing —
> the context never matches, and the rule sits there looking configured. A matrix job also registers
> one check per combination, which is why `test` appears twice.

![Branch protection rule](docs/img/branch-protection.png)
![Merge blocked on a failing PR](docs/img/merge-blocked.png)

---

## Challenges faced

The spec asks for **one** hurdle. Here it is — the one that changed how I think about where security
controls live, rather than the one that took longest to debug.

**The pipeline was not the outermost layer, and I only found out by being stopped.**

Pushing the leaked-secret demo branch failed. Not a red check — the push itself was refused,
server-side, before any workflow ran:

```
remote: error: GH013: Repository rule violations found for refs/heads/demo/leaked-secret.
remote:     - Push cannot contain secrets
remote:       —— Amazon AWS Access Key ID ——————————————————————————
remote:            path: config/aws-credentials.sample.env:22
```

I had designed and reasoned about this repository as though `ci.yml` were the whole of its security. It
isn't. Everything in the pipeline is **detective** and runs *after* a push — at which point the secret is
already on a remote and, as the permanence note above says, is compromised whether or not you delete it.
GitHub Push Protection is **preventative** and runs *before* the write lands. It is strictly the more
valuable of the two, and I hadn't accounted for it anywhere.

It also delivered a result I could not have got myself: an *independent* confirmation that the planted key
is realistic. I had argued from Gitleaks' regex that the key would match and that AWS's documentation key
would not. GitHub's scanner is a different implementation by a different vendor, and it flagged the same
string — plus the secret access key on line 23, which Gitleaks only catches through a generic entropy rule.

Resolving it taught me more than the demo did. My first instinct was to disable push protection, push, and
re-enable — and the API accepted it. `gh api -X PATCH … push_protection][status]=disabled` returned
success, and reading the setting back confirmed `disabled`. **The push was rejected anyway.** On a public
repository GitHub enforces push protection for high-confidence provider patterns regardless of the
repository toggle.

I was mildly annoyed for about a minute and then realised it is the correct design. A control an admin can
quietly switch off for sixty seconds is barely a control. The one that refused my attempt to disable it is
the one genuinely protecting the credential.

The fix was to stop trying to defeat it. Push protection matches **provider** patterns — formats it can
recognise with high confidence, because a false positive blocks someone's push. Gitleaks matches those
*plus* `generic-api-key`, which fires on any high-entropy value bound to a secret-shaped name. Demo B was
rebuilt around that gap: a token in no vendor's format pushes cleanly and Gitleaks still catches it
(verified `RuleID: generic-api-key`, entropy 4.66, before I relied on it).

Nothing ended up disabled or bypassed. The demo is better for having been blocked — it now demonstrates
that I know where two scanners' coverage differs, rather than that I can plant a string and watch a light
go red.

If I keep one thing from this build, it's the instinct I had to unlearn. My first move was to switch the
blocking control off — and the *right* move turned out to be to understand precisely what it did and
didn't cover, then work inside that. **When a security control blocks you, "how do I disable this" and
"what exactly is this checking" lead to very different places.** The second question got me a better
demo, and the repository is no weaker than before I started.

<details>
<summary><b>▸ Four more, kept because they were real</b> — a <code>.dockerignore</code> entry that made the pipeline unbuildable, two occasions where I had a scanner's scope wrong, hardening that silently killed a container, and a red gate with nothing in the repo to fix</summary>

**1. A `.dockerignore` entry that made the whole pipeline unbuildable.**

`.dockerignore` excluded `*.test.js`, which seemed obviously correct — the runtime image has no business
carrying test code. But `.dockerignore` filters the *build context*, and the context is shared by every
stage. The `test` stage does `COPY . .` then `RUN npm test`, so excluding the spec files left Jest with
nothing to run, and `jest` exits **1** on `No tests found`. Every commit would have failed at
`docker build --target test`, and with branch protection on, nothing could ever have merged.

What made it hard to see is that the failure looks like a *test* problem, not a *packaging* problem — the
error message talks about tests, so that's where you look. I diagnosed it by reproducing the build context
by hand (copying only the files `.dockerignore` permits into an empty directory and running `npm test`),
which turned an opaque build failure into an obvious one in about thirty seconds.

The fix was to delete the exclusion and rely on the runtime stage's explicit `COPY server.js` instead.
The real lesson is about the shape of the rule: a **deny-list** filters the context for all stages at
once, while an **allow-list `COPY`** filters per stage. When those two mechanisms disagree, the deny-list
wins silently and breaks the stage you weren't thinking about.

**2. "Gitleaks scans your full history" turned out to be false where it mattered.**

The README originally claimed `secret-scan` scanned the entire git history, and pointed at `fetch-depth: 0`
as the line that made it true. Reading `gitleaks-action`'s source, that's only right for `schedule` and
`workflow_dispatch` events — on `push` and `pull_request` it passes
`--log-opts=--no-merges --first-parent <base>^..<head>` and scans only that event's commits.

The uncomfortable part is that nothing would have failed. The demo PR still goes red (the secret *is* in
the PR's commits), `main` still goes green, and every screenshot still looks correct — while the actual
coverage claim was wrong. `fetch-depth: 0` is still necessary, just not for the reason given: resolving
`<base>^` needs the parent commit to exist locally.

I fixed both halves: corrected the claim, and added a nightly `schedule` trigger so full-history scanning
genuinely happens. That one line also re-runs Trivy against a freshly updated CVE database, which covers
the other thing that changes while your code doesn't.

**...and then the same assumption was wrong in the opposite direction.**

Having added the nightly full-history scan, I ran the local harness against a repo that had the demo
branches in it. A clean `main` went **red**. `gitleaks detect` does not scan the checked-out branch — it
scans **every ref in the repository** — so it walked `demo/leaked-secret` and found the key that is
deliberately planted there. Measured in a clone mimicking CI, with `main` checked out and the demo branch
present only as a remote-tracking ref: *4 commits scanned, 2 leaks*, on a `main` that has 3 commits and is
clean.

This one was genuinely disorienting, because the scanner was **not wrong**. The key really is in the
repository. But the run was red on a branch containing nothing wrong, pointing at a file not in the
working tree, and it contradicted the "`main` is green" evidence that putting the demos on separate
branches exists to create.

The fix is `--log-opts=HEAD`, in both `ci.yml` and `scripts/verify.sh`, so each scans the ancestry of the
ref it is actually on. A secret ever merged to `main` is still caught — it is an ancestor. The demo
branches are not, and they still fail their own PRs, which is their whole job.

Two lessons stuck. First: I had read this scanner's documentation carefully and *still* got its scope
wrong twice, in opposite directions — "what exactly does this tool look at?" deserves an experiment, not a
reading. Second, the harness had been **stricter than CI**, and a harness that fails on things CI would
pass is worse than none, because you learn to ignore it.

**3. Hardening that silently killed a container.**

Adding `cap_drop: ALL` to both Compose services read as an unambiguous improvement. For Redis it was fatal:
the official entrypoint drops privileges with `gosu`, `gosu` calls `setuid(2)`, and `setuid(2)` needs
`CAP_SETUID` — which had just been dropped. Redis exited, its healthcheck never passed, and `api` (waiting
on `service_healthy`) never started either, so the visible symptom was the *app* hanging rather than the
database failing.

Reading the image's `docker-entrypoint.sh` rather than guessing was what found it. The fix — `user: "999:1000"`
— is better than restoring the capabilities, because it means the process is never root at any point. The
general lesson: a hardening flag is a behavioural change, and "more restrictive" and "more secure" are only
the same thing if you verify the result still runs.

**4. A scanner failure with nothing in the repository to fix.**

The image scan went red on a clean `main`: four fixable HIGH CVEs, while `npm audit` was green and the
Trivy filesystem scan reported `package-lock.json: 0`. Two scanners looking at the same project
disagreeing that sharply is the signal — they weren't contradicting each other, they were looking at
different things. `find / -name brace-expansion` inside the running container settled it: the findings were
in **npm's own bundled dependencies**, shipped inside the official Node base image, reachable by nothing in
this application.

That framing made the fix obvious: a container that runs `node server.js` doesn't need npm at all, so it
gets deleted. Then two more surfaced underneath — `libcrypto3`/`libssl3`, fixed in a newer Alpine package
than the pinned digest carries — which is the cost of digest pinning stated plainly: pinning for
reproducibility also pins the vulnerabilities, so it has to be paired with `apk upgrade` at build time.

The habit I'd keep is the ordering. A red gate with no obvious cause is *not* a reason to reach for
`.trivyignore`; it's a reason to find out which layer the finding lives in. Both of these turned out to be
genuinely fixable, and `.trivyignore` is still empty.

A footnote that turned out to matter: re-scanning the base image months later, the four npm findings had
**gone**, while the `libcrypto3`/`libssl3` pair remained and is still what `apk upgrade` is there to fix
(CVE-2026-14456, `3.5.7-r0` → `3.5.8-r0`; the scan goes from `Total: 2 (HIGH: 2)` to `Total: 0`). Advisory
databases move under you, so a measured number in a comment is a *dated observation*, not a constant. The
figures above are dated rather than deleted for exactly that reason.

</details>

---

## Submission checklist

| Spec requirement | Status | Where |
|---|---|---|
| Starter repository forked | ✅ | this repo |
| `Dockerfile` included, runs as non-root | ✅ | [`Dockerfile`](Dockerfile) — `USER node`, asserted in CI |
| `.dockerignore` included | ✅ | [`.dockerignore`](.dockerignore) |
| Workflow runs tests and builds the image | ✅ | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Security scanner integrated | ✅ | Trivy + Gitleaks + CodeQL + Dependabot |
| Scanner demonstrably **caught** a planted flaw | ✅ | [PR #1](https://github.com/Jeck-bot/devsecops-exam-starter/pull/1) and [PR #3](https://github.com/Jeck-bot/devsecops-exam-starter/pull/3), both red, both open |
| README explains architecture and demonstrates a catch | ✅ | this file |
| *Bonus:* Docker Compose | ✅ | [`docker-compose.yml`](docker-compose.yml) |
| *Bonus:* multi-stage build | ✅ | [`Dockerfile`](Dockerfile) |
| *Bonus:* branch protection | ✅ | seven required checks, `enforce_admins` on |

Everything above is verified against a real build rather than asserted: `bash scripts/verify.sh` runs
14/14 locally, and the same fourteen gates run in CI on every push.

### Detection → remediation, demonstrated end to end

Worth calling out because it happened on this repository rather than being described in the abstract:
Trivy and `npm audit` both reported `qs` (reached via `express`), Dependabot opened
[PR #2](https://github.com/Jeck-bot/devsecops-exam-starter/pull/2) to bump it, CI verified the bump,
and it merged with `main` still green.

Accurately: that cleared **one of three** moderate advisories — two remain, both below the
HIGH threshold the gate blocks on. A scanner that reports and a bot that fixes are two different
capabilities, and only having the first is how a repository accumulates findings nobody acts on.
