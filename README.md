# Macky Merch API — Secure Delivery Pipeline

![CI](https://github.com/Jeck-bot/devsecops-exam-starter/actions/workflows/ci.yml/badge.svg)

LSCS DevSecOps Engineering Challenge — 41st LSCS, Term 1.

A baseline Express API (`/health`, one Jest test) wrapped in a containerised, automated, security-gated
delivery pipeline. The application code is unchanged; **the pipeline is the deliverable.**

---

## Pipeline at a glance

```
 push / pull_request -> main          nightly schedule (02:00 UTC)
            │                                    │
  ┌─────────┼──────────────┬───────────┐         │
  ▼         ▼              ▼           ▼         │
 test    secret-scan  dependency-scan codeql  ◄──┘   parallel — fail fast
 (22,24)  Gitleaks    Trivy fs +      JS static
                      npm audit       analysis
  │
  └────────────► docker
                 ├─ build --target test   (jest inside Alpine)
                 ├─ build runtime
                 ├─ assert non-root       ← enforces the spec, every commit
                 ├─ assert no devDeps     ← enforces the multi-stage split
                 ├─ smoke-test /health
                 └─ Trivy image scan
```

Five jobs. Four start immediately; `docker` alone waits — on `test`, so build minutes aren't spent on code
that's already broken. The scanners deliberately do **not** gate each other, so one red run reports every
distinct problem at once rather than revealing them one push at a time.

---

## Setup instructions

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

Twelve checks: host tests → test-stage build → runtime build → non-root assertion → dev-dependency
isolation → `/health` smoke test → prompt shutdown → the Compose stack with DNS resolution → a
full-history Gitleaks scan → a Trivy dependency gate → the production `npm audit` gate → a Trivy
scan of the shipped image. Exits 0 only if all pass.

That list is deliberately identical to the set of gates in `ci.yml`, and it did not start out that
way. The last two were CI-only for a while, which meant the first time they ever ran was the push
that would have turned `main` red. A harness that covers *most* of the pipeline tells you the least
on exactly the days you need it most.

---

## Architectural explanation

### Why `node:24-alpine`?

**Why not `node:latest`** — it's an unpinned moving target. The same `docker build` produces different
images on different days, and it will silently carry you across a major version bump the moment one is
released. Reproducible builds require a pinned tag.

**Why not `node:18-alpine`** (the example in the spec)? Because it is end-of-life:

| Release line | Status | End of life |
|---|---|---|
| Node 18 (Hydrogen) | **EOL** | 2025-04-30 |
| Node 20 (Iron) | **EOL** | 2026-04-30 |
| Node 22 (Jod) | Maintenance LTS | 2027-04-30 |
| **Node 24 (Krypton)** | **Active LTS** | 2028-04-30 |

*(Dates from the official `nodejs/Release` schedule. Node 24 enters Maintenance on 2026-10-20, when Node
26 becomes Active LTS — so this table has a known expiry, which is the point of writing the dates down
rather than the word "current".)*

An EOL runtime receives **no security patches at all**. Pinning to Node 18 today means every future CVE
in the Node runtime is permanently unfixed — which would quietly undermine the entire point of adding a
vulnerability scanner downstream. Node 24 is the current Active LTS line and matches the local development
runtime (v24.21.0), so "works on my machine" and "works in the image" mean the same thing.

**Why Alpine over Debian-based tags?** Measured, not estimated:

| Base image | Compressed (pull) | On disk |
|---|---|---|
| `node:24` (Debian) | 410 MB | ~1.1 GB |
| `node:24-alpine` | **59 MB** | **235 MB** |

Roughly a 4.7× reduction. Size is the visible benefit, but the security benefit is the real one: Alpine
ships a fraction of the OS packages, and **a package that isn't installed cannot have a CVE.** Smaller
base = smaller attack surface = a shorter Trivy report that people actually read.

> Worth stating explicitly because the two numbers get conflated constantly: Docker Hub reports
> *compressed* size, `docker images` reports *uncompressed on-disk* size. They differ by about 4×, so
> quoting one against the other makes a base image look far better or worse than it is.

**The honest trade-off:** Alpine uses musl libc rather than glibc. Native C++ addons occasionally
misbehave under musl, and there have been reported DNS-resolution edge cases. That risk is acceptable
here because the dependency tree is pure JavaScript (Express and its transitive deps compile nothing) —
and the `test` build stage runs Jest *inside* Alpine, so any musl incompatibility fails the build rather
than reaching production.

**Why the digest, not just the tag?**

```dockerfile
FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS deps
```

The argument against `node:latest` above is an argument about mutability — and it applies to
`node:24-alpine` too, just more slowly. That tag is re-pushed on every patch release (it moved on
2026-09-09), so `FROM node:24-alpine` is still "whatever that name points at today". A tag is a pointer;
only a digest is an identity. Pinning the digest is what makes the build actually reproducible, and
Dependabot's `docker` ecosystem bumps it weekly so pinning doesn't mean going stale.

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

The layer breakdown of that 250 MB is the more interesting number:

| Layer | Size |
|---|---|
| `node:24-alpine` base | 235 MB |
| `apk upgrade` + tini | 6.6 MB |
| production `node_modules` (67 packages) | 4.6 MB |
| `rm` of the bundled package managers | 29 kB |
| `server.js` + `package.json` | 25 kB |

**The application is 0.01% of its own image.** That ratio is worth internalising: the base image *is* the
attack surface, which is why the choice between Alpine and Debian — and what gets stripped out of the base
below — matters more than anything done in the application layer above it.

The pipeline **asserts** the split rather than trusting it: the `docker` job runs `ls /app/node_modules`
inside the built image and fails if `jest` is present. Without that check, dropping `--omit=dev` from the
`deps` stage would still build, still serve traffic, and still pass every other test — it would just
quietly ship 250 extra packages.

### Why the runtime stage patches and strips its own base image

Two lines in the runtime stage exist because **the image scan failed on a clean `main`** — no vulnerable
application dependency, `npm audit` green, the Trivy filesystem scan reporting `package-lock.json: 0`, and
the image gate still red. Both findings came from the base image, and neither was fixable from anything in
this repository.

**1. `rm -rf` the bundled package managers.** Trivy reported four fixable HIGH findings — `brace-expansion`
(CVE-2026-14257, CVE-2026-69152), `ip-address` (CVE-2026-69192, an SSRF), and `tar` (CVE-2026-73566). None
appear in `package-lock.json`. All four live in **npm's own vendored dependency tree** at
`/usr/local/lib/node_modules/npm/node_modules/`, shipped inside the official Node image.

A container whose only job is `node server.js` needs no package manager at runtime, so npm, npx, yarn and
corepack are deleted. That removes the entire `node-pkg` class of findings legitimately rather than by
suppression — and it removes a ready-made install tool from an attacker who gains code execution. It is
the same argument as Alpine-over-Debian, one level down: *the most reliable way not to have a
vulnerability is not to have the package.*

> Worth being precise about what this does **not** do: the image doesn't get 18 MB smaller. Deleting in a
> later layer cannot reclaim bytes from an earlier one — `rm` writes a whiteout, and the data stays in the
> base layer. It's the same append-only property that makes `.dockerignore` necessary, seen from the other
> side. The files are gone from the final filesystem (so Trivy no longer finds them) but not from the
> image's history.

**2. `apk upgrade --no-cache`, which is where digest pinning bites back.** With npm gone, two HIGH findings
remained: `libcrypto3` and `libssl3` at `3.5.7-r0`, affected by CVE-2026-14456, fixed upstream in
`3.5.8-r0`.

This is the direct cost of the digest pin argued for above. Pinning a digest freezes the OS packages at
whatever state that digest was published in, so **a pinned image is also a pinned-and-vulnerable one** the
moment a CVE lands upstream. Official images trail Alpine's security updates by days or weeks, and there
is no version of "wait for a new base image" that is faster than patching at build time.

The honest trade-off: `apk` is a moving target, so this reduces byte-for-byte reproducibility of the final
image. That's the correct trade. The digest still pins the base layer, the Node version and the filesystem
layout; this line adds "…and current security patches on top". Reproducibility exists to make builds
trustworthy, not to preserve known-vulnerable libraries.

**Result — the image gate now passes on merit:**

```
macky-merch-api:local (alpine 3.24.1)   alpine   0 vulnerabilities
```

Nothing is in `.trivyignore`. Both problems were fixed, not silenced.

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

The pipeline **asserts** this rather than trusting it:

```yaml
- name: Assert the container does not run as root
  run: |
    uid=$(docker run --rm --entrypoint id "${IMAGE_NAME}:${GITHUB_SHA}" -u)
    if [ "$uid" = "0" ]; then exit 1; fi
```

**tini** solves a separate problem. PID 1 is special: the kernel ignores signals that have no explicit
handler installed. Node doesn't install a SIGTERM handler, so as PID 1 it ignores `docker stop` entirely —
Docker waits the full 10-second grace period, then SIGKILLs, which makes every deploy slow. tini sits at
PID 1, forwards signals, and reaps zombies, for about 1MB. `scripts/verify.sh` checks the container stops
in under 5 seconds.

**Stated precisely:** this buys *prompt, signal-correct* shutdown — **not** connection draining. Draining
in-flight requests requires `server.close()` inside `server.js`, and the starter repo forbids modifying
it. Fast teardown is the part achievable from the container layer, and it's the part that makes
`docker stop` honest; the rest is noted in [API security](#api-security-what-this-pipeline-does-not-cover)
below.

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

There's also a correctness angle on Windows: the host `node_modules` contains Windows-native binaries
that cannot execute on Alpine. Excluding it forces `npm ci` to build a correct Linux tree.

**What `.dockerignore` deliberately does *not* exclude — and why.** It's tempting to add `*.test.js`,
since the runtime image obviously has no business carrying test code. That is a trap. `.dockerignore`
filters the **build context**, which is shared by *every* stage — so excluding the spec files also hides
them from the `test` stage, where Jest then finds nothing to run and exits 1 on `No tests found`. The
result is a Dockerfile that fails to build on every single commit.

Test code is kept out of the shipped image by a stronger mechanism instead: the runtime stage copies an
explicit **allow-list**, not everything-minus-a-deny-list.

```dockerfile
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node server.js ./
```

Nothing leaks in by accident, because nothing gets in unless it's named. One build context, three stages,
different needs — and the deny-list is the wrong tool for the only stage that matters.

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
| `docker` | builds both stages, asserts non-root and dep isolation, smoke-tests `/health`, scans the image | the artefact is invalid or vulnerable |

Deliberate choices worth calling out:

- **`permissions: contents: read` at the top.** The `GITHUB_TOKEN` starts read-only; only
  `dependency-scan` and `codeql` opt into `security-events: write` for SARIF. The `docker` job asks for
  nothing extra, because it uploads no SARIF — an unused grant is just latent blast radius.
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

Three scanners, chosen to cover different axes rather than duplicate each other.

| Threat | Tool | Job | Blocking |
|---|---|---|---|
| Vulnerable npm package | Trivy `fs` + `npm audit` | `dependency-scan` | ✅ |
| CVE in base-image OS packages | Trivy `image` | `docker` | ✅ |
| CVE in packages bundled *inside* the base image | Trivy `image` | `docker` | ✅ |
| Secret in the working tree | Trivy `secret` | `dependency-scan` | report |
| Secret in the commits being pushed | Gitleaks | `secret-scan` | ✅ |
| Secret **anywhere in git history** | Gitleaks (nightly) | `secret-scan` | ✅ |
| Uncatalogued dataflow vulnerability | CodeQL | `codeql` | ✅ |
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

#### Why the nightly run scans `main` and not every ref

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

Two things change while your source code doesn't:

1. **Newly disclosed CVEs.** Trivy's database updates continuously. A dependency that was clean at merge
   time can be CRITICAL a week later with no commit in between. Push-triggered scanning can only ever tell
   you about code you just wrote.
2. **Git history.** As above — the scheduled run is the only one that sees all of `main`'s history,
   rather than just the commits in the event that triggered it.

### A note on `github-pat`

An earlier revision passed `github-pat: ${{ secrets.GITHUB_TOKEN }}` to the Trivy steps, believing it
authenticated the vulnerability-DB pull from ghcr.io and avoided `TOOMANYREQUESTS`. It does not. Reading
`trivy-action`'s `entrypoint.sh`, `INPUT_GITHUB_PAT` is only read inside `if [ "$TRIVY_FORMAT" = "github" ]`
— it authenticates an *upload* to the Dependency Snapshot API, nothing else. The input was removed.

What actually mitigates the rate limit is already in place: the action restores the DB through
`actions/cache` under a date-based key, so at most the first run of each day downloads anything, and the
later passes reuse the binary via `skip-setup-trivy`. Recording this because a plausible-sounding, wrong
justification in a config comment is worse than no comment — it stops anyone from checking.

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

PR: **TODO:** PR link

`lodash@4.17.20`, pinned exactly, added to `dependencies`:

| | |
|---|---|
| CVE | **CVE-2021-23337** |
| Flaw | Command injection via `_.template` |
| Severity | **HIGH** (CVSS 7.2) |
| Fixed in | `4.17.21` |

The "fixed in" row is load-bearing. Because the gate runs with `ignore-unfixed: true`, a CVE with no
available patch would be filtered out and the demo would silently pass. 4.17.20 has a fix exactly one
patch release away, so it survives the filter. **A vulnerable package is not sufficient — it has to be a
fixable one**, which is a subtlety worth internalising before trusting any scanner's output.

Verified against the live advisory database rather than assumed: `npm audit --audit-level=high` on this
tree exits **1**, reporting `lodash <=4.17.23  Severity: high` across several advisories with a fix
available at `4.18.1`.

It also went into `dependencies` rather than `devDependencies`, so it survives the `--omit=dev` gate,
reaches the production image, and gets caught a second time by the image scan.

**Result — two independent jobs fail:**

![Vulnerable dependency PR](docs/img/pr-vuln-dependency.png)

```
TODO: paste the Trivy table rows showing CVE-2021-23337
```

![Trivy CVE detail](docs/img/trivy-cve-detail.png)

One planted flaw, caught by two layers that share no code path.

### Demo B — leaked secret (`demo/leaked-secret`)

PR: **TODO:** PR link

A fake AWS key pair committed to `config/aws-credentials.sample.env`.

**Two traps worth documenting, because both silently produce a false pass:**

1. **Not `.env`** — the starter's `.gitignore` excludes it, so the file would never be committed and the
   scanner would have nothing to find.
2. **Not `AKIAIOSFODNN7EXAMPLE`** — AWS's canonical documentation key. Gitleaks allowlists it *explicitly*:
   the `aws-access-token` rule carries `allowlists.regexes = ['''.+EXAMPLE$''']`, precisely because that
   string appears in every tutorial. Using it means the scan passes and you conclude the pipeline works
   when it does not.

The planted key was checked against the scanner's *actual current rule* rather than a remembered version
of it:

| Check | Value |
|---|---|
| Rule regex (gitleaks 8.24.3 — the version the action pins) | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16})\b` |
| Rule regex (current gitleaks) | `...[A-Z2-7]{16}` — **base32**, narrower |
| Shannon entropy | 4.22 (rule requires > 3) |
| Path allowlisted? | No |

Upstream narrowed that trailing character class from `[A-Z0-9]` to base32 `[A-Z2-7]`. The planted key
contains only `2`, `3`, `4`, `7`, so it satisfies both and survives the change — but a regenerated key
containing a `0`, `1`, `8`, or `9` would match the old rule, fail the current one, and produce a silent
green build. Same failure mode as the documentation-key trap, one layer deeper.

**Result:**

![Leaked secret PR](docs/img/pr-leaked-secret.png)

```
TODO: paste the Gitleaks finding (it redacts the value)
```

![Gitleaks detail](docs/img/gitleaks-detail.png)

### For contrast — `main` stays green

![Green pipeline on main](docs/img/main-green.png)

### A note on permanence

That fake key is now in the fork's history **permanently**. Deleting the file in a later commit does not
remove it — `git log -p` still shows it. That is exactly why `secret-scan` checks out with
`fetch-depth: 0`, and why the nightly full-history scan exists alongside the per-push one.

It is also the reason the nightly scan is scoped to `main`'s ancestry rather than every ref
([above](#why-the-nightly-run-scans-main-and-not-every-ref)). The key on `demo/leaked-secret` is
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

`main` requires all six status checks to pass before merging, with **"do not allow bypassing"**
enabled — without that, repository admins silently bypass the rule and it protects nobody.

| Required check | Job |
|---|---|
| `Unit tests (Node 22)` | `test` (matrix) |
| `Unit tests (Node 24)` | `test` (matrix) |
| `Secret scan (Gitleaks)` | `secret-scan` |
| `Dependency scan (Trivy + npm audit)` | `dependency-scan` |
| `Static analysis (CodeQL)` | `codeql` |
| `Docker build & image scan` | `docker` |

> Those are the job **`name:` values**, not the job IDs. GitHub registers a status check under the
> display name when one is set, so requiring `secret-scan` or `test (22)` silently protects nothing —
> the context never matches, and the rule sits there looking configured. A matrix job also registers
> one check per combination, which is why `test` appears twice.

![Branch protection rule](docs/img/branch-protection.png)
![Merge blocked on a failing PR](docs/img/merge-blocked.png)

---

## Challenges faced

> **TODO — rewrite this section in your own words before submitting.** It is graded on comprehension, and
> the writing should be yours. The four below are the real problems from this build, kept as raw
> material; cut them to the one or two you can speak to confidently in an interview.

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

---

## Submission checklist

| Spec requirement | Status | Where |
|---|---|---|
| Starter repository forked | ✅ | this repo |
| `Dockerfile` included, runs as non-root | ✅ | [`Dockerfile`](Dockerfile) — `USER node`, asserted in CI |
| `.dockerignore` included | ✅ | [`.dockerignore`](.dockerignore) |
| Workflow runs tests and builds the image | ✅ | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Security scanner integrated | ✅ | Trivy + Gitleaks + CodeQL + Dependabot |
| README explains architecture and demonstrates a catch | ✅ | this file |
| *Bonus:* Docker Compose | ✅ | [`docker-compose.yml`](docker-compose.yml) |
| *Bonus:* multi-stage build | ✅ | [`Dockerfile`](Dockerfile) |
| *Bonus:* branch protection | ✅ | screenshot above |

**Before submitting** — everything measurable is already filled in and verified against a real build
(`bash scripts/verify.sh` → 12/12, image gate clean). What's left needs a live repo:

- [ ] Two PR links (Demo A, Demo B)
- [ ] Two log excerpts — the Trivy CVE-2021-23337 rows, and the Gitleaks finding
- [ ] Seven screenshots into `docs/img/`
- [ ] Rewrite *Challenges faced* in your own voice

`grep -n TODO README.md` finds all of them.
