# Security policy

This repository is coursework — a submission for the LSCS DevSecOps Engineering Challenge. It is not a
production service and has no users. The policy below is short on purpose, but it is real: a repository
that runs six security scanners and has nowhere to send a finding is only half a security posture.

## Before you report: the deliberately planted flaws

Two vulnerabilities in this repository are **intentional**, required by the exam brief, and already
documented. Please don't spend time reporting them.

| Branch | What's planted | Why |
|---|---|---|
| `demo/vulnerable-dependency` | `lodash@4.17.20` — CVE-2021-23337, HIGH | demonstrates the dependency gate failing a PR |
| `demo/leaked-secret` | a fake API token in `config/api-credentials.sample.env` | demonstrates the secret gate failing a PR |

**The credentials are fake.** They were generated for this demonstration, were never valid, are not
associated with any account or service, and grant access to nothing. Both branches have open,
permanently failing pull requests — the red checks are the deliverable. Neither is merged into `main`,
and branch protection prevents it.

Anything reported against `main`, however, is a genuine finding.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Jeck-bot/devsecops-exam-starter/security/advisories/new)
— that keeps the details out of public issues until there's a fix. If you'd rather not use GitHub, open a
regular issue saying only that you have something to report, and I'll follow up.

Please include the affected branch and commit, what an attacker could actually do, and the steps to
reproduce. A proof of concept is welcome; please don't test against anything that isn't this repository.

Expect a first response within a few days. This is a student project, so that's a best effort rather
than an SLA.

## What's in scope

In scope: the `Dockerfile` and the image it produces, `docker-compose.yml`, the GitHub Actions workflow
in `.github/workflows/ci.yml`, and `scripts/verify.sh`.

Out of scope, and deliberately so:

- **`server.js` and the test suite.** The exam brief forbids modifying the baseline application, so
  application-layer issues can be documented but not fixed here. The
  [API security](README.md#api-security-what-this-pipeline-does-not-cover) section of the README already
  records what this pipeline does *not* protect against — missing rate limiting, no auth, no helmet
  headers — because a pipeline that is green says nothing about whether the app behind it is safe.
- **The two demo branches**, as above.

## How this repository defends itself

Every push and pull request to `main` runs Gitleaks (secrets), Trivy (dependency and image CVEs),
`npm audit` (a second advisory database), CodeQL (static dataflow analysis), and — because the build is
privileged code too — hadolint and zizmor against the Dockerfile and the workflows themselves. A nightly
scheduled run re-scans `main`'s full history against an updated CVE database, because a dependency that
was clean at merge time can be critical a week later with no commit in between.

Each build also publishes a CycloneDX SBOM of the shipped image as an artefact. A scan tells you what was
vulnerable on the day it ran; an inventory tells you what is in the image when a CVE is disclosed later,
which is the question that matters during an incident.

OpenSSF Scorecard runs on `main` and nightly, grading this repository's supply-chain posture against
criteria nobody here chose. It reports rather than gates — several of its checks do not apply to a
coursework fork, and a blocking check that cannot be satisfied is worse than no check.

Dependabot has security updates enabled and opens remediation PRs; `.trivyignore` is committed but
empty, and every future entry must carry a CVE ID, a specific non-exploitability justification, a review
date, and an approver.

GitHub secret scanning **and push protection are enabled** and were left that way — including when push
protection blocked the demo above. That episode is written up in the README; the short version is that
the demo was rebuilt rather than the control switched off.
