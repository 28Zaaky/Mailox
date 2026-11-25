# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub Security Advisories:
open <https://github.com/28Zaaky/Mailox/security/advisories/new>
(repository **Security** tab, then **Report a vulnerability**).

Do not open a public issue, pull request or discussion for a vulnerability.

Include what you can of:

- affected version or commit, edition (`selfhosted` / `saas`) and install path
  (Docker or manual);
- the component (API endpoint, worker engine, frontend, scripts) and the impact;
- reproduction steps or a proof of concept against your own instance;
- any suggested fix.

## Disclosure

We follow coordinated disclosure with a **90-day** window:

- acknowledgement within 7 days;
- assessment and, if confirmed, a fix and an advisory as soon as practical;
- public disclosure when the fix is released, or after 90 days from the report,
  whichever comes first. We can agree on a different date together if a fix needs
  more time.

Reporters are credited in the advisory unless they prefer otherwise.

## Scope

In scope: the code in this repository (`backend/`, `frontend/`, Docker files, install
and start scripts), for example authentication and session bypass (including the
loopback-only local session), tenant isolation, SSRF or egress-guard bypass in the scan
engines, injection, secrets exposure, insecure defaults in the shipped configuration.

Out of scope:

- findings that require the operator to deliberately weaken the documented setup
  (binding the API or Vite to `0.0.0.0` without a reverse proxy, `DEBUG=true` in
  production, enabling active modules against third parties);
- scanning or testing infrastructure you do not own, including the hosted SaaS
  edition, without written permission from Khaøtic Security;
- denial of service through resource exhaustion of your own instance;
- reports from automated scanners without a demonstrated impact.

## Testing rules

Test against your own local instance. Do not run scans, probes or credential attempts
against third-party domains while researching MAILOX.
