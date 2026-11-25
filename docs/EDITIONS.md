# Editions

MAILOX has one code base and two editions, selected at startup with `MAILOX_EDITION`.

## `selfhosted`

The edition of this repository. Installed and run by you, on your machine.

- No domain-ownership verification: any domain typed in the UI can be scanned. You are
  responsible for being authorised to test it.
- Sign-in: optional no-login local session (`LOCAL_SESSION_ENABLED=true`, loopback
  peers only, manual install), or accounts mode with a first platform admin created by a
  loopback registration or `python -m app.cli create-admin`.
- The SaaS-only API routes (domain verification, access requests) are not mounted.

## `saas`

The hosted service operated by Khaøtic Security. Accounts are invite-only and a domain
must be proven with a DNS TXT record (`mailox-verify=...`) before it can be scanned;
scheduled and monitoring scans follow the same rule. Platform admins manage accounts,
quotas and module permissions, but do not see customers' assessments or findings.

The SaaS deployment, its marketing site and its operating procedures are not part of
this repository.

## Default

`MAILOX_EDITION` defaults to `saas` in `backend/app/core/config.py`. This is
deliberate: an instance that forgets the setting gets the restrictive edition, never
an open scanner without domain checks. Self-hosted installs set
`MAILOX_EDITION=selfhosted` explicitly; `backend/.env.selfhosted` and the
`start.sh` / `start.ps1` scripts do it.

Check what an instance runs with:

```bash
python -m app.cli edition
```
