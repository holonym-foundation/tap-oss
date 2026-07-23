# Security Policy

TAP holds credentials on behalf of its users — we treat every report against
this codebase as high priority.

## Reporting a vulnerability

Email **security@human.tech** with a description, reproduction steps, and the
impact you believe it has. Please do not open a public issue for anything you
believe is exploitable.

You can expect an acknowledgment within 2 business days. We'll keep you
updated as we triage, fix, and (where applicable) roll the fix out to managed
hosting, and we're happy to credit you in the fix's release notes.

## Scope

- The TAP proxy, CLI, bots, and core crates in this repository
- The managed hosting at `app.tap.human.tech` / `proxy.tap.human.tech`
  (please: no denial-of-service testing, no testing against other users'
  teams or credentials — use your own free team as the target)

## What we care about most

- Credential exfiltration paths (placeholder position validation bypasses,
  response sanitization gaps, approval-message leakage)
- Authentication/authorization flaws (agent key scoping, team isolation,
  approver/role boundaries, passkey flows)
- Anything that would let an agent act without the policy-required human
  approval

## Verifying the hosted deployment

Managed hosting runs in hardware-attested enclaves; each release's enclave
measurement is published in [`measurements/`](measurements/) and the custody
model is documented at
[docs.tap.human.tech/security](https://docs.tap.human.tech/security).
