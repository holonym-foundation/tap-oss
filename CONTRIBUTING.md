# Contributing

Thanks for helping improve TAP OSS.

## Best Contribution Targets

- connector request-shape bugs
- approval flow bugs
- sanitization bugs
- routing / sidecar bugs
- CLI and setup-skill improvements
- tests that lock in known-good connector behavior

## What This Repo Optimizes For

- code auditing
- debugging failed requests
- improving connector reliability
- making TAP setup skills more accurate and less hallucination-prone

## What Is Out Of Scope Here

- hosted deployment internals
- enclave deployment configuration
- dashboard/admin UI
- production secret bootstrapping

## Local Checks

```bash
cargo test --workspace -- --test-threads=1
```

## Contribution Style

- prefer concrete fixes over abstract connector templates
- include a regression test when you fix a connector-specific bug
- document the real request shape if a connector is unusual
- if a service uses a sidecar or relative target, make that obvious in the skill or code comments
