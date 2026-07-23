# Tool Authorization Protocol (TAP)

Credential isolation, approval gating, and connector routing for AI agents.

This repository contains the code that is most useful for:

- auditing request routing and connector behavior
- debugging failed requests
- understanding approval flows
- improving connector-side request shaping
- contributing fixes to the core TAP experience

> [!WARNING]
> **Self-hosting means you own the security of your credentials and signing keys.**
> TAP keeps secrets out of your agents, but running it yourself puts the host
> hardening, key isolation, and correct policy-engine operation on you. It's a path
> for teams that are well versed in security. For everyone else the hosted version is
> strongly recommended: credentials sit in a hardware enclave we can't read into, with
> no ops to run. Start free at [tap.human.tech](https://tap.human.tech).

## Start Here

- `crates/tap-proxy/src/routing.rs` — how TAP resolves connector target shapes
- `crates/tap-proxy/src/placeholder.rs` — credential substitution and position validation
- `crates/tap-proxy/src/policy.rs` — approval policy enforcement
- `docs/` — full documentation including self-hosting guide

## Included

- core proxy and storage crates
- Telegram and Matrix approval bots
- remote MCP server (`tap-mcp`)
- CLI
- docs (self-hosting, API reference, credential setup)

## Not Included

- enclave deployment glue (CCE policy generation, release-policy automation, ARM templates, env config)
- production workflows and secret bootstrapping
- managed hosting operations glue
- the hosted dashboard UI source (a placeholder is shipped so the proxy compiles)

The enclave **key-management source is included** (`key_provider_enclave.rs`,
`kms_azure.rs`, `skr.rs`) — it's the custody model documented at
[docs.tap.human.tech/security](https://docs.tap.human.tech/security), and each
hosted release's enclave measurement is published in [`measurements/`](measurements/).
Hosted deployment and operational infrastructure are maintained separately from this repository.

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## License

[Apache-2.0](LICENSE): free to use, read, modify, and self-host. This repo is the
open-source TAP runtime (`tap-core`, `tap-proxy`, `tap-bot`, `tap-cli`, `tap-mcp`). The
hosted dashboard and managed-service deployment glue are proprietary and live in
a separate private repo.

## Contributing

See `CONTRIBUTING.md`.

## Testing

```bash
# Needs Postgres (default postgres://tap:tap@localhost:5434/tap, override with
# POSTGRES_DATABASE_URL). Isolated suites parallelize; env-mutating unit tests stay serial.
cargo test -p tap-core
cargo test -p tap-proxy --test integration --test e2e
cargo test -p tap-proxy -p tap-bot -p tap-cli --lib --bins -- --test-threads=1
```
