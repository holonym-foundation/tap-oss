//! One-time DEK re-wrap migration tool (internal-docs#1187, KEK/DEK envelope).
//!
//! Re-wraps the existing per-service master **DEK** under the Azure **KEK** so the
//! `azure-skr` backend can unwrap the *same* DEK on boot — preserving per-service key
//! continuity (and rollback) across Evervault → Azure.
//!
//! ## Custody model — the plaintext DEK NEVER leaves the enclave
//! The DEK only exists in plaintext inside the trusted enclave; no human (and no Azure
//! component) ever holds it. So this tool does the re-wrap **inside the source (Evervault)
//! enclave context**: it loads the DEK via the in-enclave KMS path (the same
//! `key_provider::load_encryption_key()` the proxy uses — Evervault `/decrypt`), wraps it
//! with the Azure KEK's **public** key, and prints only the **wrapped ciphertext**.
//!
//! Both things that cross the trust boundary are non-secret:
//!   - **in:** the Azure KEK *public* key (a JWK fetched from Key Vault — public keys are
//!     freely readable, no attestation needed);
//!   - **out:** the RSA-OAEP-wrapped DEK ciphertext (only the attested Azure image can ever
//!     release the KEK private key to unwrap it).
//!
//! The human shuttles those two artifacts; the secret stays in the TEE.
//!
//! Build with the enclave feature:  `cargo build --release --features enclave --bin rewrap_dek`
//!
//! ## Where to run it
//! This must execute where the Evervault `/decrypt` endpoint + the enclave Postgres are
//! reachable — i.e. inside the source enclave's trust context, with the same env the proxy
//! uses (`EVERVAULT_ENDPOINT`, `POSTGRES_DATABASE_URL`, the CA cert). Two viable mechanisms
//! (pick one in the attended deploy — flagged for review):
//!   (a) a one-shot maintenance run of this binary in that context, or
//!   (b) a startup migration hook in the proxy itself (set an env var → it wraps its
//!       in-memory DEK and writes the ciphertext to a config row). (a) is implemented here;
//!       (b) is `key_provider::run_startup_rewrap()` — the zero-exec path for a *sealed*
//!       Evervault enclave (gated on `TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK`).
//!
//! ## Operator runbook
//! 1. Fetch the KEK **public** key:  `GET {vault}/keys/{kek}?api-version=7.4` → save the
//!    `key` JWK to `kek-public.jwk` (this is public; safe to handle).
//! 2. In the source enclave context:  `rewrap_dek --kek-public-jwk kek-public.jwk`
//!    → prints the base64 wrapped DEK. (It reads the live DEK in-enclave; nothing secret
//!    is printed or written to disk.)
//! 3. Store that base64 as the azure-skr instance's `encryption_key_ciphertext` config row.
//! 4. Boot azure-skr (`TAP_SKR_REQUIRE_MIGRATED_DEK=1`); it releases the KEK via the sidecar
//!    and unwraps *this* DEK. Verify it can read an existing credential (DEK continuity).

#[cfg(feature = "enclave")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let mut kek_jwk_path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--kek-public-jwk" => kek_jwk_path = args.next(),
            "-h" | "--help" => {
                eprintln!(
                    "usage: rewrap_dek --kek-public-jwk <path>   (run inside the source enclave)"
                );
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    let Some(kek_jwk_path) = kek_jwk_path else {
        eprintln!("error: --kek-public-jwk <path> is required");
        return std::process::ExitCode::FAILURE;
    };

    // Safety: this must run in the SOURCE (Evervault) enclave so load_encryption_key()
    // yields the DEK to migrate. Running it with the azure-skr backend would wrap the Azure
    // DEK with the Azure KEK — circular and wrong.
    if std::env::var("TAP_KMS_BACKEND").as_deref() == Ok("azure-skr") {
        eprintln!(
            "error: TAP_KMS_BACKEND=azure-skr — run this inside the SOURCE (Evervault) enclave, \
             not the Azure target"
        );
        return std::process::ExitCode::FAILURE;
    }

    // Read the KEK PUBLIC key (non-secret). Accept a bare JWK or a Key Vault GET response
    // ({"key": <jwk>}).
    let jwk_text = match std::fs::read_to_string(&kek_jwk_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read KEK JWK '{kek_jwk_path}': {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let jwk: serde_json::Value = match serde_json::from_str(&jwk_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: KEK JWK is not valid JSON: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let jwk = jwk.get("key").cloned().unwrap_or(jwk);
    // Custody: the KEK private half must never leave the enclave/HSM. Refuse a JWK that
    // carries any private component (M1) so an operator can't accidentally export it here.
    if let Err(e) = tap_proxy::skr::ensure_public_only_jwk(&jwk) {
        eprintln!("error: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let kek_pub = match tap_proxy::skr::parse_rsa_public_jwk(&jwk) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Load the DEK via the in-enclave KMS (Evervault). The plaintext DEK lives only here,
    // in the same trusted context the proxy itself uses — it is never printed or persisted.
    let dek = match tap_proxy::key_provider::load_encryption_key().await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: failed to load the source DEK via the enclave KMS: {e}");
            eprintln!("       (run this inside the source enclave, with EVERVAULT_ENDPOINT + POSTGRES_DATABASE_URL set)");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Non-secret continuity check: the operator can compare this fingerprint before and
    // after the migration (and against the azure-skr boot log) to confirm the SAME DEK was
    // re-wrapped, without ever exposing key material (M3).
    eprintln!(
        "DEK fingerprint (non-secret): {}",
        tap_proxy::skr::dek_fingerprint(&dek)
    );

    match tap_proxy::skr::wrap_dek(&kek_pub, &dek) {
        Ok(b64) => {
            println!("{b64}");
            eprintln!(
                "ok: store this base64 as the azure-skr instance's wrapped-DEK config row \
                 (see deploy/azure/tap-skr-keymgmt.md for the backend-namespaced key name)"
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "enclave"))]
fn main() {
    eprintln!(
        "rewrap_dek requires the `enclave` feature: cargo run --features enclave --bin rewrap_dek"
    );
    std::process::exit(2);
}
