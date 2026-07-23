use sqlx::postgres::{PgConnectOptions, PgConnection, PgSslMode};
use sqlx::Connection as _;
use sqlx::Executor as _;
use std::process::ExitCode;
use std::str::FromStr as _;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("AZURE_DB_PROBE_ERROR {}", sanitize(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let url = std::env::var("POSTGRES_DATABASE_URL")?;
    let ca_cert_path = std::env::var("TAP_POSTGRES_CA_CERT_PATH")
        .unwrap_or_else(|_| "/etc/ssl/certs/tap-supabase-ca.crt".to_string());
    let parsed = url::Url::parse(&url)?;
    let host = parsed.host_str().unwrap_or("<unknown>");
    let port = parsed.port_or_known_default().unwrap_or(5432);

    let opts = PgConnectOptions::from_str(&url)?
        .statement_cache_capacity(0)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(&ca_cert_path);

    let mut conn = PgConnection::connect_with(&opts).await?;

    // Use raw SQL through the simple-query path. Supabase's transaction pooler
    // is intentionally valid as the stored GitHub secret, but it breaks named
    // prepared statements. The runtime deploy rewrites that same secret to the
    // session pooler before injecting it into ACI.
    conn.execute("SELECT 1").await?;
    for i in 0..32 {
        conn.execute(format!("SELECT {i}::int4").as_str()).await?;
    }

    println!("AZURE_DB_PROBE_OK peer={host}:{port} ca={ca_cert_path}");
    Ok(())
}

fn sanitize(input: &str) -> String {
    let mut out = input.to_string();
    for scheme in ["postgres://", "postgresql://"] {
        let mut start = 0;
        while let Some(pos) = out[start..].find(scheme) {
            let url_start = start + pos;
            let userinfo_start = url_start + scheme.len();
            let Some(at_rel) = out[userinfo_start..].find('@') else {
                break;
            };
            let at = userinfo_start + at_rel;
            let end = out[userinfo_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|end| userinfo_start + end)
                .unwrap_or(out.len());
            if at < end {
                out.replace_range(userinfo_start..=at, "<redacted>@");
                start = url_start + scheme.len() + "<redacted>@".len();
            } else {
                start = userinfo_start;
            }
        }
    }
    out.chars().take(2048).collect()
}
