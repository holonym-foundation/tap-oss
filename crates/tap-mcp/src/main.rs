use tap_mcp::{build_router, McpConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tap_mcp=info,tower_http=info".into()),
        )
        .json()
        .init();

    let config = McpConfig::from_env()?;
    let listen_addr = config.listen_addr();
    let public_url = config.public_base_url().clone();
    // Durable, revocable OAuth token state. It lives in the proxy's Postgres,
    // reached over the authenticated /internal/mcp endpoints — this process holds
    // no database credentials. `None` only in demo mode.
    let durable_tokens = config.token_client().is_some();
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    tracing::info!(
        %listen_addr,
        %public_url,
        durable_tokens,
        "starting TAP MCP server"
    );
    // `into_make_service_with_connect_info` surfaces the peer address so the
    // OAuth-endpoint per-IP throttle can key on it.
    axum::serve(
        listener,
        build_router(config).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
