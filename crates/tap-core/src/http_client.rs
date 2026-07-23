use reqwest::{Client, ClientBuilder, Error, Proxy};

pub const EGRESS_PROXY_ENV: &str = "TAP_EGRESS_PROXY_URL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRoute {
    Direct,
    EgressProxy,
}

pub fn configure_client(
    builder: ClientBuilder,
    route: ClientRoute,
) -> Result<ClientBuilder, Error> {
    let builder = builder.no_proxy();

    match route {
        ClientRoute::Direct => Ok(builder),
        ClientRoute::EgressProxy => match std::env::var(EGRESS_PROXY_ENV) {
            Ok(proxy_url) if !proxy_url.trim().is_empty() => {
                Ok(builder.proxy(Proxy::all(proxy_url.trim())?))
            }
            _ => Ok(builder),
        },
    }
}

pub fn build_client(route: ClientRoute) -> Result<Client, Error> {
    configure_client(Client::builder(), route)?.build()
}
