use std::{io::Error, net::SocketAddr};

use clap::Parser;
use tokio_stream::StreamExt;
use tracing::info;

const SERVICE_NAME: &str = "_genmeta._quic.local";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "192.168.1.7:7000")]
    local_addr: SocketAddr,
    #[arg(long, default_value = "test2.genmeta.net")]
    domain: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mut mdns = gmdns::mdns::ArcMdns::new(
        args.domain.clone(),
        SERVICE_NAME.to_string(),
        [args.local_addr].to_vec(),
    );

    while let Some(ret) = mdns.discover().next().await {
        if ret.0.is_empty() {
            continue;
        }
        info!("discovery response: {:?}", ret);
    }
    Ok(())
}
