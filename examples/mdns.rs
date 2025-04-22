use std::{io::Error, net::SocketAddr, time::Duration};

use clap::Parser;
use tokio_stream::StreamExt;
use tracing::info;

const SERVICE_NAME: &str = "_genmeta._quic.local";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "1.12.74.4:20004")]
    bind: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let mut mdns =
        gmdns::mdns::ArcMDNS::new(SERVICE_NAME.to_string(), [args.bind.ip()].to_vec(), 6000);

    while let Some(packet) = mdns.discover().next().await {
        info!("{:?}", packet);
    }
    Ok(())
}
