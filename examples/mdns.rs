use std::{io::Error, net::SocketAddr};

use clap::Parser;
use tokio_stream::StreamExt;

const SERVICE_NAME: &str = "_genmeta.local";

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
    let mut mdns = gmdns::mdns::Mdns::new(SERVICE_NAME.to_string())?;
    mdns.add_host(
        "test.genmeta.net".to_string(),
        vec![
            "192.168.1.7:7000".parse().unwrap(),
            "192.168.1.13:7000".parse().unwrap(),
        ],
    );

    mdns.add_host(
        "test2.genmeta.net".to_string(),
        vec!["192.168.1.7:7001".parse().unwrap()],
    );

    let mut stream = mdns.discover();
    while let Some((addr, packet)) = stream.next().await {
        println!("Received packet from {}: {:?}", addr, packet);
    }
    Ok(())
}
