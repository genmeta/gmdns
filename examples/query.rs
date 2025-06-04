use std::{io::Error, net::SocketAddr};

use clap::Parser;

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
    let mdns = gmdns::mdns::Mdns::new(SERVICE_NAME)?;

    let ret = mdns
        .query("ljsy.test.genmeta.net".to_string())
        .await
        .unwrap();
    println!("{ret:?}\n");
    Ok(())
}
