use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Dns(#[from] dns_parser::Error),
    #[error("{0}")]
    Timeout(#[from] tokio::time::Elapsed),
}
