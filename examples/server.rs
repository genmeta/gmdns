use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use bytes::Bytes;
use clap::Parser;
use gmdns::parser::{packet::be_packet, record::RData};
use redis::AsyncCommands;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, instrument, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Clone)]
pub struct Options {
    #[clap(short, long, default_value = "redis://127.0.0.1:6379")]
    pub redis: String,
    #[clap(short, long, default_value = "0.0.0.0:8090")]
    pub listen: SocketAddr,
    #[clap(short, long)]
    pub cert: Option<PathBuf>,
    #[clap(short, long)]
    pub key: Option<PathBuf>,
    #[clap(long, default_value = "logs/app.log")]
    pub log_dir: PathBuf,
    #[clap(long)]
    pub require_signature: bool,
    #[clap(long)]
    pub pub_key: Option<PathBuf>,
}

pub fn init_logging(options: &Options) {
    let file_appender = tracing_appender::rolling::daily(&options.log_dir, "app.log");
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_level(true)
        .with_ansi(false);

    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(fmt::layer().with_writer(std::io::stdout))
        .with(fmt_layer.with_writer(file_writer))
        .init();
}

#[derive(Clone)]
pub struct AppState {
    pub redis_pool: deadpool_redis::Pool,
    pub require_signature: bool,
    pub pub_key: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum AppError {
    MissingHostParam,
    InvalidDnsPacket,
    NoAnswersInPacket,
    RedisPoolError(String),
    RedisError(String),
    NotFound(String),
    SignatureRequired,
    InvalidSignature,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::MissingHostParam => write!(f, "Missing host parameter"),
            AppError::InvalidDnsPacket => write!(f, "Invalid DNS packet"),
            AppError::NoAnswersInPacket => write!(f, "No answers in DNS packet"),
            AppError::RedisPoolError(msg) => write!(f, "Redis pool error: {msg}"),
            AppError::RedisError(msg) => write!(f, "Redis error: {msg}"),
            AppError::NotFound(msg) => write!(f, "{msg}"),
            AppError::SignatureRequired => write!(f, "Signature required but not provided"),
            AppError::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AppError::MissingHostParam => StatusCode::BAD_REQUEST,
            AppError::InvalidDnsPacket => StatusCode::BAD_REQUEST,
            AppError::NoAnswersInPacket => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::RedisPoolError(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::RedisError(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::SignatureRequired => StatusCode::BAD_REQUEST,
            AppError::InvalidSignature => StatusCode::BAD_REQUEST,
        };
        (status, self.to_string()).into_response()
    }
}

pub async fn get_redis_conn(
    pool: &deadpool_redis::Pool,
) -> Result<deadpool_redis::Connection, AppError> {
    pool.get().await.map_err(|e| {
        error!(error = %e, "redis.pool.get.err");
        AppError::RedisPoolError(e.to_string())
    })
}

#[instrument(skip_all)]
pub async fn publish(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let name = match params.get("host") {
        Some(host) => host.clone(),
        None => {
            warn!("publish.missing_host");
            return Err(AppError::MissingHostParam);
        }
    };

    if let Err(e) = validate_dns_packet(body.as_ref(), state.require_signature, &state.pub_key) {
        warn!(host = %name, bytes = body.len(), "publish.invalid_dns_packet");
        return Err(e);
    }

    let mut conn = match get_redis_conn(&state.redis_pool).await {
        Ok(conn) => conn,
        Err(e) => return Err(e),
    };

    if let Err(e) = conn.set_ex::<_, _, ()>(&name, body.as_ref(), 30).await {
        error!(host = %name, error = %e, "publish.cache_set.err");
        return Err(AppError::RedisError(e.to_string()));
    }

    info!(host = %name, ttl = 30, bytes = body.len(), "publish.cache_set.ok");
    Ok((StatusCode::OK, "Success").into_response())
}

#[instrument(skip_all)]
pub async fn lookup(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let host_name = match params.get("host") {
        Some(host) => host,
        None => {
            warn!("lookup.missing_host");
            return Err(AppError::MissingHostParam);
        }
    };

    let mut conn = match get_redis_conn(&state.redis_pool).await {
        Ok(conn) => conn,
        Err(e) => {
            return Err(e);
        }
    };

    match conn.get::<_, Option<Vec<u8>>>(host_name).await {
        Ok(Some(record_bytes)) => {
            let bytes_len: usize = record_bytes.len();
            info!(host = %host_name, bytes = bytes_len, "lookup.hit");
            Ok((StatusCode::OK, Bytes::from(record_bytes)).into_response())
        }
        Ok(None) => {
            info!(host = %host_name, "lookup.miss");
            Err(AppError::NotFound("No DNS records found".to_string()))
        }
        Err(e) => {
            let error_msg: String = e.to_string();
            error!(host = %host_name, error = %error_msg, "lookup.get.err");
            Err(AppError::RedisError(error_msg))
        }
    }
}

pub fn validate_dns_packet(
    packet: &[u8],
    require_signature: bool,
    pub_key: &Option<Vec<u8>>,
) -> Result<String, AppError> {
    let (remaining, dns_packet) = be_packet(packet).map_err(|_| AppError::InvalidDnsPacket)?;
    if !remaining.is_empty() {
        warn!(remain = remaining.len(), "dns.parse.extra_bytes");
    }

    if require_signature {
        let has_signature = dns_packet
            .answers
            .iter()
            .any(|record| matches!(record.data(), RData::E(endpoint) if endpoint.is_signed()));
        if !has_signature {
            warn!("signature.required.bu_not_provided");
            return Err(AppError::SignatureRequired);
        }

        // 验证签名
        for record in &dns_packet.answers {
            if let RData::E(endpoint) = &record.data() {
                if endpoint.is_signed() {
                    if let Some(pk) = pub_key {
                        let spki = SubjectPublicKeyInfoDer::try_from(pk.as_slice())
                            .map_err(|_| AppError::InvalidSignature)?;
                        if !endpoint
                            .verify_signature(spki)
                            .map_err(|_| AppError::InvalidSignature)?
                        {
                            return Err(AppError::InvalidSignature);
                        }
                    } else {
                        // 如果需要签名但没有公钥，我们报错
                        return Err(AppError::SignatureRequired);
                    }
                }
            }
        }
    }

    dns_packet
        .answers
        .first()
        .map(|record| record.name().to_string())
        .ok_or(AppError::NoAnswersInPacket)
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/publish", post(publish))
        .route("/lookup", get(lookup))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    init_logging(&options);

    // 初始化 Redis 连接池
    let redis_cfg = deadpool_redis::Config::from_url(options.redis.clone());
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let pub_key = if let Some(path) = &options.pub_key {
        Some(std::fs::read(path)?)
    } else {
        None
    };

    let state = AppState {
        redis_pool,
        require_signature: options.require_signature,
        pub_key,
    };
    let app = build_router(state);

    info!(listen = %options.listen, "server.start");

    match (options.cert, options.key) {
        (Some(cert), Some(key)) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| format!("TLS config error: {e}"))?;
            axum_server::bind_rustls(options.listen, config)
                .serve(app.into_make_service())
                .await?
        }
        _ => {
            axum_server::bind(options.listen)
                .serve(app.into_make_service())
                .await?
        }
    }

    Ok(())
}
