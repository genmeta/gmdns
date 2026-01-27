use std::{
    collections::{HashMap, HashSet},
    fmt,
    fmt::Display,
    io::{self},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};

use futures::{Stream, stream};
#[cfg(feature = "h3x-resolver")]
use gm_quic::qinterface::io::IO;
#[cfg(feature = "h3x-resolver")]
use gm_quic::qinterface::{Interface, component::Component};
use tokio::{sync::watch, task::JoinSet, time};

use crate::{
    parser::{packet::Packet, record::endpoint::EndpointAddr},
    protocol::MdnsProtocol,
};

pub struct Mdns {
    service_name: String,
    hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
    inner: Mutex<MdnsInner>,
}

struct MdnsInner {
    local_device: String,
    ip: Ipv4Addr,
    proto: Option<Arc<MdnsProtocol>>,
    shutdown_tx: watch::Sender<bool>,
    tasks: JoinSet<()>,
    closing: bool,
}

impl fmt::Debug for Mdns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (local_device, ip, closing) = {
            let guard = self.inner.lock().expect("Mdns inner lock poisoned");
            (guard.local_device.clone(), guard.ip, guard.closing)
        };
        f.debug_struct("Mdns")
            .field("service_name", &self.service_name)
            .field("local_device", &local_device)
            .field("ip", &ip)
            .field("closing", &closing)
            .finish()
    }
}

impl Display for Mdns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let local_device = self
            .inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .local_device
            .clone();
        write!(f, "mDNS({})", local_device)
    }
}

impl Mdns {
    pub fn new(service_name: &str, ip: Ipv4Addr, device: &str) -> io::Result<Self> {
        let service_name = service_name.to_string();
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<EndpointAddr>>::new()));

        let proto = MdnsProtocol::new(device, ip)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tasks = Self::spawn_tasks(
            proto.clone(),
            hosts.clone(),
            service_name.clone(),
            shutdown_rx,
        );

        Ok(Self {
            service_name,
            hosts,
            inner: Mutex::new(MdnsInner {
                local_device: device.to_string(),
                ip,
                proto: Some(proto),
                shutdown_tx,
                tasks,
                closing: false,
            }),
        })
    }

    fn spawn_tasks(
        proto: Arc<MdnsProtocol>,
        hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
        service_name: String,
        shutdown_rx: watch::Receiver<bool>,
    ) -> JoinSet<()> {
        let mut tasks = JoinSet::new();

        // (1) periodic broadcaster
        tasks.spawn({
            let proto = proto.clone();
            let service_name = service_name.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            async move {
                let mut interval = time::interval(Duration::from_secs(10));
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let packet = Packet::query(service_name.clone());
                            if let Err(e) = proto.broadcast_packet(packet).await {
                                tracing::debug!(target: "mdns", "Broadcast packet error: {}", e);
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        // (2) responder
        tasks.spawn({
            let proto = proto.clone();
            let hosts = hosts.clone();
            let service_name = service_name.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        res = proto.receive_query() => {
                            let Ok((_src, query)) = res else {
                                break;
                            };

                            let packet = {
                                let guard = hosts.lock().unwrap();
                                let host_name = guard
                                    .keys()
                                    .cloned()
                                    .map(|h| Self::local_name(service_name.clone(), h))
                                    .collect::<HashSet<_>>();

                                query
                                    .questions
                                    .iter()
                                    .any(|q| host_name.iter().any(|h| h.contains(q.name.as_str())))
                                    .then(|| Packet::answer(query.header.id, &guard))
                            };

                            if let Some(packet) = packet
                                && let Err(e) = proto.broadcast_packet(packet).await
                            {
                                tracing::debug!(target: "mdns", "Send response error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        tasks
    }

    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        if !inner.closing {
            inner.closing = true;
            let _ = inner.shutdown_tx.send(true);
        }

        while ready!(inner.tasks.poll_join_next(cx)).is_some() {}
        inner.proto.take();

        Poll::Ready(())
    }

    #[inline]
    pub fn local_device(&self) -> String {
        self.inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .local_device
            .clone()
    }

    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[inline]
    pub fn insert_host(&self, host_name: String, host_addr: Vec<SocketAddr>) {
        let local_name = Self::local_name(self.service_name.clone(), host_name.clone());
        let mut guard = self.hosts.lock().unwrap();
        tracing::debug!(
            target: "mdns",
            %local_name, ?host_addr,
            "Adding host with addresses",
        );
        let eps = host_addr
            .into_iter()
            .map(|addr| match addr {
                SocketAddr::V4(addr) => EndpointAddr::direct_v4(addr),
                SocketAddr::V6(addr) => EndpointAddr::direct_v6(addr),
            })
            .collect::<Vec<_>>();
        guard.insert(local_name, eps);
    }

    #[inline]
    pub async fn query(&self, domain: String) -> io::Result<Vec<EndpointAddr>> {
        let proto = self
            .inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .proto
            .clone()
            .ok_or_else(|| io::Error::other("mdns is closed"))?;
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
        let (src, mut endpoints) = proto.query(local_name).await?;
        if let Some(pos) = endpoints.iter().position(|ep| ep.addr().ip() == src.ip()) {
            endpoints.swap(0, pos);
        }
        if endpoints.is_empty() {
            return Err(io::Error::other("empty dns result"));
        }
        Ok(endpoints)
    }

    #[inline]
    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> {
        let proto = self
            .inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .proto
            .clone();

        Box::pin(stream::unfold(proto, async move |proto| {
            let proto = proto?;
            Some((proto.receive_boardcast().await.ok()?, Some(proto)))
        }))
    }

    #[inline]
    fn local_name(service_name: String, name: String) -> String {
        name.split_once("genmeta.net")
            .map(|(prefix, _)| format!("{prefix}{service_name}"))
            .unwrap_or(name)
    }
}

#[cfg(feature = "h3x-resolver")]
impl Component for Mdns {
    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        self.poll_close(_cx)
    }

    fn reinit(&self, _iface: &Interface) {
        // Try to re-bind mdns socket/tasks to the new interface.
        let bind_uri = _iface.bind_uri();
        let Some((_family, device, _port)) = bind_uri.as_iface_bind_uri() else {
            return;
        };

        let Ok(real_addr) = _iface.real_addr() else {
            return;
        };

        let Ok(sock_addr) = real_addr.to_string().parse::<SocketAddr>() else {
            return;
        };

        let SocketAddr::V4(v4) = sock_addr else {
            // current mDNS impl is IPv4-only
            return;
        };
        let ip = *v4.ip();

        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        if inner.local_device == device && inner.ip == ip && inner.proto.is_some() {
            return;
        }

        // signal old tasks to stop; remaining tasks will be aborted when JoinSet is dropped.
        let _ = inner.shutdown_tx.send(true);

        let Ok(proto) = MdnsProtocol::new(device, ip) else {
            tracing::debug!(target: "mdns", device, %ip, "Failed to reinit mdns protocol");
            return;
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tasks = Self::spawn_tasks(
            proto.clone(),
            self.hosts.clone(),
            self.service_name.clone(),
            shutdown_rx,
        );

        inner.local_device = device.to_string();
        inner.ip = ip;
        inner.proto = Some(proto);
        inner.shutdown_tx = shutdown_tx;
        inner.tasks = tasks;
        inner.closing = false;
    }
}
