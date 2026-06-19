use crate::api::api::create_router;
use crate::buf::BytePacketBuffer;
use crate::record::packet::DnsPacket;
use crate::resolver::resolver::ResolverService;
use crate::telemetry::{get_subscriber, init_subscriber};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, info};

pub mod api;
pub mod buf;
pub mod handlers;
pub mod record;
pub mod resolver;
pub mod telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tokio::try_join!(handle_dns_requests(), handle_api_requests());
    Ok(())
}

async fn handle_api_requests() -> Result<()> {
    let router = create_router();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;

    axum::serve(listener, router).await?;

    Ok(())
}

async fn handle_dns_requests() -> Result<()> {
    // Setup tracing
    let subscriber = get_subscriber(
        "resolve-rs".to_string(),
        "info".to_string(),
        std::io::stdout,
    );
    init_subscriber(subscriber);

    // Using Arc since we will spawn a thread for each connection and we need to share the
    // socket between them.
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 2053)).await?);

    // Max 256 concurrent queries
    let limiter = Arc::new(Semaphore::new(256));

    let mut tasks = JoinSet::new();
    let resolver = Arc::new(ResolverService::new());

    loop {
        // Receive done in main() so that we can handle multiple queries at once.
        let mut req_buffer = BytePacketBuffer::new();

        tokio::select! {
            result = socket.recv_from(&mut req_buffer.buf) => {
                let (_, src) = result?;
                let request = DnsPacket::from_buffer(&mut req_buffer)?;

                let socket = Arc::clone(&socket);
                let limiter = Arc::clone(&limiter);
                let resolver = Arc::clone(&resolver);

                // Spawn a task for each query
                tasks.spawn(async move {
                    let permit = limiter.acquire().await;
                    let response = resolver.handle_query(request).await?;
                    socket.send_to(&response, src).await?;

                    drop(permit);
                    Ok::<(), anyhow::Error>(())
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT, shutting down");
                break; // break out of loop and trigger graceful shutdown
            }

        }
    }

    let graceful = async {
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                error!("Error: {}", e);
            } else {
                debug!("Shutting down task");
            }
        }
    };

    if timeout(Duration::from_secs(5), graceful).await.is_err() {
        error!("Shutdown timeout reached, force quitting threads");
        tasks.abort_all();
    }

    Ok(())
}
