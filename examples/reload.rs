//! Minimal runnable example.
//!
//! Watches a directory for a `value` file and logs it whenever it
//! changes. Unlike a real Kubernetes mount you drive the changes by
//! hand:
//!
//! ```bash
//! mkdir -p /tmp/kr-demo && echo v1 > /tmp/kr-demo/value
//! KUNOBI_RELOAD_DIR=/tmp/kr-demo cargo run --example reload
//!
//! # then, in another terminal:
//! echo v2 > /tmp/kr-demo/value
//! echo v3 > /tmp/kr-demo/value
//! ```
//!
//! Each write is picked up within a couple hundred milliseconds — no
//! polling, no restart.

use std::time::Duration;

use kunobi_reload::{BoxError, watch};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let dir = std::env::var("KUNOBI_RELOAD_DIR").unwrap_or_else(|_| "/tmp/kr-demo".into());

    let value = watch(&dir)
        .spawn(|mount| async move {
            let v = mount.read_str("value")?;
            Ok::<_, BoxError>(v.trim().to_string())
        })
        .await?;

    tracing::info!(dir, "watching — edit the `value` file to see reloads");

    loop {
        tracing::info!(value = value.borrow().as_str(), "current");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
