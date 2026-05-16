//! Hot-reload values derived from **Kubernetes mounted volumes** —
//! `Secret`s, `ConfigMap`s, `projected` volumes, CSI secret mounts —
//! without restarting the pod.
//!
//! When a credential, TLS certificate, or config file is mounted into
//! a pod and the source object is updated, kubelet refreshes the files
//! on disk. The running process, however, read those files once at
//! startup — it keeps using the stale value until it restarts. This
//! crate closes that gap: you describe how to parse the mount into a
//! typed value, and that value re-derives itself whenever the mount
//! changes.
//!
//! It is **not** a Kubernetes client — it has no dependency on `kube`
//! or `k8s-openapi`. It only watches the filesystem. It just *knows*
//! the contract Kubernetes mounted volumes follow (the atomically
//! swapped `..data` symlink) and watches it correctly.
//!
//! # Quickstart
//!
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! // Watch a mounted Secret; parse the `uri` key into a connection
//! // pool. The closure re-runs every time the Secret rotates.
//! let db = kunobi_reload::watch("/etc/app/db")
//!     .spawn(|mount| async move {
//!         let uri = mount.read_str("uri")?;
//!         // e.g. sqlx::PgPool::connect(&uri).await
//!         Ok::<_, kunobi_reload::BoxError>(uri)
//!     })
//!     .await?;
//!
//! // `load()` always returns the freshest parsed value.
//! let current = db.load();
//! # let _ = current;
//! # Ok(())
//! # }
//! ```
//!
//! # How it works
//!
//! A Kubernetes mounted volume is not a plain set of files — it is a
//! `..data` symlink pointing at a timestamped directory that kubelet
//! **swaps atomically** on every update. This crate:
//!
//! - watches the *mount directory* with [`notify`] (inotify on Linux,
//!   FSEvents on macOS) — never the individual files, which are
//!   symlinks that would either never fire an event or strand the
//!   watch on a deleted inode;
//! - debounces the event burst a single rotation produces;
//! - confirms the `..data` target actually moved before re-parsing;
//! - resolves `..data` once per parse so a multi-file value (a TLS
//!   cert + key + CA bundle) never mixes old and new files;
//! - keeps the previous value if a re-parse fails, so a transient
//!   read error mid-rotation never takes the value away.
//!
//! See the [`reload`] module for the full mechanism.
//!
//! # When to use
//!
//! - A service reading mounted credentials (database, API tokens,
//!   OAuth client secrets) that may rotate while the process runs.
//! - A server reading mounted TLS material that cert-manager or a
//!   Postgres operator renews automatically.
//! - Hot-reloadable configuration from a mounted `ConfigMap`.
//!
//! # When NOT to use
//!
//! - You need to watch arbitrary files edited in place. This crate is
//!   built around the Kubernetes mounted-volume contract (the atomic
//!   `..data` swap); a plain directory works as a fallback (change is
//!   detected by content hash) but in-place edits have no atomicity
//!   guarantee and may be read torn.
//! - You want to *fetch* secrets from an API (Vault, cloud secret
//!   managers). Mount them as a volume first — via the CSI driver or
//!   External Secrets Operator — then point this crate at the mount.
//!
//! # MSRV
//!
//! The crate's `rust-version` tracks recent stable; CI builds on the
//! pinned image.

#![warn(missing_docs)]

pub mod error;
pub mod reload;

pub use error::{BoxError, Error, Result};
pub use reload::{Mount, Reloadable, Watch, watch};
