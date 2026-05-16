//! Error types returned by mount-reload operations.
//!
//! [`Error`] is the top-level enum every fallible API in this crate
//! returns. It is `#[non_exhaustive]` — match through with a wildcard
//! arm to stay compatible with future minor releases.

use std::path::PathBuf;

/// A boxed, thread-safe error.
///
/// The `parse` closure passed to [`Watch::spawn`][crate::Watch::spawn]
/// returns `Result<T, BoxError>` so callers can use `?` with any error
/// type — [`crate::Error`], `sqlx::Error`, `rustls` errors, etc. — in
/// the same `async` block.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Error returned by mount-reload operations.
///
/// Marked `#[non_exhaustive]` — match through with a wildcard arm to
/// keep your code compatible with future minor releases.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The mount directory could not be listed — it does not exist,
    /// is not a directory, or permissions denied the read.
    ///
    /// On a Kubernetes pod this usually means the volume is not
    /// mounted yet, or the `mountPath` in the Deployment is wrong.
    #[error("mount directory {path}: {source}")]
    Mount {
        /// The directory that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A specific key (file) within the mount could not be read.
    ///
    /// During a credential rotation there is a brief window where the
    /// old timestamped data directory is being deleted; a read landing
    /// in that window surfaces here. The background poll loop tolerates
    /// it and retries on the next tick.
    #[error("reading key {key:?} from mount: {source}")]
    Key {
        /// The key that could not be read.
        key: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A key's bytes were requested as a `String` via
    /// [`Mount::read_str`][crate::Mount::read_str] but are not valid
    /// UTF-8.
    #[error("key {key:?} is not valid UTF-8")]
    Utf8 {
        /// The key whose bytes were not valid UTF-8.
        key: String,
    },

    /// The `parse` closure returned an error.
    ///
    /// On the initial parse this is returned from
    /// [`Watch::spawn`][crate::Watch::spawn]. On a later reload it is
    /// logged and the previous value is kept.
    #[error("parsing mount: {0}")]
    Parse(#[source] BoxError),

    /// Setting up the filesystem watcher failed — creating the
    /// `notify` backend, or registering the watch on the mount
    /// directory. The mount directory most likely does not exist yet.
    #[error("watching mount directory: {0}")]
    Watch(#[source] BoxError),
}

/// Convenience `Result` alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
