//! Watch a Kubernetes mounted volume and re-derive a typed value
//! whenever its **content** changes.
//!
//! # How Kubernetes mounts Secrets and ConfigMaps
//!
//! When a `Secret`, `ConfigMap`, or `projected` volume is mounted, the
//! directory is not a plain set of files. kubelet builds it like this:
//!
//! ```text
//! /etc/app/db/
//! ├── ..2026_05_15_20_00_00.123/   real directory holding the data
//! │   ├── uri
//! │   └── password
//! ├── ..data -> ..2026_05_15_20_00_00.123    symlink
//! ├── uri      -> ..data/uri                 symlink
//! └── password -> ..data/password            symlink
//! ```
//!
//! On every update kubelet writes a *new* timestamped directory, then
//! **atomically renames** the `..data` symlink to point at it, then
//! removes the old directory. The user-facing files (`uri`,
//! `password`) are symlinks whose text never changes — only `..data`'s
//! target moves.
//!
//! # What this module does
//!
//! - **Watches the mount directory** with [`notify`] (inotify on
//!   Linux, FSEvents on macOS) — never the individual files, which are
//!   symlinks that would either never fire an event or strand the
//!   watch on a deleted inode after the first rotation.
//! - A **slow fallback poll** (default 5 min, see
//!   [`Watch::fallback_poll`]) is a safety net for the rare missed
//!   filesystem event — `notify` is the mechanism, polling is not.
//! - On any trigger it **reads the content and hashes it**; a reload
//!   only happens when the hash actually changed. A `..data` swap that
//!   produces byte-identical content causes zero churn — subscribers
//!   are not woken.
//! - It resolves `..data` once per parse, so a multi-file value (a TLS
//!   cert + key + CA bundle) never mixes old and new files.
//! - It **keeps the previous value** if a re-parse fails.
//!
//! [`Mount`] is the read side, [`Watch`]/[`Reloadable`] the watch
//! side, [`Subscription`] the push side, and [`FromMount`] lets a type
//! describe its own parsing.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};

use crate::error::{BoxError, Error, Result};

/// How long to wait for the filesystem to go quiet after the first
/// event before re-reading the mount. A single Kubernetes volume
/// update produces a burst of events; coalescing them avoids hashing
/// and re-parsing several times for one rotation.
const DEBOUNCE: Duration = Duration::from_millis(200);

/// Default cadence of the fallback poll — a safety net for a missed
/// `notify` event, not the primary mechanism. Override with
/// [`Watch::fallback_poll`].
const DEFAULT_FALLBACK_POLL: Duration = Duration::from_secs(300);

// ===========================================================================
// Mount
// ===========================================================================

/// A consistent snapshot of a mounted volume's files.
///
/// For a Kubernetes `Secret`/`ConfigMap`/`projected` volume, the
/// directory carries a `..data` symlink that kubelet swaps atomically
/// on every update. `Mount` resolves `..data` once at construction and
/// reads every key from that single snapshot, so a multi-file parse
/// never sees a torn mix of old and new files.
///
/// For a plain directory with no `..data`, the directory itself is
/// used — convenient for local development and tests.
#[derive(Debug, Clone)]
pub struct Mount {
    /// Directory the key files actually live in: `<root>/..data` when
    /// the Kubernetes layout is present, else `<root>`.
    data_dir: PathBuf,
}

impl Mount {
    /// Resolve a mount root to its current data snapshot.
    fn resolve(root: &Path) -> Mount {
        let data = root.join("..data");
        let data_dir = if data.exists() {
            data
        } else {
            root.to_path_buf()
        };
        Mount { data_dir }
    }

    /// Read a key's raw bytes.
    ///
    /// `key` is a file name within the mount, e.g. `"uri"` or
    /// `"tls.crt"`.
    pub fn read(&self, key: &str) -> Result<Vec<u8>> {
        std::fs::read(self.data_dir.join(key)).map_err(|source| Error::Key {
            key: key.to_string(),
            source,
        })
    }

    /// Read a key's bytes as a UTF-8 string.
    ///
    /// The value is returned exactly as stored — Kubernetes Secret and
    /// ConfigMap values are verbatim bytes, so trim in your parser if
    /// the source might carry a trailing newline.
    pub fn read_str(&self, key: &str) -> Result<String> {
        let bytes = self.read(key)?;
        String::from_utf8(bytes).map_err(|_| Error::Utf8 {
            key: key.to_string(),
        })
    }

    /// List the keys present in the mount, sorted.
    ///
    /// Kubernetes' internal entries (`..data` and the `..<timestamp>`
    /// directories) are skipped.
    pub fn keys(&self) -> Result<Vec<String>> {
        let entries = std::fs::read_dir(&self.data_dir).map_err(|source| Error::Mount {
            path: self.data_dir.clone(),
            source,
        })?;
        let mut keys = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::Mount {
                path: self.data_dir.clone(),
                source,
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Skip `..data` and the `..<timestamp>` data directories.
            if name.starts_with("..") {
                continue;
            }
            keys.push(name);
        }
        keys.sort();
        Ok(keys)
    }

    /// A content hash over every key and value in the mount.
    ///
    /// This is the change signal: a reload happens only when this
    /// value differs from the last observed one. It is intentionally
    /// derived from the *bytes*, not from the `..data` symlink target
    /// or file timestamps — a re-sync that produces identical content
    /// must not wake subscribers.
    fn fingerprint(&self) -> Result<u64> {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for key in self.keys()? {
            key.hash(&mut hasher);
            self.read(&key)?.hash(&mut hasher);
        }
        Ok(hasher.finish())
    }
}

// ===========================================================================
// FromMount
// ===========================================================================

/// A value that knows how to build itself from a [`Mount`] snapshot.
///
/// Implement this so the type can be watched without an explicit
/// parse closure:
///
/// ```no_run
/// use kunobi_reload::{BoxError, FromMount, Mount, watch};
///
/// struct DbUri(String);
///
/// impl FromMount for DbUri {
///     async fn from_mount(mount: Mount) -> Result<Self, BoxError> {
///         Ok(DbUri(mount.read_str("uri")?.trim().to_string()))
///     }
/// }
///
/// # async fn run() -> anyhow::Result<()> {
/// let uri = watch("/etc/app/db").reloadable::<DbUri>().await?;
/// # let _ = uri;
/// # Ok(())
/// # }
/// ```
///
/// The future must be `Send`: it is driven on a background task. An
/// `async fn` in the impl satisfies the bound as long as nothing
/// non-`Send` is held across an `await`.
pub trait FromMount: Sized + Send + Sync + 'static {
    /// Build `Self` from the mount's current contents.
    fn from_mount(mount: Mount)
    -> impl Future<Output = std::result::Result<Self, BoxError>> + Send;
}

// ===========================================================================
// Refresh
// ===========================================================================

/// A long-lived client that refreshes itself **in place** from a new
/// mount snapshot.
///
/// This is the other half of the trait design — pick by whether the
/// client's *identity* must stay stable:
///
/// - [`FromMount`] + [`Reloadable`]: each rotation produces a
///   brand-new value. Consumers pick it up via [`Reloadable::load`] or
///   a [`Subscription`]. Good when the value is small and passed by
///   `load()` at the point of use.
/// - [`Refresh`] + [`Watch::drive`]: the consumer holds one stable
///   `Arc<Client>` and the crate calls [`refresh`][Refresh::refresh]
///   on it on every change. Every existing `&Client` call site keeps
///   working untouched — only the client's internal credential or
///   config is swapped. Good for retrofitting rotation into an
///   existing client without rewiring its call sites.
///
/// `kunobi-reload` deliberately ships **no** client implementations —
/// no `sqlx`, no `rustls` dependency. You implement `Refresh` (or
/// `FromMount`) for your own client type; the crate stays a pure
/// watcher.
///
/// ```no_run
/// use std::sync::{Arc, Mutex};
/// use kunobi_reload::{BoxError, Mount, Refresh, watch};
///
/// struct ApiClient {
///     token: Mutex<String>,
/// }
///
/// impl Refresh for ApiClient {
///     async fn refresh(&self, mount: Mount) -> Result<(), BoxError> {
///         *self.token.lock().unwrap() = mount.read_str("token")?;
///         Ok(())
///     }
/// }
///
/// # async fn run() -> anyhow::Result<()> {
/// let client = Arc::new(ApiClient { token: Mutex::new(String::new()) });
/// // `drive` refreshes the client once eagerly, then on every change.
/// let _driver = watch("/etc/app/api").drive(client.clone()).await?;
/// // every holder of `client` now transparently sees rotated tokens.
/// # Ok(())
/// # }
/// ```
pub trait Refresh: Send + Sync + 'static {
    /// Update `self` in place from the mount's current contents.
    fn refresh(
        &self,
        mount: Mount,
    ) -> impl Future<Output = std::result::Result<(), BoxError>> + Send;
}

// ===========================================================================
// Reloadable
// ===========================================================================

/// A value re-derived from a mounted volume whenever its content
/// changes.
///
/// Clone freely — every clone shares one background watcher and one
/// current value. The watcher stops only when the last clone (and
/// every [`Subscription`] taken from it) is dropped.
pub struct Reloadable<T> {
    rx: watch::Receiver<Arc<T>>,
    nudge: mpsc::UnboundedSender<()>,
    shared: Arc<WatchHandle>,
}

impl<T> Clone for Reloadable<T> {
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
            nudge: self.nudge.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Reloadable<T> {
    /// The current value.
    ///
    /// Cheap. The returned `Arc` is a snapshot taken at call time;
    /// keep the `Arc` if you need a stable view across `await` points,
    /// rather than calling `load` again.
    pub fn load(&self) -> Arc<T> {
        self.rx.borrow().clone()
    }

    /// Subscribe to changes.
    ///
    /// The returned [`Subscription`] is *pushed* the new value every
    /// time the mount's content changes — use it to rebuild a
    /// connection pool, reconfigure TLS, etc. A subscription keeps the
    /// watcher alive on its own.
    pub fn subscribe(&self) -> Subscription<T> {
        Subscription {
            rx: self.rx.clone(),
            _shared: Arc::clone(&self.shared),
        }
    }

    /// Trigger an immediate content check, bypassing the debounce and
    /// the fallback-poll wait.
    ///
    /// If the content has changed since the last reload the value is
    /// re-parsed and subscribers are notified; if it is byte-identical
    /// this is a no-op. Useful right after a deploy, or in tests.
    pub fn reload(&self) {
        let _ = self.nudge.send(());
    }
}

impl<T> std::fmt::Debug for Reloadable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloadable")
            .field("type", &std::any::type_name::<T>())
            .finish()
    }
}

// ===========================================================================
// Subscription
// ===========================================================================

/// The push side of a [`Reloadable`] — yields the new value every time
/// the mount's content changes.
///
/// Obtain one with [`Reloadable::subscribe`]. Holding a `Subscription`
/// keeps the background watcher alive.
pub struct Subscription<T> {
    rx: watch::Receiver<Arc<T>>,
    _shared: Arc<WatchHandle>,
}

impl<T> Clone for Subscription<T> {
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
            _shared: Arc::clone(&self._shared),
        }
    }
}

impl<T> Subscription<T> {
    /// The current value, without waiting.
    pub fn current(&self) -> Arc<T> {
        self.rx.borrow().clone()
    }

    /// Wait for the next change and return the new value.
    ///
    /// Resolves once the mount's content changes and the re-parse
    /// succeeds. Returns `None` only if the watcher has stopped — which
    /// cannot happen while this `Subscription` is alive unless the
    /// background task panicked.
    pub async fn changed(&mut self) -> Option<Arc<T>> {
        self.rx.changed().await.ok()?;
        Some(self.rx.borrow_and_update().clone())
    }
}

impl<T> std::fmt::Debug for Subscription<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("type", &std::any::type_name::<T>())
            .finish()
    }
}

/// Owns the background reload task. Aborting the task on drop also
/// drops the `notify` watcher the task holds, releasing the OS watch.
struct WatchHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ===========================================================================
// Watch builder
// ===========================================================================

/// Builder returned by [`watch`]. Configure, then call
/// [`spawn`][Watch::spawn] or [`reloadable`][Watch::reloadable].
#[derive(Debug, Clone)]
pub struct Watch {
    dir: PathBuf,
    fallback_poll: Option<Duration>,
}

/// Start watching a mounted volume directory.
///
/// `dir` is the `mountPath` of a Kubernetes `Secret`/`ConfigMap`/
/// `projected` volume (or any directory).
pub fn watch(dir: impl Into<PathBuf>) -> Watch {
    Watch {
        dir: dir.into(),
        fallback_poll: Some(DEFAULT_FALLBACK_POLL),
    }
}

impl Watch {
    /// Set the fallback poll cadence — a safety net for a missed
    /// `notify` event. `notify` remains the primary mechanism; this
    /// only bounds worst-case staleness if the OS watch drops an
    /// event. Defaults to 5 minutes.
    ///
    /// Pass `None` to disable the fallback entirely and rely on
    /// `notify` alone.
    #[must_use]
    pub fn fallback_poll(mut self, interval: Option<Duration>) -> Self {
        self.fallback_poll = interval;
        self
    }

    /// Parse the mount into `T` with an explicit closure and keep it
    /// refreshed.
    ///
    /// `parse` runs once eagerly — if it fails, `spawn` returns the
    /// error and no watcher is started. On success a `notify` watcher
    /// observes the mount directory; whenever its content changes,
    /// `parse` re-runs and the new value is published to every
    /// [`Subscription`]. A failing re-parse is logged at `warn` and
    /// the previous value is kept.
    ///
    /// # Errors
    ///
    /// - [`Error::Watch`] if the filesystem watcher cannot be created
    ///   or registered (most often: the mount directory is missing).
    /// - [`Error::Parse`] if the initial `parse` call fails.
    pub async fn spawn<T, F, Fut>(self, parse: F) -> Result<Reloadable<T>>
    where
        T: Send + Sync + 'static,
        F: Fn(Mount) -> Fut + Send + 'static,
        Fut: Future<Output = std::result::Result<T, BoxError>> + Send,
    {
        let dir = self.dir;
        let fallback_poll = self.fallback_poll;

        // 1. Start watching FIRST, so a rotation racing startup is not
        //    missed. The notify callback runs on notify's own thread;
        //    an unbounded sender is non-blocking and Send. The same
        //    channel carries `reload()` nudges.
        let (nudge, mut events) = mpsc::unbounded_channel::<()>();
        let watcher_nudge = nudge.clone();
        let mut watcher =
            notify::recommended_watcher(move |_event: notify::Result<notify::Event>| {
                // Every event is just a hint to re-check the content;
                // event kinds are not decoded. Errors are a hint too.
                let _ = watcher_nudge.send(());
            })
            .map_err(|e| Error::Watch(Box::new(e)))?;
        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| Error::Watch(Box::new(e)))?;

        // 2. Fingerprint, then 3. parse — in that order, so a swap
        //    landing between the two still triggers a re-parse: the
        //    fingerprint is pre-swap, the watcher fires, the task sees
        //    a differing fingerprint and reloads.
        let mut last_fp = Mount::resolve(&dir).fingerprint().unwrap_or(0);
        let initial = parse(Mount::resolve(&dir)).await.map_err(Error::Parse)?;
        let (tx, rx) = watch::channel(Arc::new(initial));

        let task = {
            let dir = dir.clone();
            tokio::spawn(async move {
                // Hold the watcher for the lifetime of the task; when
                // the task is aborted the watcher drops and the OS
                // watch is released.
                let _watcher = watcher;

                loop {
                    if wait_for_change(&mut events, fallback_poll).await {
                        return; // event channel closed — task should exit
                    }
                    drain_debounced(&mut events).await;

                    // Read the content and only proceed if it changed.
                    let mount = Mount::resolve(&dir);
                    let fp = match mount.fingerprint() {
                        Ok(fp) => fp,
                        Err(error) => {
                            tracing::warn!(
                                dir = %dir.display(), %error,
                                "could not read mount; will retry",
                            );
                            continue;
                        }
                    };
                    if fp == last_fp {
                        continue; // content identical — do not churn
                    }

                    match parse(Mount::resolve(&dir)).await {
                        Ok(value) => {
                            last_fp = fp;
                            // `send` notifies every subscriber. It errs
                            // only if all receivers are gone, in which
                            // case the task is about to be aborted.
                            let _ = tx.send(Arc::new(value));
                            tracing::info!(dir = %dir.display(), "reloaded mount");
                        }
                        Err(error) => {
                            // Leave `last_fp` stale so this same content
                            // is retried on the next trigger.
                            tracing::warn!(
                                dir = %dir.display(), %error,
                                "mount re-parse failed; keeping previous value",
                            );
                        }
                    }
                }
            })
        };

        Ok(Reloadable {
            rx,
            nudge,
            shared: Arc::new(WatchHandle { task }),
        })
    }

    /// Watch a type that implements [`FromMount`].
    ///
    /// Sugar for [`spawn`][Watch::spawn] using the type's own
    /// [`FromMount::from_mount`] as the parser.
    ///
    /// # Errors
    ///
    /// Same as [`spawn`][Watch::spawn].
    pub async fn reloadable<T: FromMount>(self) -> Result<Reloadable<T>> {
        self.spawn(|mount| T::from_mount(mount)).await
    }

    /// Drive an existing client that implements [`Refresh`].
    ///
    /// [`Refresh::refresh`] is called once eagerly (failing fast if it
    /// errors), then again every time the mount's content changes. The
    /// consumer keeps and uses `client` directly — its identity never
    /// changes; it just stays fresh.
    ///
    /// The returned [`Driver`] keeps the watch alive; drop it to stop.
    ///
    /// # Errors
    ///
    /// - [`Error::Watch`] if the filesystem watcher cannot be created
    ///   or registered.
    /// - [`Error::Parse`] if the initial `refresh` call fails.
    pub async fn drive<C: Refresh>(self, client: Arc<C>) -> Result<Driver> {
        // Reuse the spawn machinery: the "parsed value" is `()`, and
        // the parse step is the client's own in-place refresh. notify,
        // debounce, content-diff and the fallback poll all apply.
        let inner = self
            .spawn(move |mount| {
                let client = Arc::clone(&client);
                async move {
                    client.refresh(mount).await?;
                    Ok(())
                }
            })
            .await?;
        Ok(Driver { inner })
    }
}

/// Keeps a [`Watch::drive`] watch alive. Drop it to stop refreshing.
pub struct Driver {
    inner: Reloadable<()>,
}

impl Driver {
    /// Force an immediate content check and, if the content changed,
    /// a [`Refresh::refresh`]. A no-op if the content is unchanged.
    pub fn reload(&self) {
        self.inner.reload();
    }
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver").finish()
    }
}

/// Block until something asks the loop to re-check the mount: a
/// `notify` event, a [`Reloadable::reload`] nudge, or the fallback
/// poll tick. Returns `true` if the event channel has closed and the
/// task should exit.
async fn wait_for_change(
    events: &mut mpsc::UnboundedReceiver<()>,
    fallback: Option<Duration>,
) -> bool {
    match fallback {
        Some(interval) => {
            tokio::select! {
                event = events.recv() => event.is_none(),
                () = tokio::time::sleep(interval) => false,
            }
        }
        None => events.recv().await.is_none(),
    }
}

/// Drain the event burst a single rotation produces, returning once
/// the filesystem has been quiet for [`DEBOUNCE`].
async fn drain_debounced(events: &mut mpsc::UnboundedReceiver<()>) {
    loop {
        match tokio::time::timeout(DEBOUNCE, events.recv()).await {
            Ok(Some(())) => continue, // more events — keep draining
            Ok(None) | Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build a Kubernetes-style mount layout under `root`:
    /// `..<version>/` holding the data, an atomically-renamed `..data`
    /// symlink, and a top-level symlink per key.
    fn write_k8s_mount(root: &Path, version: &str, files: &[(&str, &str)]) {
        let data = root.join(format!("..{version}"));
        std::fs::create_dir_all(&data).unwrap();
        for (key, value) in files {
            std::fs::write(data.join(key), value).unwrap();
        }
        // Atomic `..data` swap: write a temp symlink, then rename it —
        // exactly what kubelet does.
        let tmp = root.join("..data_tmp");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(format!("..{version}"), &tmp).unwrap();
        std::fs::rename(&tmp, root.join("..data")).unwrap();
        for (key, _) in files {
            let link = root.join(key);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("..data/{key}"), &link).unwrap();
        }
    }

    /// Poll until `reloadable.load()` equals `expected`, or panic after
    /// ~10s. The crate reacts via `notify`; the *test* polls for the
    /// observable result, which is normal.
    async fn wait_for_value(reloadable: &Reloadable<String>, expected: &str) {
        for _ in 0..200 {
            if reloadable.load().as_str() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "timed out waiting for {expected:?}, last value was {:?}",
            reloadable.load()
        );
    }

    #[test]
    fn mount_reads_through_data_symlink() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "postgres://a")]);

        let mount = Mount::resolve(dir.path());
        assert_eq!(mount.read_str("uri").unwrap(), "postgres://a");
    }

    #[test]
    fn mount_reads_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), "abc123").unwrap();

        let mount = Mount::resolve(dir.path());
        assert_eq!(mount.read_str("token").unwrap(), "abc123");
    }

    #[test]
    fn keys_skip_kubernetes_internal_entries() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "x"), ("password", "y")]);

        let keys = Mount::resolve(dir.path()).keys().unwrap();
        assert_eq!(keys, vec!["password".to_string(), "uri".to_string()]);
    }

    #[test]
    fn fingerprint_tracks_content_not_the_data_target() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "same")]);
        let fp1 = Mount::resolve(dir.path()).fingerprint().unwrap();

        // New `..data` target, identical content.
        write_k8s_mount(dir.path(), "v2", &[("uri", "same")]);
        let fp2 = Mount::resolve(dir.path()).fingerprint().unwrap();
        assert_eq!(fp1, fp2, "identical content must hash the same");

        // Same as above but content actually differs.
        write_k8s_mount(dir.path(), "v3", &[("uri", "different")]);
        let fp3 = Mount::resolve(dir.path()).fingerprint().unwrap();
        assert_ne!(fp1, fp3, "changed content must hash differently");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloads_when_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);

        let reloadable = watch(dir.path())
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await
            .unwrap();
        assert_eq!(reloadable.load().as_str(), "old");

        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        wait_for_value(&reloadable, "new").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_reload_when_content_is_identical() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "stable")]);

        let reloadable = watch(dir.path())
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await
            .unwrap();
        let mut sub = reloadable.subscribe();

        // Swap `..data` to a new directory with byte-identical content.
        write_k8s_mount(dir.path(), "v2", &[("uri", "stable")]);

        // The subscription must NOT fire — content did not change.
        let fired = tokio::time::timeout(Duration::from_millis(800), sub.changed()).await;
        assert!(
            fired.is_err(),
            "a content-identical swap must not wake subscribers",
        );
        assert_eq!(reloadable.load().as_str(), "stable");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn subscription_is_pushed_the_new_value() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);

        let reloadable = watch(dir.path())
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await
            .unwrap();
        let mut sub = reloadable.subscribe();

        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);

        let received = tokio::time::timeout(Duration::from_secs(10), sub.changed())
            .await
            .expect("subscription should be pushed the change");
        assert_eq!(received.as_deref().map(String::as_str), Some("new"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keeps_previous_value_when_reparse_fails() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "good")]);

        let reloadable = watch(dir.path())
            .spawn(|mount| async move {
                let uri = mount.read_str("uri")?;
                if uri.is_empty() {
                    return Err("empty uri".into());
                }
                Ok::<_, BoxError>(uri)
            })
            .await
            .unwrap();
        assert_eq!(reloadable.load().as_str(), "good");

        write_k8s_mount(dir.path(), "v2", &[("uri", "")]);
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(
            reloadable.load().as_str(),
            "good",
            "previous value must survive a failed re-parse",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_fails_when_mount_directory_is_missing() {
        let missing = std::path::Path::new("/nonexistent/kunobi-reload/mount");
        let result = watch(missing)
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await;
        assert!(result.is_err(), "spawn must fail on a missing mount");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reload_nudge_forces_an_immediate_check() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);

        // No notify, no fallback poll — only an explicit reload() can
        // advance the value.
        let reloadable = watch(dir.path())
            .fallback_poll(None)
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await
            .unwrap();

        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        reloadable.reload();
        wait_for_value(&reloadable, "new").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloadable_via_from_mount_trait() {
        struct DbUri(String);

        impl FromMount for DbUri {
            async fn from_mount(mount: Mount) -> std::result::Result<Self, BoxError> {
                Ok(DbUri(mount.read_str("uri")?.trim().to_string()))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "postgres://h\n")]);

        let reloadable = watch(dir.path()).reloadable::<DbUri>().await.unwrap();
        assert_eq!(reloadable.load().0, "postgres://h");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drive_refreshes_a_client_in_place() {
        use std::sync::Mutex;

        struct Client {
            token: Mutex<String>,
        }

        impl Refresh for Client {
            async fn refresh(&self, mount: Mount) -> std::result::Result<(), BoxError> {
                *self.token.lock().unwrap() = mount.read_str("token")?;
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("token", "tok-old")]);

        let client = Arc::new(Client {
            token: Mutex::new(String::new()),
        });
        let _driver = watch(dir.path()).drive(client.clone()).await.unwrap();
        // The eager refresh ran before `drive` returned.
        assert_eq!(client.token.lock().unwrap().as_str(), "tok-old");

        write_k8s_mount(dir.path(), "v2", &[("token", "tok-new")]);
        for _ in 0..200 {
            if client.token.lock().unwrap().as_str() == "tok-new" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            client.token.lock().unwrap().as_str(),
            "tok-new",
            "the client must be refreshed in place — same Arc identity",
        );
    }
}
