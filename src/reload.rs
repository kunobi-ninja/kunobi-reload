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
//! **atomically renames** the `..data` symlink to point at it. The
//! user-facing files are symlinks whose text never changes — only
//! `..data`'s target moves.
//!
//! # What this module does
//!
//! - **Watches the mount directory** with [`notify`] (inotify on
//!   Linux, FSEvents on macOS); a slow [fallback poll][Watch::fallback_poll]
//!   is only a safety net for a missed event.
//! - On any trigger it **reads the content and hashes it** — a reload
//!   happens only when the bytes actually changed.
//! - Resolves `..data` once per read, so a multi-file value (a TLS
//!   cert + key + CA bundle) never mixes old and new files.
//! - Hands the current value out through [`Ref`] — a lock-free guard
//!   that cannot be stored, so callers cannot freeze a stale snapshot.
//! - **Keeps the previous value** if a re-parse fails, and reports it
//!   via [`Reloadable::reload_status`].

use std::future::Future;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use notify::{RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};

use crate::error::{BoxError, Error, Result};

/// How long to wait for the filesystem to go quiet after the first
/// event before re-reading the mount.
const DEBOUNCE: Duration = Duration::from_millis(200);

/// Default cadence of the fallback poll — a safety net for a missed
/// `notify` event, not the primary mechanism.
const DEFAULT_FALLBACK_POLL: Duration = Duration::from_secs(300);

// ===========================================================================
// Mount
// ===========================================================================

/// A consistent snapshot of a mounted volume's files.
///
/// For a Kubernetes `Secret`/`ConfigMap`/`projected` volume, `Mount`
/// resolves the `..data` symlink once at construction and reads every
/// key from that single snapshot, so a multi-file parse never sees a
/// torn mix of old and new files.
///
/// For a plain directory with no `..data`, the directory itself is
/// used — convenient for local development and tests.
#[derive(Debug, Clone)]
pub struct Mount {
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

    /// Read a key's raw bytes. `key` is a file name within the mount.
    pub fn read(&self, key: &str) -> Result<Vec<u8>> {
        std::fs::read(self.data_dir.join(key)).map_err(|source| Error::Key {
            key: key.to_string(),
            source,
        })
    }

    /// Read a key's bytes as a UTF-8 string.
    ///
    /// The value is returned exactly as stored — trim in your parser
    /// if the source might carry a trailing newline.
    pub fn read_str(&self, key: &str) -> Result<String> {
        let bytes = self.read(key)?;
        String::from_utf8(bytes).map_err(|_| Error::Utf8 {
            key: key.to_string(),
        })
    }

    /// List the keys present in the mount, sorted. Kubernetes' internal
    /// entries (`..data` and the `..<timestamp>` directories) are
    /// skipped.
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
    /// The change signal: a reload happens only when this differs from
    /// the last observed value. Derived from the *bytes*, not from the
    /// `..data` symlink target — a re-sync producing identical content
    /// wakes nobody.
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
// FromMount / Refresh
// ===========================================================================

/// A value that knows how to build itself from a [`Mount`] snapshot.
///
/// Implement this so the type can be watched without an explicit parse
/// closure, and so it can describe its own teardown via [`retire`].
///
/// ```no_run
/// use std::sync::Arc;
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
/// [`retire`]: FromMount::retire
pub trait FromMount: Sized + Send + Sync + 'static {
    /// Build `Self` from the mount's current contents.
    fn from_mount(mount: Mount)
    -> impl Future<Output = std::result::Result<Self, BoxError>> + Send;

    /// Called on the *old* value after a newer one has been swapped in.
    ///
    /// The default is a no-op. Override it for **async teardown** that
    /// `Drop` (which is synchronous) cannot do — e.g. `PgPool::close()`,
    /// a graceful gRPC drain, flushing a buffer. Receives `Arc<Self>`
    /// because in-flight callers may still hold the old value.
    fn retire(self: Arc<Self>) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// A long-lived client that refreshes itself **in place** from a new
/// mount snapshot.
///
/// Implement this when the client's *identity* must stay stable across
/// rotations — see [`Watch::drive`]. Contrast [`FromMount`], where each
/// rotation produces a brand-new value.
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
/// let _driver = watch("/etc/app/api").drive(client.clone()).await?;
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
// Ref — the access guard
// ===========================================================================

/// A guard over the current value of a [`Reloadable`].
///
/// `borrow()` returns a `Ref`, not an owned value, on purpose: the
/// `'a` lifetime makes it **impossible to store** in a struct field,
/// so a caller cannot freeze a stale snapshot — every use re-borrows
/// and sees the latest value.
///
/// It is **lock-free**: internally just an `Arc`, holding no lock. It
/// is safe to hold across `.await` (the handler future stays `Send`)
/// and never blocks the reload task's swap. For an owned value of one
/// operation, `(*r).clone()` where `T: Clone`.
pub struct Ref<'a, T> {
    value: Arc<T>,
    // Marker only — zero runtime representation. Ties the guard to the
    // borrow of the handle so it cannot outlive it / be stored.
    _bound: PhantomData<&'a ()>,
}

impl<T> std::ops::Deref for Ref<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&*self.value, f)
    }
}

// ===========================================================================
// ReloadStatus
// ===========================================================================

/// Health of the most recent reload attempt.
///
/// Returned by [`Reloadable::reload_status`]. A failed re-parse keeps
/// the previous value (so the service keeps running on the last-known
/// credentials) — `ReloadStatus` is how a consumer learns it happened,
/// to drive a metric or an alert.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReloadStatus {
    /// The current value reflects the latest mount content.
    Healthy,
    /// The mount changed but re-parsing keeps failing; the value in
    /// use is stale. Carries when it started failing and the most
    /// recent error.
    Stale {
        /// When re-parsing first started failing.
        since: Instant,
        /// The most recent re-parse error, as a string.
        last_error: String,
    },
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
    value: Arc<ArcSwap<T>>,
    changed: watch::Receiver<()>,
    nudge: mpsc::UnboundedSender<()>,
    status: Arc<ArcSwap<ReloadStatus>>,
    shared: Arc<WatchHandle>,
}

impl<T> Clone for Reloadable<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            changed: self.changed.clone(),
            nudge: self.nudge.clone(),
            status: Arc::clone(&self.status),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Reloadable<T> {
    /// Borrow the current value.
    ///
    /// Returns a [`Ref`] — lock-free, cheap, and impossible to store.
    /// Re-borrow at each use; do not stash the result.
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            value: self.value.load_full(),
            _bound: PhantomData,
        }
    }

    /// Subscribe to changes — the returned [`Subscription`] is *pushed*
    /// the new value every time the mount's content changes.
    pub fn subscribe(&self) -> Subscription<T> {
        Subscription {
            value: Arc::clone(&self.value),
            changed: self.changed.clone(),
            _shared: Arc::clone(&self.shared),
        }
    }

    /// Health of the most recent reload attempt — [`ReloadStatus::Healthy`]
    /// normally, [`ReloadStatus::Stale`] if re-parsing is failing.
    pub fn reload_status(&self) -> ReloadStatus {
        ReloadStatus::clone(&self.status.load())
    }

    /// Trigger an immediate content check, bypassing the debounce and
    /// the fallback-poll wait. A no-op if the content is unchanged.
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
/// the mount's content changes. Holding one keeps the watcher alive.
pub struct Subscription<T> {
    value: Arc<ArcSwap<T>>,
    changed: watch::Receiver<()>,
    _shared: Arc<WatchHandle>,
}

impl<T> Clone for Subscription<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            changed: self.changed.clone(),
            _shared: Arc::clone(&self._shared),
        }
    }
}

impl<T> Subscription<T> {
    /// Borrow the current value without waiting. See [`Ref`].
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            value: self.value.load_full(),
            _bound: PhantomData,
        }
    }

    /// Wait for the next change and borrow the new value.
    ///
    /// Resolves once the mount's content changes and the re-parse
    /// succeeds. Returns `None` only if the watcher has stopped.
    pub async fn changed(&mut self) -> Option<Ref<'_, T>> {
        self.changed.changed().await.ok()?;
        Some(Ref {
            value: self.value.load_full(),
            _bound: PhantomData,
        })
    }
}

impl<T> std::fmt::Debug for Subscription<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("type", &std::any::type_name::<T>())
            .finish()
    }
}

/// Owns the background reload task. Aborting it on drop also drops the
/// `notify` watcher the task holds, releasing the OS watch.
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

/// Builder returned by [`watch()`]. Configure, then call
/// [`spawn`][Watch::spawn], [`reloadable`][Watch::reloadable], or
/// [`drive`][Watch::drive].
#[derive(Debug, Clone)]
pub struct Watch {
    dir: PathBuf,
    fallback_poll: Option<Duration>,
}

/// Start watching a mounted volume directory.
pub fn watch(dir: impl Into<PathBuf>) -> Watch {
    Watch {
        dir: dir.into(),
        fallback_poll: Some(DEFAULT_FALLBACK_POLL),
    }
}

impl Watch {
    /// Set the fallback poll cadence — a safety net for a missed
    /// `notify` event, and the retry timer for a failed re-parse.
    /// Defaults to 5 minutes; `None` disables it.
    #[must_use]
    pub fn fallback_poll(mut self, interval: Option<Duration>) -> Self {
        self.fallback_poll = interval;
        self
    }

    /// Parse the mount into `T` with an explicit closure.
    ///
    /// The closure runs once eagerly — if it fails, `spawn` returns the
    /// error. On success a watcher re-runs it whenever the content
    /// changes. A failing re-parse keeps the previous value (see
    /// [`Reloadable::reload_status`]).
    ///
    /// Values needing async teardown of the *old* incarnation should
    /// implement [`FromMount`] (which has [`retire`][FromMount::retire])
    /// and use [`reloadable`][Watch::reloadable] instead.
    ///
    /// # Errors
    ///
    /// - [`Error::Watch`] if the watcher cannot be created/registered.
    /// - [`Error::Parse`] if the initial parse fails.
    pub async fn spawn<T, F, Fut>(self, factory: F) -> Result<Reloadable<T>>
    where
        T: Send + Sync + 'static,
        F: Fn(Mount) -> Fut + Send + 'static,
        Fut: Future<Output = std::result::Result<T, BoxError>> + Send,
    {
        self.spawn_inner(factory, |_old: Arc<T>| async {}).await
    }

    /// Watch a type that implements [`FromMount`].
    ///
    /// Sugar for [`spawn`][Watch::spawn] using the type's own
    /// [`FromMount::from_mount`] — and its [`FromMount::retire`] is
    /// invoked on each old value after a newer one is swapped in.
    ///
    /// # Errors
    ///
    /// Same as [`spawn`][Watch::spawn].
    pub async fn reloadable<T: FromMount>(self) -> Result<Reloadable<T>> {
        self.spawn_inner(|m| T::from_mount(m), |old| T::retire(old))
            .await
    }

    /// Drive an existing client that implements [`Refresh`].
    ///
    /// [`Refresh::refresh`] is called once eagerly, then on every
    /// content change. The consumer keeps and uses `client` directly —
    /// its identity never changes. The returned [`Driver`] keeps the
    /// watch alive; drop it to stop.
    ///
    /// # Errors
    ///
    /// Same as [`spawn`][Watch::spawn].
    pub async fn drive<C: Refresh>(self, client: Arc<C>) -> Result<Driver> {
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

    /// Shared implementation: a parse factory plus a retire hook.
    async fn spawn_inner<T, F, Fut, R, RFut>(self, factory: F, retire: R) -> Result<Reloadable<T>>
    where
        T: Send + Sync + 'static,
        F: Fn(Mount) -> Fut + Send + 'static,
        Fut: Future<Output = std::result::Result<T, BoxError>> + Send,
        R: Fn(Arc<T>) -> RFut + Send + 'static,
        RFut: Future<Output = ()> + Send,
    {
        let dir = self.dir;
        let fallback = self.fallback_poll;

        // 1. Start watching first, so a rotation racing startup is not
        //    missed. The same channel carries `reload()` nudges.
        let (nudge, mut events) = mpsc::unbounded_channel::<()>();
        let watcher_nudge = nudge.clone();
        let mut watcher =
            notify::recommended_watcher(move |_event: notify::Result<notify::Event>| {
                let _ = watcher_nudge.send(());
            })
            .map_err(|e| Error::Watch(Box::new(e)))?;
        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| Error::Watch(Box::new(e)))?;

        // 2. Fingerprint, then 3. parse — in that order.
        let mut last_fp = Mount::resolve(&dir).fingerprint().unwrap_or(0);
        let initial = factory(Mount::resolve(&dir)).await.map_err(Error::Parse)?;

        let value = Arc::new(ArcSwap::from_pointee(initial));
        let status = Arc::new(ArcSwap::from_pointee(ReloadStatus::Healthy));
        let (changed_tx, changed_rx) = watch::channel(());

        let task = {
            let value = Arc::clone(&value);
            let status = Arc::clone(&status);
            let dir = dir.clone();
            tokio::spawn(async move {
                let _watcher = watcher;

                loop {
                    if wait_for_change(&mut events, fallback).await {
                        return; // event channel closed — task should exit
                    }
                    drain_debounced(&mut events).await;

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

                    match factory(Mount::resolve(&dir)).await {
                        Ok(new) => {
                            let old = value.swap(Arc::new(new));
                            last_fp = fp;
                            status.store(Arc::new(ReloadStatus::Healthy));
                            let _ = changed_tx.send(());
                            tracing::info!(dir = %dir.display(), "reloaded mount");
                            // Retire the old value after the new one is
                            // visible — graceful async teardown.
                            retire(old).await;
                        }
                        Err(error) => {
                            // Leave `last_fp` stale so the next trigger
                            // (notify event or fallback poll) retries.
                            let message = error.to_string();
                            let since = match &**status.load() {
                                ReloadStatus::Stale { since, .. } => *since,
                                ReloadStatus::Healthy => Instant::now(),
                            };
                            status.store(Arc::new(ReloadStatus::Stale {
                                since,
                                last_error: message.clone(),
                            }));
                            tracing::warn!(
                                dir = %dir.display(), error = %message,
                                "mount re-parse failed; keeping previous value",
                            );
                        }
                    }
                }
            })
        };

        Ok(Reloadable {
            value,
            changed: changed_rx,
            nudge,
            status,
            shared: Arc::new(WatchHandle { task }),
        })
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

    /// Health of the most recent refresh — see [`ReloadStatus`].
    pub fn status(&self) -> ReloadStatus {
        self.inner.reload_status()
    }
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver").finish()
    }
}

/// Block until the loop should re-check the mount. Returns `true` if
/// the event channel has closed and the task should exit.
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
            Ok(Some(())) => continue,
            Ok(None) | Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build a Kubernetes-style mount layout under `root`.
    fn write_k8s_mount(root: &Path, version: &str, files: &[(&str, &str)]) {
        let data = root.join(format!("..{version}"));
        std::fs::create_dir_all(&data).unwrap();
        for (key, value) in files {
            std::fs::write(data.join(key), value).unwrap();
        }
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

    /// Poll until `borrow()` equals `expected`, or panic after ~10s.
    async fn wait_for_value(reloadable: &Reloadable<String>, expected: &str) {
        for _ in 0..200 {
            if reloadable.borrow().as_str() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "timed out waiting for {expected:?}, last value was {:?}",
            reloadable.borrow()
        );
    }

    #[test]
    fn mount_reads_through_data_symlink() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "postgres://a")]);
        assert_eq!(
            Mount::resolve(dir.path()).read_str("uri").unwrap(),
            "postgres://a"
        );
    }

    #[test]
    fn mount_reads_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), "abc123").unwrap();
        assert_eq!(
            Mount::resolve(dir.path()).read_str("token").unwrap(),
            "abc123"
        );
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
        write_k8s_mount(dir.path(), "v2", &[("uri", "same")]);
        let fp2 = Mount::resolve(dir.path()).fingerprint().unwrap();
        assert_eq!(fp1, fp2, "identical content must hash the same");
        write_k8s_mount(dir.path(), "v3", &[("uri", "different")]);
        let fp3 = Mount::resolve(dir.path()).fingerprint().unwrap();
        assert_ne!(fp1, fp3, "changed content must hash differently");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloads_when_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);
        let reloadable = watch(dir.path())
            .spawn(|m| async move { Ok::<_, BoxError>(m.read_str("uri")?) })
            .await
            .unwrap();
        assert_eq!(reloadable.borrow().as_str(), "old");
        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        wait_for_value(&reloadable, "new").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_reload_when_content_is_identical() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "stable")]);
        let reloadable = watch(dir.path())
            .spawn(|m| async move { Ok::<_, BoxError>(m.read_str("uri")?) })
            .await
            .unwrap();
        let mut sub = reloadable.subscribe();
        write_k8s_mount(dir.path(), "v2", &[("uri", "stable")]);
        let fired = tokio::time::timeout(Duration::from_millis(800), sub.changed()).await;
        assert!(
            fired.is_err(),
            "a content-identical swap must not wake subscribers",
        );
        assert_eq!(reloadable.borrow().as_str(), "stable");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn subscription_is_pushed_the_new_value() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);
        let reloadable = watch(dir.path())
            .spawn(|m| async move { Ok::<_, BoxError>(m.read_str("uri")?) })
            .await
            .unwrap();
        let mut sub = reloadable.subscribe();
        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        let got = tokio::time::timeout(Duration::from_secs(10), sub.changed())
            .await
            .expect("subscription should be pushed the change");
        assert_eq!(got.expect("watcher alive").as_str(), "new");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keeps_previous_value_and_reports_stale_on_failed_reparse() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "good")]);
        let reloadable = watch(dir.path())
            .spawn(|m| async move {
                let uri = m.read_str("uri")?;
                if uri.is_empty() {
                    return Err("empty uri".into());
                }
                Ok::<_, BoxError>(uri)
            })
            .await
            .unwrap();
        assert!(matches!(reloadable.reload_status(), ReloadStatus::Healthy));

        write_k8s_mount(dir.path(), "v2", &[("uri", "")]);
        tokio::time::sleep(Duration::from_millis(800)).await;

        assert_eq!(
            reloadable.borrow().as_str(),
            "good",
            "previous value must survive a failed re-parse",
        );
        assert!(
            matches!(reloadable.reload_status(), ReloadStatus::Stale { .. }),
            "a failed re-parse must be reported as Stale",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_fails_when_mount_directory_is_missing() {
        let missing = std::path::Path::new("/nonexistent/kunobi-reload/mount");
        let result = watch(missing)
            .spawn(|m| async move { Ok::<_, BoxError>(m.read_str("uri")?) })
            .await;
        assert!(result.is_err(), "spawn must fail on a missing mount");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reload_nudge_forces_an_immediate_check() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);
        let reloadable = watch(dir.path())
            .fallback_poll(None)
            .spawn(|m| async move { Ok::<_, BoxError>(m.read_str("uri")?) })
            .await
            .unwrap();
        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        reloadable.reload();
        wait_for_value(&reloadable, "new").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloadable_via_from_mount_calls_retire_on_the_old_value() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Process-unique counter, touched only by this test.
        static RETIRED: AtomicUsize = AtomicUsize::new(0);

        struct Probe(String);
        impl FromMount for Probe {
            async fn from_mount(m: Mount) -> std::result::Result<Self, BoxError> {
                Ok(Probe(m.read_str("uri")?))
            }
            async fn retire(self: Arc<Self>) {
                RETIRED.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);
        let reloadable = watch(dir.path()).reloadable::<Probe>().await.unwrap();
        assert_eq!(reloadable.borrow().0, "old");
        assert_eq!(RETIRED.load(Ordering::SeqCst), 0);

        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        for _ in 0..200 {
            if RETIRED.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(reloadable.borrow().0, "new");
        assert!(
            RETIRED.load(Ordering::SeqCst) > 0,
            "retire() must run on the old value after a swap",
        );
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
        assert_eq!(client.token.lock().unwrap().as_str(), "tok-old");

        write_k8s_mount(dir.path(), "v2", &[("token", "tok-new")]);
        for _ in 0..200 {
            if client.token.lock().unwrap().as_str() == "tok-new" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(client.token.lock().unwrap().as_str(), "tok-new");
    }

    /// `Ref` must be `Send + Sync` so it can be held across `.await` on
    /// a multi-threaded runtime.
    #[test]
    fn ref_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ref<'static, String>>();
        assert_send_sync::<Reloadable<String>>();
        assert_send_sync::<Subscription<String>>();
    }
}
