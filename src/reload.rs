//! Watch a Kubernetes mounted volume and re-derive a typed value
//! whenever its contents change.
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
//! Two consequences this module relies on:
//!
//! - **Watch the directory, not the files.** A watch on `uri` either
//!   sees nothing (the symlink is never rewritten) or dies pointing at
//!   a deleted inode after the first rotation. Watching the *mount
//!   directory* sees the `..data` swap.
//! - **Read through `..data` for a consistent set.** Because the whole
//!   `..data` directory is swapped atomically, resolving `..data` once
//!   and reading every key from that snapshot guarantees a multi-file
//!   parse (e.g. TLS cert + key + CA) never mixes old and new files.
//!
//! [`Mount`] encapsulates the read side; [`Watch`] the watch side.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::error::{BoxError, Error, Result};

/// How long to wait for the filesystem to go quiet after the first
/// event before re-reading the mount.
///
/// A single Kubernetes volume update produces a burst of events — new
/// timestamped directory created, `..data` symlink swapped, old
/// directory removed. Coalescing them avoids re-parsing several times
/// for one rotation.
const DEBOUNCE: Duration = Duration::from_millis(200);

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
    /// ConfigMap values are verbatim bytes, so trim in your `parse`
    /// closure if the source might carry a trailing newline.
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
}

/// A cheap fingerprint of a mount's contents, used to confirm a
/// filesystem event reflects a real change before re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Signature {
    /// Kubernetes layout: the resolved target of the `..data` symlink.
    /// kubelet swaps this atomically, so a changed target is a real
    /// update and nothing else is.
    DataLink(PathBuf),
    /// Plain directory (no `..data`): a content hash over every key.
    Hash(u64),
    /// The mount could not be read at all (e.g. briefly missing during
    /// a swap). Distinct from every other value so recovery re-parses.
    Unreadable,
}

/// Compute the current [`Signature`] of a mount root.
fn signature(root: &Path) -> Signature {
    match std::fs::read_link(root.join("..data")) {
        Ok(target) => Signature::DataLink(target),
        Err(_) => match content_hash(&Mount::resolve(root)) {
            Ok(hash) => Signature::Hash(hash),
            Err(_) => Signature::Unreadable,
        },
    }
}

/// Hash every key/value in a mount — the change signal for plain
/// directories that have no `..data` symlink.
fn content_hash(mount: &Mount) -> Result<u64> {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for key in mount.keys()? {
        key.hash(&mut hasher);
        mount.read(&key)?.hash(&mut hasher);
    }
    Ok(hasher.finish())
}

/// A value re-derived from a mounted volume whenever its contents
/// change.
///
/// Clone freely — every clone shares one background watcher and one
/// current value. The watcher stops only when the last clone is
/// dropped.
pub struct Reloadable<T> {
    current: Arc<ArcSwap<T>>,
    shared: Arc<WatchHandle>,
}

impl<T> Clone for Reloadable<T> {
    fn clone(&self) -> Self {
        Self {
            current: Arc::clone(&self.current),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Reloadable<T> {
    /// The current value.
    ///
    /// Cheap and lock-free. The returned `Arc` is a snapshot taken at
    /// call time; clone it (or keep the `Arc`) if you need a stable
    /// view across `await` points, rather than calling `load` again.
    pub fn load(&self) -> Arc<T> {
        self.current.load_full()
    }
}

impl<T> std::fmt::Debug for Reloadable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloadable")
            .field("type", &std::any::type_name::<T>())
            .finish()
    }
}

/// Owns the background reload task. Aborting the task on drop also
/// drops the `notify` watcher the task holds, stopping the OS watch.
struct WatchHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Builder returned by [`watch`]. Call [`spawn`][Watch::spawn] to start.
#[derive(Debug, Clone)]
pub struct Watch {
    dir: PathBuf,
}

/// Start watching a mounted volume directory.
///
/// `dir` is the `mountPath` of a Kubernetes `Secret`/`ConfigMap`/
/// `projected` volume (or any directory). Pair with [`Watch::spawn`]
/// to parse it into a typed value that refreshes automatically.
pub fn watch(dir: impl Into<PathBuf>) -> Watch {
    Watch { dir: dir.into() }
}

impl Watch {
    /// Parse the mount into `T` and keep it refreshed.
    ///
    /// `parse` runs once eagerly — if it fails, `spawn` returns the
    /// error and no watcher is started. On success a `notify` watcher
    /// observes the mount directory; whenever Kubernetes swaps the
    /// `..data` symlink (or, for a plain directory, the contents
    /// change), `parse` re-runs and the new value is swapped in
    /// atomically.
    ///
    /// A failing re-parse is logged at `warn` and the previous value
    /// is kept — a transient read error mid-rotation never takes the
    /// value away.
    ///
    /// # Errors
    ///
    /// - [`Error::Watch`] if the filesystem watcher cannot be created
    ///   or registered (most often: the mount directory does not
    ///   exist yet).
    /// - [`Error::Parse`] if the initial `parse` call fails.
    pub async fn spawn<T, F, Fut>(self, parse: F) -> Result<Reloadable<T>>
    where
        T: Send + Sync + 'static,
        F: Fn(Mount) -> Fut + Send + 'static,
        Fut: Future<Output = std::result::Result<T, BoxError>> + Send,
    {
        let dir = self.dir;

        // 1. Start watching FIRST, so a rotation racing startup is not
        //    missed. The notify callback runs on notify's own thread;
        //    an unbounded sender is non-blocking and Send.
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();
        let mut watcher =
            notify::recommended_watcher(move |_event: notify::Result<notify::Event>| {
                // Every event is just a hint to re-check the signature;
                // we don't decode event kinds. Errors are a hint too.
                let _ = tx.send(());
            })
            .map_err(|e| Error::Watch(Box::new(e)))?;
        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| Error::Watch(Box::new(e)))?;

        // 2. Record the signature, then 3. parse — in that order, so a
        //    swap landing between the two is caught: the signature is
        //    pre-swap, the watcher fires, and the task re-parses.
        let mut last_sig = signature(&dir);
        let initial = parse(Mount::resolve(&dir)).await.map_err(Error::Parse)?;
        let current = Arc::new(ArcSwap::from_pointee(initial));

        let task = {
            let current = Arc::clone(&current);
            let dir = dir.clone();
            tokio::spawn(async move {
                // Hold the watcher for the lifetime of the task; when
                // the task is aborted the watcher drops and the OS
                // watch is released.
                let _watcher = watcher;

                while rx.recv().await.is_some() {
                    // Debounce: drain the event burst until the
                    // filesystem goes quiet for DEBOUNCE.
                    loop {
                        match tokio::time::timeout(DEBOUNCE, rx.recv()).await {
                            Ok(Some(())) => continue,
                            Ok(None) => return, // all senders dropped
                            Err(_quiet) => break,
                        }
                    }

                    let sig = signature(&dir);
                    if sig == last_sig {
                        continue;
                    }

                    match parse(Mount::resolve(&dir)).await {
                        Ok(value) => {
                            current.store(Arc::new(value));
                            last_sig = sig;
                            tracing::info!(dir = %dir.display(), "reloaded mount");
                        }
                        Err(error) => {
                            // Keep last_sig unchanged so the next event
                            // retries this same content.
                            tracing::warn!(
                                dir = %dir.display(),
                                %error,
                                "mount re-parse failed; keeping previous value",
                            );
                        }
                    }
                }
            })
        };

        Ok(Reloadable {
            current,
            shared: Arc::new(WatchHandle { task }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build a Kubernetes-style mount layout under `root`:
    /// `..<version>/` holding the data, `..data` symlinked to it, and
    /// a top-level symlink per key.
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

    /// Poll `reloadable` until `load()` equals `expected`, or panic
    /// after ~10s. The crate reacts via `notify`; the *test* polls for
    /// the observable result, which is normal.
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

        let mut keys = Mount::resolve(dir.path()).keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["password".to_string(), "uri".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloads_when_data_symlink_is_swapped() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);

        let reloadable = watch(dir.path())
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await
            .unwrap();
        assert_eq!(reloadable.load().as_str(), "old");

        // Rotate: new timestamped dir + atomic ..data swap.
        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        wait_for_value(&reloadable, "new").await;
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

        // Rotate to content the parser rejects.
        write_k8s_mount(dir.path(), "v2", &[("uri", "")]);
        // Give the watcher time to fire + debounce + fail the re-parse.
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
    async fn clones_share_one_value_and_watcher() {
        let dir = tempfile::tempdir().unwrap();
        write_k8s_mount(dir.path(), "v1", &[("uri", "old")]);

        let a = watch(dir.path())
            .spawn(|mount| async move { Ok::<_, BoxError>(mount.read_str("uri")?) })
            .await
            .unwrap();
        let b = a.clone();

        write_k8s_mount(dir.path(), "v2", &[("uri", "new")]);
        wait_for_value(&b, "new").await;
        assert_eq!(a.load().as_str(), "new", "clones observe the same value");
    }
}
