# kunobi-reload

[![CI](https://github.com/kunobi-ninja/kunobi-reload/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kunobi-ninja/kunobi-reload/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.94.1-blue.svg)](Cargo.toml)

Hot-reload values derived from **Kubernetes mounted volumes** —
`Secret`s, `ConfigMap`s, `projected` volumes, CSI secret mounts —
without restarting the pod.

## Why

A pod reads a mounted credential, TLS certificate, or config file
**once at startup**. When the underlying object is updated — a Postgres
operator rotates a password, cert-manager renews a certificate, you
edit a `ConfigMap` — kubelet refreshes the files on disk, but the
running process keeps using the stale value until it restarts.

The usual workarounds are unsatisfying: restart the pod on every
rotation (an external controller watching the Secret), or poll the
files on a timer (wasteful, and slow to react). Both also have to get
the *Kubernetes mounted-volume layout* right, which is easy to get
subtly wrong. This crate solves it once.

`kunobi-reload` is **not** a Kubernetes client — no `kube`, no
`k8s-openapi` dependency. It only watches the filesystem. It just
*knows* the contract Kubernetes mounted volumes follow and watches it
correctly.

## How Kubernetes mounts Secrets

A mounted volume is not a plain set of files. kubelet builds it like
this:

```text
/etc/app/db/
├── ..2026_05_15_20_00_00.123/   real directory holding the data
│   ├── uri
│   └── password
├── ..data -> ..2026_05_15_20_00_00.123    symlink
├── uri      -> ..data/uri                 symlink
└── password -> ..data/password            symlink
```

On every update kubelet writes a **new** timestamped directory, then
**atomically renames** the `..data` symlink onto it, then removes the
old directory. The user-facing files (`uri`, `password`) are symlinks
whose text never changes — only `..data`'s target moves.

`kunobi-reload`:

- watches the **mount directory** with [`notify`](https://crates.io/crates/notify)
  (inotify on Linux, FSEvents on macOS) — never the individual files,
  which are symlinks that would either never fire an event or strand
  the watch on a deleted inode after the first rotation;
- **debounces** the event burst a single rotation produces;
- confirms the `..data` target actually moved before re-parsing;
- resolves `..data` once per parse, so a multi-file value (a TLS
  cert + key + CA bundle) never mixes old and new files;
- **keeps the previous value** if a re-parse fails — a transient read
  error mid-rotation never takes the value away.

## Usage

```toml
[dependencies]
kunobi-reload = { git = "https://github.com/kunobi-ninja/kunobi-reload", tag = "v0.1.0" }
```

```rust
use kunobi_reload::{watch, BoxError};

# async fn run() -> anyhow::Result<()> {
// Mount the Secret as a volume at /etc/app/db, then:
let db = watch("/etc/app/db")
    .spawn(|mount| async move {
        let uri = mount.read_str("uri")?;
        // build whatever T you need — a pool, a client, a token:
        // Ok(sqlx::PgPool::connect(&uri).await?)
        Ok::<_, BoxError>(uri)
    })
    .await?;

// `load()` always returns the freshest parsed value — lock-free.
let current = db.load();
# let _ = current;
# Ok(())
# }
```

`spawn` parses once eagerly (so a missing or malformed mount fails
fast), then a `notify` watcher takes over. When the Secret rotates,
the closure re-runs and the new value is swapped in atomically.
`Reloadable<T>` is cheap to clone — every clone shares one watcher and
one current value.

### Multi-file values

Because `..data` is swapped atomically, a parse that reads several
keys always sees a consistent set:

```rust
# use kunobi_reload::{watch, BoxError};
# async fn run() -> anyhow::Result<()> {
let tls = watch("/etc/app/tls")
    .spawn(|mount| async move {
        let cert = mount.read("tls.crt")?;
        let key  = mount.read("tls.key")?;
        // cert and key are guaranteed to be from the same rotation
        # let _ = (&cert, &key);
        Ok::<_, BoxError>((cert, key))
    })
    .await?;
# let _ = tls;
# Ok(())
# }
```

## Mounting the Secret as a volume

Use a volume mount, **not** `env.valueFrom.secretKeyRef` — environment
variables are injected once at pod start and never update.

```yaml
volumes:
  - name: db-credentials
    secret:
      secretName: my-db-pguser
containers:
  - name: app
    volumeMounts:
      - name: db-credentials
        mountPath: /etc/app/db
        readOnly: true
```

## Common pitfalls

- **Watching the file, not the directory.** `notify` on `…/uri`
  watches a symlink that is never rewritten — zero events — or, if it
  follows the link, strands on the deleted inode after one rotation.
  Always watch the mount directory. (This crate does.)
- **Using an env var for a rotating secret.** Env vars are frozen at
  pod start. Mount the Secret as a volume.
- **Caching the parsed value forever.** Call `load()` when you need
  the value; don't stash the `Arc<T>` from startup. Holding it across
  one request is fine — holding it for the process lifetime defeats
  the point.
- **Assuming instant propagation.** kubelet syncs mounted Secrets on
  its own cycle (up to ~1 minute). `kunobi-reload` reacts within
  milliseconds of the *file* changing — but the file changing is still
  gated by kubelet.

## Testing

```bash
cargo test
```

Tests build Kubernetes-style mount layouts (`..<timestamp>` data
directory, atomically renamed `..data` symlink, per-key symlinks) in
`tempfile` directories and assert the watcher reloads on a swap — no
real cluster needed.

```bash
cargo deny check
```

## Roadmap

Future additions as duplication shows up across Kunobi services:

- `Reloadable<rustls::ServerConfig>` helper behind a `rustls` feature
- `Reloadable<sqlx::PgPool>` helper behind a `sqlx` feature
- a manual `reload()` trigger for consumers that want to force a refresh

## License

Apache-2.0
