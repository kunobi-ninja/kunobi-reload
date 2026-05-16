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

`kunobi-reload` closes that gap. You describe how to parse the mount;
the value re-derives itself, in milliseconds, whenever the mount's
**content** actually changes.

It is **not** a Kubernetes client — no `kube`, no `k8s-openapi`
dependency, and **no client dependencies either**: no `sqlx`, no
`rustls`. It ships *traits*, not helpers. You implement a trait for
your own client type; the crate stays a pure filesystem watcher that
understands the Kubernetes mounted-volume contract.

## How Kubernetes mounts Secrets

A mounted volume is not a plain set of files:

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
**atomically renames** the `..data` symlink onto it. `kunobi-reload`:

- watches the **mount directory** with [`notify`](https://crates.io/crates/notify)
  (inotify on Linux, FSEvents on macOS) — never the individual files,
  which are symlinks that would never fire an event or strand the
  watch on a deleted inode after the first rotation;
- falls back to a **slow poll** (default 5 min, configurable) only as
  a safety net for a missed event — `notify` is the mechanism;
- on any trigger, **reads the content and hashes it** — a reload
  happens only when the bytes actually changed, so a `..data` swap
  with identical content wakes nobody;
- resolves `..data` once per parse, so a multi-file value (TLS
  cert + key + CA) never mixes old and new files;
- **keeps the previous value** if a re-parse fails.

## The trait design — two ways to stay fresh

Pick by whether your client's *identity* must stay stable.

### `FromMount` — the value is rebuilt

The crate owns the value; consumers read the latest via `load()` or are
pushed it via a `Subscription`. Each rotation yields a brand-new value.

```rust
use kunobi_reload::{watch, BoxError, FromMount, Mount};

struct DbUri(String);

impl FromMount for DbUri {
    async fn from_mount(mount: Mount) -> Result<Self, BoxError> {
        Ok(DbUri(mount.read_str("uri")?.trim().to_string()))
    }
}

# async fn run() -> anyhow::Result<()> {
let db = watch("/etc/app/db").reloadable::<DbUri>().await?;

let current = db.load();              // freshest value, any time
let mut sub = db.subscribe();         // or be *pushed* every change:
// while let Some(new) = sub.changed().await { /* rebuild pool, ... */ }
# let _ = (current, sub);
# Ok(())
# }
```

### `Refresh` — the client updates itself in place

The consumer holds one stable `Arc<Client>`; the crate calls
`refresh` on it on every change. Every existing `&Client` call site
keeps working untouched — only the client's internals are swapped.
Best for retrofitting rotation into an existing client without
rewiring its call sites.

```rust
use std::sync::{Arc, Mutex};
use kunobi_reload::{watch, BoxError, Mount, Refresh};

struct ApiClient {
    token: Mutex<String>,
}

impl Refresh for ApiClient {
    async fn refresh(&self, mount: Mount) -> Result<(), BoxError> {
        *self.token.lock().unwrap() = mount.read_str("token")?;
        Ok(())
    }
}

# async fn run() -> anyhow::Result<()> {
let client = Arc::new(ApiClient { token: Mutex::new(String::new()) });
let _driver = watch("/etc/app/api").drive(client.clone()).await?;
// `client` is now kept fresh — every holder of it sees rotated tokens.
# Ok(())
# }
```

For an ad-hoc value with no named type, `watch(dir).spawn(closure)`
takes a parse closure directly.

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

- **Watching the file, not the directory.** A watch on `…/uri`
  watches a symlink that is never rewritten — zero events — or strands
  on a deleted inode after one rotation. Always watch the mount
  directory. (This crate does.)
- **Using an env var for a rotating secret.** Frozen at pod start.
  Mount the Secret as a volume.
- **Caching the parsed value forever.** Call `load()` when you need
  it; hold the `Arc` across one request, not for the process lifetime.
- **Assuming instant propagation.** kubelet syncs mounted Secrets on
  its own cycle (up to ~1 min). `kunobi-reload` reacts within
  milliseconds of the *file* changing — but the file changing is still
  gated by kubelet.

## Testing

```bash
cargo test       # builds K8s-style mounts in tempdirs, asserts reload-on-swap
cargo deny check
```

## Roadmap

`kunobi-reload` deliberately ships **no client implementations** — the
trait surface (`FromMount`, `Refresh`) is the contract; consumers
implement it for their own types and the crate keeps zero client
dependencies. Future work, only as duplication shows up:

- a derive macro for `FromMount` over a struct of named keys
- richer `Mount` accessors (optional keys, base64/PEM decoding helpers
  that stay dependency-free)

## License

Apache-2.0
