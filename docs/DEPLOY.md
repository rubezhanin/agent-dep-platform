# Deploying `agency-server` on a VPS

This document is the end-to-end
walkthrough for taking a fresh
Linux VPS and exposing
`agency-server` on HTTPS. Two
parallel paths are documented:

- **[A] Docker Compose** — recommended. Self-contained, easy to roll back.
- **[B] Native systemd** — for operators who do not run Docker on the box.

Both paths share the same
**Prerequisites** below.

> **Status (2.9.0)**: the
> `agency-server` binary is
> VPS-ready. The Tauri desktop
> app (`crates/tauri-app`) is
> GUI-only and does NOT run on a
> headless server. The CLI
> (`agency`) is a separate
> binary that operators install
> on their workstation and point
> at the server over HTTPS.

## Prerequisites

A Linux VPS (Ubuntu 22.04 LTS or
Debian 12 — the steps below
assume `apt`). You need:

- A public hostname with DNS `A` / `AAAA` records pointing at the VPS (e.g. `agency.example.com`).
- Ports 80 + 443 open inbound (for Let's Encrypt via Caddy). If you only need an internal test, 80 + 443 can stay closed; the steps still work locally via `https://localhost` with a self-signed cert.
- At least 1 GB RAM and 5 GB disk. The binary itself is ~30 MB; the SQLite database and Hermes working copies are what grows over time.
- **Hermes Agent already installed** and the `hermes` CLI on `PATH`. Detect it with:

  ```bash
  hermes --version
  ```

  The server uses `which("hermes")` and (optionally) `HERMES_HOME` to find the install. If you have a non-standard layout, set `HERMES_HOME=/path/to/.hermes` in the environment.

- A **2.x release** binary (local build) OR a GitHub release tag. For a self-built binary:

  ```bash
  git clone https://github.com/<owner>/agent-dep-platform.git
  cd agent-dep-platform
  cargo build --release -p agency-server -p agency
  ```

  The release profile in `Cargo.toml` is `lto = "thin"` + `opt-level = 3`; binaries are stripped and self-contained (no extra `.so` install required, except for `glibc` on the distroless image).

## 1. The shape of the deployment

```
operator workstation                          VPS
+-----------------------+               +----------------------+
|  agency (CLI)         |               |  caddy :80 / :443    |
|  Tauri desktop (opt.) |               |     \                |
+--------+----------+    |               |  reverse_proxy      |
         |   HTTPS over    |               |  agency-server:8080|
         |   Bearer token  |               |     (distroless)   |
         |                 |               |     /var/lib/agency|
         +-----------------+               |       data/agency.db|
                                           +----------+-----------+
                                                      | file:// or git+ssh
                                                      v
                                              Hermes home (already on the box)
```

- `caddy` terminates TLS and reverse-proxies to `agency-server` on a private network.
- `agency-server` is the only process that touches `/var/lib/agency`. The CLI talks to it over HTTPS.
- The audit log, the secrets vault, the `pending_deploys` table, the admin user table, and the Hermes working copies all live under `/var/lib/agency`.

## 2. [A] Docker Compose path

### 2.1 — install Docker

```bash
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release; echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
# log out + back in for the group to apply
```

### 2.2 — clone + build

```bash
sudo mkdir -p /opt/agency-server
sudo chown $USER:$USER /opt/agency-server
git clone https://github.com/<owner>/agent-dep-platform.git /opt/agency-server/repo
cd /opt/agency-server/repo
# Optional: pin a tag.
#   git checkout v2.9.0
```

### 2.3 — write the operator secrets

```bash
sudo install -d -m 0700 -o root -g root /etc/agency
sudo tee /etc/agency/agency.env >/dev/null <<'EOF'
AGENCY_VAULT_PASSPHRASE=replace-me-with-a-32-byte-random-string
AGENCY_OIDC_ISSUER=https://idp.example.com/
AGENCY_OIDC_CLIENT_ID=replace-me
AGENCY_OIDC_CLIENT_SECRET=replace-me
AGENCY_OIDC_REDIRECT_URI=https://agency.example.com/v1/auth/oidc/callback
AGENCY_OIDC_JWKS_URL=https://idp.example.com/.well-known/jwks.json
AGENCY_OIDC_MOCK=0
EOF
sudo chmod 0600 /etc/agency/agency.env
```

For the dev loop (no real IdP wired up yet), set `AGENCY_OIDC_MOCK=1` and leave the rest blank.

### 2.4 — write the plugin trust store

The trust store is the operator-supplied list of Ed25519 public keys that may sign `plugin.toml` files. The 2.7.4 production policy is "unsigned manifest is REJECTED", so even with an empty trust store the `PluginScanner` will refuse every plugin.

```bash
sudo install -d -m 0755 /opt/agency-server/repo/etc
cat > /opt/agency-server/repo/etc/trust.json <<'EOF'
{
  "signers": [
    {
      "id": "acme-security",
      "public_key": "<base64url-32-byte-ed25519-public-key>",
      "label": "acme@example.com"
    }
  ]
}
EOF
# How to derive `id`: run
#   python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex('<hex-of-public-key>')).hexdigest()[:16])"
```

### 2.5 — start the stack

```bash
cd /opt/agency-server/repo
# Pick a domain. On first start Caddy
# will issue a self-signed cert for
# this name; switch to a public
# hostname (with DNS A/AAAA pointing
# here) to get Let's Encrypt
# automatically.
export AGENCY_DOMAIN=agency.example.com
# Load operator secrets into the
# compose env.
set -a; source /etc/agency/agency.env; set +a
docker compose up -d --build
docker compose logs -f agency-server
```

On first boot, the server prints
the admin token to the log:

```
agency-server: created initial admin user, token in /var/lib/agency/server.token
agency-server: token=<...> (save this; the plain token is not stored)
```

The plain token is **only** in the
log — it is hashed inside the
`users` table from this point on.
Copy the token somewhere safe (a
password manager) and `Ctrl-C` the
log tail.

### 2.6 — smoke test

```bash
# health (no auth)
curl -kfsS https://${AGENCY_DOMAIN}/v1/health
# → {"status":"ok"}

# audit (with the token from the log)
TOKEN=$(docker compose exec -T agency-server cat /var/lib/agency/server.token)
curl -kfsS -H "Authorization: Bearer $TOKEN" https://${AGENCY_DOMAIN}/v1/audit
# → {"items":[],"total":0}

# list environments
curl -kfsS -H "Authorization: Bearer $TOKEN" \
  https://${AGENCY_DOMAIN}/v1/environments
```

### 2.7 — what you can do end-to-end right now

With a Hermes install on the host
(`/usr/local/bin/hermes` or
`/opt/hermes/bin/hermes`), the
following round-trip works against
a local catalog directory:

```bash
# 1. create a target the deploys land on
curl -kfsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"dev","environment":"dev","path":"/srv/hermes","path_kind":"posix"}' \
  https://${AGENCY_DOMAIN}/v1/targets

# 2. plan + request a deploy
curl -kfsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "$(cat <<JSON
{
  "catalog": "/srv/catalog",
  "system_yaml": "$(cat /srv/catalog/systems/test.yaml | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')",
  "environment": "dev",
  "target": "dev"
}
JSON
)" \
  https://${AGENCY_DOMAIN}/v1/deploys
```

`POST /v1/deploys` returns 201
with a plan preview; the row is in
`pending` state. An admin can then
`POST /v1/deploys/{id}/approve`
and `POST /v1/deploys/{id}/applied`
to walk it through the 2.2.0
state machine.

### 2.8 — backup

The `agency-data` named volume
holds the SQLite database. To
snapshot:

```bash
docker run --rm -v agency-server_agency-data:/from -v $PWD:/to \
  alpine cp /from/data/agency.db /to/agency-$(date +%Y%m%d).db
```

Stop the stack before restoring a
snapshot; Caddy health checks will
fail briefly while `docker compose
up` re-attaches the new database.

### 2.9 — upgrade

```bash
cd /opt/agency-server/repo
git pull --ff-only
docker compose build --pull
docker compose up -d
```

The migration sequence is in
`crates/core/migrations/`. The
`db.migrate()` call in
`boot_default_state()` runs every
SQL file in numeric order on each
boot; additive migrations are
safe across restarts.

## 3. [B] Native (no Docker) systemd path

### 3.1 — system user + dirs

```bash
sudo useradd -r -s /bin/false -d /var/lib/agency agency
sudo mkdir -p /var/lib/agency/data /etc/agency
sudo chown -R agency:agency /var/lib/agency
sudo chmod 0750 /var/lib/agency
```

### 3.2 — install the binaries

```bash
sudo install -m 0755 /opt/agency-server/repo/target/release/agency-server /usr/local/bin/agency-server
sudo install -m 0755 /opt/agency-server/repo/target/release/agency         /usr/local/bin/agency
# Optional: install `agency` (the CLI) on operator workstations
# pointing at https://agency.example.com.
```

### 3.3 — install the systemd unit

```bash
sudo install -m 0644 /opt/agency-server/repo/packaging/systemd/agency-server.service \
                 /etc/systemd/system/agency-server.service
sudo systemctl daemon-reload
```

### 3.4 — operator secrets

Same as [A] step 2.3:

```bash
sudo tee /etc/agency/agency.env >/dev/null <<'EOF'
AGENCY_VAULT_PASSPHRASE=replace-me-with-a-32-byte-random-string
AGENCY_OIDC_ISSUER=https://idp.example.com/
AGENCY_OIDC_CLIENT_ID=...
AGENCY_OIDC_CLIENT_SECRET=...
AGENCY_OIDC_REDIRECT_URI=https://agency.example.com/v1/auth/oidc/callback
AGENCY_OIDC_JWKS_URL=https://idp.example.com/.well-known/jwks.json
AGENCY_OIDC_MOCK=0
EOF
sudo chmod 0600 /etc/agency/agency.env
```

### 3.5 — start + enable

```bash
sudo systemctl enable --now agency-server
sudo systemctl status agency-server
journalctl -u agency-server -f
```

The first-boot token message goes
to the journal:

```bash
sudo journalctl -u agency-server | grep 'token='
```

### 3.6 — front with caddy (still recommended for TLS)

Caddy on the same host as a
systemd-managed server is fine;
just point the reverse proxy at
`127.0.0.1:8080`:

```caddyfile
agency.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Install caddy from
[the official repo](https://caddyserver.com/docs/install) and drop the
above into `/etc/caddy/Caddyfile`,
then `systemctl reload caddy`.

### 3.7 — backup

```bash
sudo systemctl stop agency-server
sudo install -m 0640 /var/lib/agency/data/agency.db \
                 /var/backups/agency-$(date +%Y%m%d).db
sudo systemctl start agency-server
```

## 4. Verifying the deploy

After either path, the same smoke
test suite applies:

```bash
TOKEN=$(cat /var/lib/agency/server.token)   # or via docker compose exec

# 1. health
curl -kfsS https://agency.example.com/v1/health

# 2. audit (the seed admin user is
# the only principal in the DB)
curl -kfsS -H "Authorization: Bearer $TOKEN" \
  https://agency.example.com/v1/audit | jq

# 3. create a target + plan a deploy
#    (see 2.7 above)
```

## 5. What is NOT yet production-grade

These are 3.x-deferred in the source
TZ; track in the `Deferred to later
milestones` section of the README
and in `docs/adr/`:

- **Multi-region / multi-host fleet** — current `targets` table is a registry only; the server does not push to remote machines. A 2.5.0 deploy asks the operator's `agency` CLI to do the on-host work. 3.x is when the server runs the deploy itself.
- **No TLS in the binary** — the binary speaks plain HTTP; TLS is the reverse proxy's job. This is intentional (avoids cert-management in Rust) and matches every other system in the stack (Hermes, Postgres, etc.).
- **No rate-limiting** — `tower::limit` would be straightforward, deferred.
- **No audit-log stream to an external sink** — the audit log is the `audit_log` SQLite table. A 2.5.0 follow-up could add a `tail` endpoint.
- **No OIDC client-side rate-limiting** — `POST /v1/auth/oidc/callback` will hit your IdP with whatever rate the operator throws at it. Add a Caddy rate-limit module if this becomes a problem.

## 6. Troubleshooting

| Symptom                                              | Likely cause                                              | Fix                                                                                              |
|------------------------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `curl: (7) Failed to connect`                        | binary is bound to 127.0.0.1                              | Rebuild with `AGENCY_BIND_IP=0.0.0.0` (or pass `--bind 0.0.0.0`); check 2.9.0 main.rs change     |
| `403 forbidden` on a write endpoint                   | role check is failing                                     | the seed user is `admin` (full perms); new users need `Role::Admin` in `POST /v1/users`         |
| `pending_deploys.target_id NOT NULL` on insert       | 2.5.3 migration not applied                               | check the journal for the migration log; the file `crates/core/migrations/018_*.sql` is the source |
| `AGENCY_VAULT_PASSPHRASE is unset but the secrets table has N row(s)` | fresh install on top of an old DB | set the env var to the passphrase that encrypted the existing rows, or back up + delete `secrets` |
| `unknown signer ...` in `PluginScanner`              | plugin manifest is signed by a key not in `trust.json`   | add the public key to the trust store (see 2.4)                                                |
| `unsupported alg` on OIDC callback                   | IdP issues a JWT with `alg=HS256` (symmetric)            | the server only accepts RS256/384/512, ES256/384, PS256/384/512 (2.7.7.1)                       |
| `JWKS GET: ...`                                       | `AGENCY_OIDC_JWKS_URL` is unreachable                     | check from inside the container: `docker exec -it agency-server wget -qO- "$AGENCY_OIDC_JWKS_URL"` |
| `git clone: ... 8.3 short paths` on Windows          | cyrillic-username short-path workaround not in effect      | 2.8.1+ honours `dunce::canonicalize`; only affects Windows operator workstations, not VPS deploys |

## 7. See also

- `Dockerfile` — multi-stage build for `agency-server` + `agency`.
- `docker-compose.yml` — agency-server + caddy reverse proxy stack.
- `Caddyfile` — TLS terminator (used by compose).
- `packaging/systemd/agency-server.service` — native unit.
- `CHANGELOG.md` — release notes.
- `TZ_Enterprise_Agent_Deployment_Platform_Enterprise_v2.md` — source spec (gitignored).
- `docs/adr/` — Architecture Decision Records (gitignored).
