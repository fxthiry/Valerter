# Getting Started

This guide covers installing and running Valerter for the first time.

## Requirements

- **VictoriaLogs** instance (v1.0+) accessible via HTTP
- **Linux** (amd64 or arm64) - systemd recommended for production

## Installation

### Debian/Ubuntu (.deb)

```bash
# Download and install the latest release
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter_latest_amd64.deb
sudo dpkg -i valerter_latest_amd64.deb
```

For ARM64 systems, use `valerter_latest_arm64.deb` instead.

The .deb package will:
1. Install binary to `/usr/bin/valerter`
2. Create `valerter` system user and group
3. Install systemd service to `/lib/systemd/system/`
4. Create config directory `/etc/valerter/` with example configuration

### Static Binary (any Linux)

For non-Debian systems, containers, or quick testing:

```bash
# Download (x86_64, or aarch64 for ARM)
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter-linux-x86_64.tar.gz

# Optional: Verify checksum
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/checksums-sha256.txt
sha256sum -c checksums-sha256.txt --ignore-missing

# Extract and run
tar -xzf valerter-linux-x86_64.tar.gz
cd valerter-linux-x86_64
./valerter --validate -c config.example.yaml
./valerter -c config.example.yaml
```

The tarball contains a statically-linked musl binary that runs on any Linux distribution (Alpine, Arch, RHEL, containers, etc.). For systemd integration, see [`systemd/valerter.service`](https://github.com/fxthiry/valerter/blob/main/systemd/valerter.service) in the repository.

### From Source

```bash
# Clone repository
git clone https://github.com/fxthiry/valerter.git
cd valerter

# Build static binary (requires musl target)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Run directly
./target/x86_64-unknown-linux-musl/release/valerter -c config/config.example.yaml

# Or copy binary to PATH
sudo cp ./target/x86_64-unknown-linux-musl/release/valerter /usr/local/bin/
```

## Post-Installation

### 1. Configure

Edit the configuration file:

```bash
sudo vim /etc/valerter/config.yaml
```

Minimal configuration:

```yaml
victorialogs:
  url: "http://victorialogs:9428"

notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/your-webhook-id"

defaults:
  throttle:
    count: 5
    window: 60s

templates:
  default_alert:
    title: "{{ title | default('Alert') }}"
    body: "{{ body }}"
    body_html: "<p>{{ body }}</p>"

rules:
  - name: "error_alert"
    query: '_stream:{app="myapp"} level:error'
    parser:
      regex: '(?P<message>.*)'
    notify:
      template: "default_alert"
      destinations:
        - "mattermost-ops"
```

### 2. Validate Configuration

```bash
valerter --validate
```

### 3. Start the Service

```bash
sudo systemctl start valerter
sudo systemctl enable valerter  # Enable at boot
```

### 4. Verify

```bash
# Check status
sudo systemctl status valerter

# View logs
journalctl -u valerter -f
```

## Updating

### .deb Package

```bash
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter_latest_amd64.deb
sudo dpkg -i valerter_latest_amd64.deb
sudo systemctl restart valerter
```

**Note:** Configuration is preserved during upgrades - dpkg will prompt if you've modified `/etc/valerter/config.yaml`.

## Uninstalling

```bash
sudo dpkg -r valerter        # Remove (keeps config)
sudo dpkg --purge valerter   # Purge (removes everything)
```

## Next Steps

- [Configuration Reference](configuration.md) - Full configuration options
- [Notifiers](notifiers.md) - Configure Mattermost, Email, Webhook
- [Metrics](metrics.md) - Prometheus monitoring
