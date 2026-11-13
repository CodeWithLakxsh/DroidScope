# Installation

DroidScope runs on macOS, Linux and Windows. Static analysis works everywhere
its dependencies do; dynamic analysis has platform-specific requirements
covered in [dynamic-analysis.md](dynamic-analysis.md).

## What you actually need

| Component | Required for | Notes |
|---|---|---|
| Python 3.12+ | Everything | 3.12 and 3.13 are tested in CI |
| [uv](https://docs.astral.sh/uv/) | Install | `pip` works too; `uv` is much faster |
| Node.js 20+ | The web interface | Not needed for the CLI |
| JRE 17+ | JADX, apktool, Ghidra | These are JVM tools |
| JADX | Source decompilation | Without it, source rules cannot run |
| apktool | Smali and resource decoding | Optional; improves coverage |
| yara-python | YARA scanning | `pip install yara-python` |
| Ghidra | Native decompilation (full profile) | Large; optional |
| Android SDK | Building fixtures, dynamic analysis | Optional |
| Docker | Containerised deployment | Optional |

Run `droidscope doctor` at any point: it reports what is present, what is
missing, what each missing tool would enable, and how to install it.

## Quick install

```bash
git clone https://github.com/CodeWithLakxsh/DroidScope.git
cd droidscope
make setup
make doctor
```

## Platform notes

### macOS

```bash
brew install python@3.12 node openjdk@17 uv
brew install jadx apktool yara
brew install --cask android-platform-tools   # adb
brew install ghidra                          # optional, large
```

If `java` is not found afterwards, Homebrew's `openjdk` is keg-only:

```bash
sudo ln -sfn /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk \
             /Library/Java/JavaVirtualMachines/openjdk-17.jdk
```

Apple silicon is fully supported; the Android emulator uses arm64 system images.

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv nodejs npm default-jre-headless unzip
curl -LsSf https://astral.sh/uv/install.sh | sh

JADX_VERSION=1.5.1
curl -fsSL -o /tmp/jadx.zip \
  "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
sudo mkdir -p /opt/jadx && sudo unzip -q /tmp/jadx.zip -d /opt/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

sudo apt install -y apktool yara
```

For the emulator, KVM must be available: `ls /dev/kvm` and add yourself to the
`kvm` group.

### Windows 11

The backend is most reliable under WSL2 — follow the Linux instructions inside
it. For a native install:

```powershell
winget install Python.Python.3.12 OpenJS.NodeJS.LTS EclipseAdoptium.Temurin.17.JDK
winget install astral-sh.uv
```

Then download JADX and apktool manually and add them to `PATH`, or point
DroidScope at them:

```powershell
$env:DROIDSCOPE_JADX_PATH = "C:\tools\jadx\bin\jadx.bat"
```

The emulator needs WHPX (Windows Hypervisor Platform) or Hyper-V enabled.

## Configuration

Copy [`.env.example`](../../.env.example) to `.env`. Every value has a safe
default; an empty file works for local use.

The settings that matter most:

| Setting | Default | Change it when |
|---|---|---|
| `DROIDSCOPE_DATA_DIR` | `~/.droidscope` | You want artifacts elsewhere |
| `DROIDSCOPE_DATABASE_URL` | SQLite in the data dir | More than one worker, or a shared deployment |
| `DROIDSCOPE_REQUIRE_AUTH` | `false` | **Always, for a shared deployment** |
| `DROIDSCOPE_MAX_UPLOAD_BYTES` | 512 MB | You analyse larger APKs |
| `DROIDSCOPE_ANALYSIS_CONCURRENCY` | 2 | You have more cores and memory |
| `DROIDSCOPE_DYNAMIC_ANALYSIS_ENABLED` | `false` | You have an isolated test device |

## Running

### Local development

```bash
make dev     # API :8000, worker, UI :5173
```

Or separately:

```bash
droidscope init-db
droidscope server          # terminal 1
droidscope worker          # terminal 2
cd frontend && npm run dev # terminal 3
```

### Docker

```bash
docker compose up --build    # http://localhost:8080
```

PostgreSQL and Redis are not published to the host. Set `POSTGRES_PASSWORD`
and, for anything shared, `DROIDSCOPE_API_KEY` and
`DROIDSCOPE_REQUIRE_AUTH=true`.

### Production notes

- Use PostgreSQL, not SQLite, once more than one worker runs.
- Put the API behind a reverse proxy that terminates TLS.
- Run `alembic upgrade head` on deploy (the compose backend does this).
- Set `DROIDSCOPE_LOG_JSON=true` if you ship logs anywhere.
- Scale workers horizontally; job claiming is atomic.

## Verifying the install

```bash
droidscope doctor
droidscope rules validate      # should report 37 pattern rules, 8 YARA rules
make fixtures                  # needs the Android SDK
droidscope analyze tests/fixtures/vulnerable-app.apk --profile quick
```

The last command should report findings including `DS-MANIFEST-003`
(debuggable). If it reports none, something is wrong — check `doctor` output.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md).
