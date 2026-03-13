# certmesh

Automated TLS certificate lifecycle management for Python 3.10+.

A unified CLI and Python API for managing certificates across **DigiCert CertCentral**, **Venafi Trust Protection Platform**, **HashiCorp Vault PKI**, and **AWS Certificate Manager** (public + private CA).

## Features

- **Multi-provider** -- single tool for DigiCert, Venafi TPP, Vault PKI, and AWS ACM/ACM-PCA
- **Full lifecycle** -- request, list, search, describe, download, renew, revoke, and export certificates
- **Credential security** -- secrets come from Vault or environment variables, never from config files
- **Resilient** -- circuit breakers, exponential-backoff retry, and configurable timeouts on all HTTP calls
- **Configurable** -- layered config: built-in defaults < YAML file < `CM_*` environment variables
- **Typed** -- fully typed with `py.typed` marker; dataclass models for all API responses

## Installation

```bash
pip install certmesh
```

From source:

```bash
git clone https://github.com/api-py/certmesh.git
cd certmesh
pip install -e ".[dev]"
```

**Requires Python 3.10, 3.11, 3.12, or 3.13.**

## Quick Start

```bash
# Show effective config
certmesh config show

# Issue a certificate from Vault PKI
certmesh vault-pki issue --cn myservice.example.com --ttl 720h

# Request a public ACM certificate
certmesh acm request --cn myapp.example.com --validation DNS

# List DigiCert certificates
certmesh digicert list --status issued

# Renew a Venafi TPP certificate
certmesh venafi renew --guid "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

## Configuration

Configuration is layered (lowest to highest precedence):

1. **Built-in defaults** -- sensible defaults for all settings
2. **YAML config file** -- `config/config.yaml` or `--config PATH`
3. **`CM_*` environment variables** -- override any setting

```bash
# Use a .env file
certmesh --env-file .env digicert list

# Override log level
certmesh --log-level DEBUG acm list
```

See [`config/config.yaml`](config/config.yaml) for the full annotated reference and [`.env.example`](.env.example) for all environment variables.

### Authentication

| Provider | Method |
|----------|--------|
| **Vault** | AppRole (default), LDAP, or AWS IAM |
| **DigiCert** | API key from `CM_DIGICERT_API_KEY` or Vault KV |
| **Venafi** | OAuth2 or LDAP; credentials from `CM_VENAFI_USERNAME`/`CM_VENAFI_PASSWORD` or Vault KV |
| **AWS ACM** | Standard boto3 credential chain (IAM role, env vars, `~/.aws/credentials`) |

Credentials are resolved env-first, Vault-fallback. Vault is only contacted when needed.

## CLI Reference

Exit codes: `0` = success, `1` = config/auth error, `2` = cert operation error, `3` = unexpected error.

### DigiCert CertCentral

```bash
certmesh digicert list     [--status TEXT] [--limit INT]
certmesh digicert search   [--cn TEXT] [--serial TEXT] [--status TEXT] [--product TEXT]
certmesh digicert describe --cert-id INT
certmesh digicert order    --cn TEXT [--san TEXT ...]
certmesh digicert download --cert-id INT --key-file PATH
certmesh digicert revoke   --cert-id INT|--order-id INT [--reason CHOICE] [--comments TEXT]
certmesh digicert duplicate --order-id INT --csr-file PATH [--cn TEXT] [--san TEXT ...]
```

### Venafi TPP

```bash
certmesh venafi list       [--limit INT] [--offset INT]
certmesh venafi search     [--cn TEXT] [--san TEXT]
certmesh venafi describe   --guid TEXT
certmesh venafi request    --policy-dn TEXT --cn TEXT [--san TEXT ...] [--client-csr]
certmesh venafi renew      --guid TEXT
certmesh venafi renew-bulk --guid-file PATH
certmesh venafi revoke     --dn TEXT|--thumbprint TEXT [--reason INT] [--disable]
certmesh venafi download   --guid TEXT
```

### HashiCorp Vault PKI

```bash
certmesh vault-pki issue   --cn TEXT [--san TEXT ...] [--ip-san TEXT ...] [--ttl TEXT] [--output-dir PATH]
certmesh vault-pki sign    --cn TEXT --csr-file PATH [--san TEXT ...] [--ttl TEXT] [--output-dir PATH]
certmesh vault-pki list
certmesh vault-pki read    --serial TEXT
certmesh vault-pki revoke  --serial TEXT
```

### AWS ACM (Public Certificates)

```bash
certmesh acm request           --cn TEXT [--san TEXT ...] [--validation DNS|EMAIL] [--key-algorithm TEXT] [--region TEXT]
certmesh acm list              [--status TEXT ...] [--region TEXT]
certmesh acm describe          --arn TEXT [--region TEXT]
certmesh acm export            --arn TEXT --passphrase [--output-dir PATH] [--region TEXT]
certmesh acm renew             --arn TEXT [--region TEXT]
certmesh acm delete            --arn TEXT [--region TEXT]
certmesh acm validation-records --arn TEXT [--region TEXT]
certmesh acm wait              --arn TEXT [--region TEXT]
```

### AWS ACM Private CA

```bash
certmesh acm-pca issue   --ca-arn TEXT --csr-file PATH [--validity-days INT] [--signing-algorithm TEXT] [--region TEXT]
certmesh acm-pca get     --ca-arn TEXT --cert-arn TEXT [--region TEXT]
certmesh acm-pca revoke  --ca-arn TEXT --cert-arn TEXT --cert-serial TEXT [--reason CHOICE] [--region TEXT]
certmesh acm-pca list    --ca-arn TEXT [--region TEXT]
```

### Config Management

```bash
certmesh config show       # Display effective merged config (secrets redacted)
certmesh config validate   # Validate config; exits 0 on success, 1 on failure
```

## Architecture

```
certmesh/
  cli.py               -- Click CLI (entry point: certmesh.cli:cli)
  settings.py           -- Layered config: defaults -> YAML -> env vars
  credentials.py        -- Env-first, Vault-fallback secret resolution
  vault_client.py       -- Vault auth + KV v2 + PKI engine
  digicert_client.py    -- DigiCert CertCentral API v2
  venafi_client.py      -- Venafi TPP API (OAuth2 + LDAP)
  acm_client.py         -- AWS ACM + ACM-PCA (boto3)
  certificate_utils.py  -- Key gen, CSR, PKCS#12, bundle assembly, persistence
  circuit_breaker.py    -- Thread-safe CLOSED/OPEN/HALF_OPEN state machine
  exceptions.py         -- Full exception hierarchy
```

### Certificate Output

Issued certificates can be persisted to:

- **Filesystem** -- PEM files with private keys written mode `0600`
- **Vault KV v2** -- certificate material stored as a versioned secret
- **Both** -- simultaneous filesystem + Vault storage

Configured per-provider via `output.destination` (`filesystem`, `vault`, or `both`).

## Development

```bash
# Clone and install
git clone https://github.com/api-py/certmesh.git
cd certmesh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v --cov=certmesh

# Lint and format
ruff check src/ tests/
ruff format src/ tests/
```

### Test Suite

- **398 tests** across 10 test modules
- **87%+ coverage** (80% minimum enforced in CI)
- Tests use `pytest`, `pytest-mock`, `responses`, `moto`, and `freezegun`

### CI

GitHub Actions runs on every push and PR:

| Job | Matrix | Description |
|-----|--------|-------------|
| **lint** | Python 3.10 - 3.13 | `ruff check` + `ruff format --check` |
| **test** | Python 3.10 - 3.13 | `pytest` with coverage |
| **build** | Python 3.12 | `python -m build` |

## License

MIT -- see [LICENSE](LICENSE) for details.
