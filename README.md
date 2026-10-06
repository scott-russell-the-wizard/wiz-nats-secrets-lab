# Wiz Custom Secret Detection Lab: Programmatic NATS NKeys & JWTs

A dedicated test suite for validating **Wiz Code** and **Wiz CLI (`wizcli`)** custom secret detection capabilities against [NATS Programmatic NKeys and JWTs](https://natsbyexample.com/examples/auth/nkeys-jwts/go/).

---

## 1. Architecture & Wiz Platform Configuration

### Custom Secret Detection Rules (`Policies > Secret Detection Rules`)

| Rule Name | Wiz Rule ID | Type | Severity | Target Platforms | Value Regex | Exclusions |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`sr-nats-nkey-seed`** | `CUSTOM-bde5d1be-61a5-4526-a27b-39de854c5236` | `SAAS_API_KEY` | `CRITICAL` | `CODE`, `CLI` | `(?:NKEY SEED-----+\r?\n\|(?:seed\|Seed\|SEED\|nkey\|NKey\|NKEY)[_A-Za-z0-9]*\s*[:=]\s*["']?)(?P<value>S[OAU]A[A-Z2-7]{55})` | Path: `tests/ignored/.*`<br>Value: `SOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` |
| **`sr-nats-ed25519-jwt`** | `CUSTOM-7f813884-2b4f-4bc5-942b-ea717baa3f15` | `SAAS_API_KEY` | `HIGH` | `CODE`, `CLI` | `\b(?P<value>eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86})\b` | Path: `tests/ignored/.*` |

### CI/CD Secrets Scan Policy (`Policies > CI/CD Policies`)

* **Policy Name**: `sr-nats-custom-secrets-policy` (`ID: 8893bd02-14c0-4b34-b296-af8791af1f37`)
* **Scanner Scope**: Secrets (`CICDScanPolicyParamsSecrets`)
* **Severity Threshold**: `MEDIUM` (blocks/alerts on `MEDIUM`, `HIGH`, and `CRITICAL` secret findings)
* **Count Threshold**: `1`
* **Path Allowlist**: `tests/ignored/**`

---

## 2. Repository Test Matrix

| File Path | Contents | Expected Scan Behavior |
| :--- | :--- | :--- |
| `cmd/nkeys-gen/main.go` | Go program from `natsbyexample.com/examples/auth/nkeys-jwts/go/` with hardcoded Operator Seed (`SOAL...`), Account Seed (`SAAL...`), and Account JWT (`eyJ0eXAi...`) | **DETECTED** (`2x sr-nats-nkey-seed`, `1x sr-nats-ed25519-jwt`) |
| `creds/my-user.creds` | Decorated NATS `.creds` file containing `-----BEGIN NATS USER JWT-----` and `-----BEGIN USER NKEY SEED-----` (`SUAL...`) | **DETECTED** (`1x sr-nats-nkey-seed`, `1x sr-nats-ed25519-jwt`) |
| `config/nats-secrets.conf` | Env/config file with Operator/Account/User public keys (`O...`, `A...`, `U...`), seeds (`SO...`, `SA...`, `SU...`), JWTs (`eyJ...`), and placeholder `SOAAAA...` | **DETECTED** on real dummy seeds/JWTs; **IGNORED** on public keys & excluded placeholder `SOAAAA...` |
| `tests/ignored/dummy.creds` | Decorated `.creds` file placed inside `tests/ignored/` | **IGNORED** via `excludePaths` (`tests/ignored/.*`) |

---

## 3. Quickstart & Usage

### Prerequisites
Copy `.env.example` to `.env` and populate your Wiz Service Account credentials:
```bash
cp .env.example .env
```

### Run Local Wiz CLI Scan
```bash
chmod +x scripts/run-wiz-scan.sh
./scripts/run-wiz-scan.sh
```

### Verify Rules, Policy & Scan Results via Wiz GraphQL API
```bash
python3 scripts/verify_wiz_api.py
```

### GitHub Actions CI/CD Pipeline
The workflow at `.github/workflows/wiz-secrets-scan.yml` runs automatically on `push`, `pull_request`, or manual `workflow_dispatch`, executing `wizcli scan dir .` against the repository with `--policies "sr-nats-custom-secrets-policy"`.

