# Wiz Custom Secret Detection Lab: Okta API/Super Admin Tokens, Broader JWTs & NATS NKeys/JWTs

A comprehensive validation test suite for evaluating **Wiz Code** and **Wiz CLI (`wizcli`)** native vs. custom secret detection capabilities against open-source scanners (**Better Leaks / Gitleaks**).

All credentials, keys, and tokens in this repository are **100% synthetic, cryptographically well-formed, high-entropy test fixtures** and are completely non-functional.

---

## 1. Wiz Custom Secret Detection Rules Under Validation (`Policies > Secret Detection Rules`)

| Rule Category | Wiz Rule Name / ID | Type | Severity | Target Platforms | Wiz Custom Secret Detection Regex (`(?P<value>...)`) | Exclusions |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Broader JWT** | `sr-generic-signed-jwt` *(Custom)* | `SAAS_API_KEY` | `HIGH` | `CODE`, `CLI` | `\b(?P<value>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b` | Path: `tests/ignored/.*` |
| **NATS JWT** | `sr-nats-ed25519-jwt`<br>(`CUSTOM-7f813884-2b4f-4bc5-942b-ea717baa3f15`) | `SAAS_API_KEY` | `HIGH` | `CODE`, `CLI` | `\b(?P<value>eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86})\b` | Path: `tests/ignored/.*` |
| **NATS NKey** | `sr-nats-nkey-seed`<br>(`CUSTOM-bde5d1be-61a5-4526-a27b-39de854c5236`) | `SAAS_API_KEY` | `CRITICAL` | `CODE`, `CLI` | `(?:NKEY SEED-----+\r?\n\|(?:seed\|Seed\|SEED\|nkey\|NKey\|NKEY)[_A-Za-z0-9]*\s*[:=]\s*["']?)(?P<value>S[OAU]A[A-Z2-7]{55})` | Path: `tests/ignored/.*`<br>Value: `SOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` |
| **Okta SSWS Token** | `sr-okta-ssws-token` *(Custom)* | `SAAS_API_KEY` | `CRITICAL` | `CODE`, `CLI` | `(?:(?i:okta\|ssws)[_A-Za-z0-9-]*\s*(?:[:=]|\s)\s*["']?)(?P<value>00[A-Za-z0-9_-]{40})\b` | Path: `tests/ignored/.*` |

### CI/CD Secrets Scan Policy (`Policies > CI/CD Policies`)

* **Policy Name**: `sr-nats-custom-secrets-policy` (`ID: 8893bd02-14c0-4b34-b296-af8791af1f37`)
* **Scanner Scope**: Secrets (`CICDScanPolicyParamsSecrets`)
* **Severity Threshold**: `MEDIUM` (blocks/alerts on `MEDIUM`, `HIGH`, and `CRITICAL` secret findings)
* **Count Threshold**: `1`
* **Path Allowlist**: `tests/ignored/**`, `**/.env`

---

## 2. Test Manifest & Expected Detection Results

### 2.1 Okta Super Admin / API Tokens (`00[A-Za-z0-9_-]{40}`) & OAuth 2.0 Private Key JWK

| File Path | Secret Type | Line(s) | Exact Code / Config Context | Validated Rule / Detection Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `config/okta-secrets.conf` | Okta SSWS API Token (`1a`) | `12` | `OKTA_API_TOKEN="003a01c34BgVoHHXLm_C2QPIvQDgJvo9kWHTKKhEA9"` | **DETECTED** by **Okta SSWS Token** custom rule (`(?i:okta\|ssws)...`) |
| `config/okta-secrets.conf` | Okta Super Admin SSWS Token (`1a`) | `13` | `OKTA_SUPER_ADMIN_TOKEN="00Ig5d3fWCoFzi9qC6H9gyNtrk6kNBhvYyd7K_S5So"` | **DETECTED** by **Okta SSWS Token** custom rule |
| `config/okta-secrets.conf` | Okta Client SSWS Token (`1a`) | `14` | `OKTA_CLIENT_TOKEN="001j-Quzq12FxlNnernuVMoSZnEv9Y-KhqR1pPzX24"` | **DETECTED** by **Okta SSWS Token** custom rule |
| `config/okta-secrets.conf` | Okta Provisioning SSWS Token (`1a`) | `17` | `export OKTA_PROVISIONING_API_TOKEN="00k9XpL2mQ8vR4tW7yN1bC5fH3jD6gS0aE9wZ4uM8r"` | **DETECTED** by **Okta SSWS Token** custom rule |
| `src/okta_admin_client.py` | Okta SSWS Header in Python (`1b`) | `18`, `25` | `"Authorization": "SSWS 00IvJOAuPE5UTK1MrWoZU7eVAtpvmnQTV1qFBKv_gD"` + `Authorization: SSWS 00...` paired with `https://acme-admin.okta.com/api/v1/users` | **DETECTED** by **Okta SSWS Token** custom rule (`SSWS 00...`) |
| `src/okta_admin_client.ts` | Okta SSWS Header in TypeScript (`1b`) | `16`, `25` | `"Authorization: SSWS 00PV5ugzm7FPHxG9Xf4JWVZYz7YhEDJ9waSh-dV76j"` paired with `https://acme-admin.okta.com/api/v1/users` | **DETECTED** by **Okta SSWS Token** custom rule (`SSWS 00...`) |
| `src/okta_curl_requests.sh` | Okta SSWS Header in cURL (`1b`) | `13` | `-H "Authorization: SSWS 00Zgd-th0RKjPJg18yiD7erfvFXAo9KmG7USRF-qbN"` paired with `https://acme-admin.okta.com/api/v1/users` | **DETECTED** by **Okta SSWS Token** custom rule (`SSWS 00...`) |
| `terraform/okta_provider.tf` | Terraform `provider "okta"` (Multi-line) (`1c`) | `19` | `provider "okta" { org_name = "acme-admin" base_url = "okta.com" api_token = "00nQqbxPjvHAGbNzDFW7SvJcJrkr6hDN7ZgA_lVShh" }` | **CONTEXT GAP TEST**: Key name is `api_token` (no `okta` on line 19); requires multi-line/block proximity or unanchored `00[A-Za-z0-9_-]{40}` |
| `terraform/okta_provider.tf` | Terraform `provider "okta"` (Single-line) (`1c`) | `23` | `provider "okta" { alias = "dr" org_name = "acme-admin-dr" base_url = "okta.com" api_token = "00UHhUpvWAI96Gmgqi8o0HxzxS7-YU4w8h-6M-P31C" }` | **CONTEXT GAP TEST**: `okta` appears in `provider "okta"` and `base_url = "okta.com"`, while attribute is `api_token = "00..."` |
| `terraform/okta_provider.tf` | Terraform `locals` (`okta_api_token`) (`1c`) | `27` | `okta_api_token = "00Mc7hHqUI0_UK8ecR9TCOrFf7J-b2GJLAVhWRFpvC"` | **DETECTED** by **Okta SSWS Token** custom rule (`okta_api_token = "00..."`) |
| `config/unlabeled-secrets.yaml` | Unlabeled Raw `00...` Tokens in YAML (`1d`) | `7`, `8` | `super_admin_token: "00U71-g5ar_93ERisCHspJ0IosvG76zyQLgf0aLb1D"`<br>`directory_sync_token: "00wR8tY3uI6oP2aS5dF9gH1jK4lZ7xC0vB3nM6qW2e"` | **NEGATIVE / GAP TEST**: No `okta` or `ssws` keyword in key or file; missed by keyword-anchored rules unless raw `\b00[A-Za-z0-9_-]{40}\b` is enabled |
| `config/unlabeled-secrets.json` | Unlabeled Raw `00...` Tokens in JSON (`1d`) | `4`, `5` | `"super_admin_token": "00pL4mK9jN2bV7cX1zQ8wE3rT6yU5iO0aS9dF4gH7k"`<br>`"failover_admin_key": "00qW9eR4tY7uI2oP5aS8dF1gH6jK3lZ0xC7vB4nM9p"` | **NEGATIVE / GAP TEST**: No `okta` or `ssws` keyword in key or file; tests context-dependent vs. raw-pattern detection |
| `creds/okta-service-app-jwk.json` | Okta OAuth 2.0 / OIDC Private Key JWK (`1e`) | `6-19` | RSA 2048-bit Private Key JWK (`"kty": "RSA"`, `"alg": "RS256"`, `"kid": "okta-svc-superadmin-2026-01"`, `"d": "HNhjvVHs..."`, `"p": ...`, `"q": ...`) | **JWK GAP TEST**: Validates whether native scanner flags JSON Web Key private key material (`"kty": "RSA"` with private exponent `"d"`) |

---

### 2.2 Broader / Generic JSON Web Tokens (JWTs) + NATS `ed25519-nkey` JWTs & NKey Seeds

| File Path | Secret Type | Line(s) | Exact Code / Config Context | Validated Rule / Detection Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `config/jwt-tokens.conf` | Standard `HS256` JWT (`2a`) | `8` | `GENERIC_HS256_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3Mi...pmBFT64N05l3L5rR_PdxQifiHV18fP9PtqLkC8NXhnA"` (`{"alg":"HS256","typ":"JWT"}`) | **DETECTED** by **Broader JWT** custom rule (`\beyJ...\b`) |
| `config/jwt-tokens.conf` | Standard `RS256` JWT (`2b`) | `13` | `GENERIC_RS256_JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6...q8lJgl7Bjz..."` (`{"typ":"JWT","alg":"RS256","kid":"..."}`) | **DETECTED** by **Broader JWT** custom rule (validates `typ`-first `eyJ0eXAi...` header ordering) |
| `config/jwt-tokens.conf` | Okta / OIDC Bearer JWT (`2c`) | `18` | `OKTA_OIDC_ACCESS_TOKEN_JWT="eyJraWQiOiJva3RhLXN2Yy1zdXBlcmFkbWlu...rUjrR-4A1B..."` (`iss: "https://acme.okta.com/oauth2/default"`, `scp: ["okta.users.manage", "okta.roles.manage"]`) | **DETECTED** by **Broader JWT** custom rule (validates `kid`-first `eyJraWQi...` header ordering) |
| `config/jwt-tokens.conf` | NATS `ed25519-nkey` JWT (`2d`) | `22` | `NATS_ED25519_NKEY_JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGki...4-kUapoPK_..."` (86-char Ed25519 signature) | **DETECTED** by both **NATS JWT** and **Broader JWT** custom rules |
| `config/jwt-tokens.conf` | NATS NKey Seeds (`SOAA`/`SAAA`/`SUAA`) (`2d`) | `23-25` | `NATS_SYNTHETIC_OPERATOR_SEED="SOAA2EMDFD6R..."`<br>`NATS_SYNTHETIC_ACCOUNT_SEED="SAAAI5TJMUFBL..."`<br>`NATS_SYNTHETIC_USER_SEED="SUAA3NESNVK2V..."` | **DETECTED** by **NATS NKey** custom rule (`S[OAU]A[A-Z2-7]{55}`) |
| `src/jwt_auth_fixtures.py` | `HS256`, `RS256`, Okta OIDC & NATS JWTs + NKey Seeds (`2a-2d`) | `9`, `12`, `15`, `18`, `19-21` | `HS256_SERVICE_JWT`, `RS256_SERVICE_JWT`, `OKTA_BEARER_ACCESS_JWT`, `NATS_ED25519_NKEY_JWT`, `nkey_operator_seed` (`SOAA...`), `nkey_account_seed` (`SAAA...`), `nkey_user_seed` (`SUAA...`) | **DETECTED**: `4x Broader JWT`, `1x NATS JWT`, `3x NATS NKey` |
| `src/okta_admin_client.py` | Okta OIDC Bearer JWT in Python (`2c`) | `31` | `OKTA_OIDC_BEARER_JWT = "eyJraWQiOiJva3RhLXN2Yy1zdXBlcmFkbWlu..."` | **DETECTED** by **Broader JWT** custom rule |
| `src/okta_curl_requests.sh` | Okta OIDC Bearer JWT in cURL (`2c`) | `18` | `-H "Authorization: Bearer eyJraWQiOiJva3RhLXN2Yy1zdXBlcmFkbWlu..."` | **DETECTED** by **Broader JWT** custom rule |
| `cmd/nkeys-gen/main.go` | Go NATS NKey Seeds & Account JWT (`2d`) | `14`, `17`, `20` | `defaultOperatorSeed = "SOALU7..."`, `defaultAccountSeed = "SAALXU..."`, `defaultAccountJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ..."` | **DETECTED**: `2x NATS NKey`, `1x NATS JWT`, `1x Broader JWT` |
| `config/nats-secrets.conf` | NATS Public Keys, Seeds, JWTs & Excluded Placeholder (`2d`) | `10-12`, `15-16`, `19` | `NATS_OPERATOR_SEED`, `NATS_ACCOUNT_SEED`, `NATS_USER_SEED`, `NATS_ACCOUNT_JWT`, `NATS_USER_JWT`, `NATS_EXAMPLE_PLACEHOLDER_SEED` (`SOAAAA...`) | **DETECTED**: `3x NATS NKey`, `2x NATS JWT`, `2x Broader JWT`; **IGNORED** on public keys (`O...`, `A...`, `U...`) and excluded placeholder (`SOAAAA...`) |
| `creds/my-user.creds` | Decorated NATS `.creds` File (`2d`) | `2`, `10` | `-----BEGIN NATS USER JWT-----` (`eyJ0eXAi...`) and `-----BEGIN USER NKEY SEED-----` (`SUALJTG5...`) | **DETECTED**: `1x NATS NKey`, `1x NATS JWT`, `1x Broader JWT` |
| `tests/ignored/dummy.creds` | Ignored Path Fixture | `3`, `7` | Decorated NATS `.creds` file placed inside `tests/ignored/` | **IGNORED** via `excludePaths` (`tests/ignored/.*`) |

---

## 3. Quickstart & Validation Commands

### Validate All Regex Rules Locally Against Repository Fixtures
```bash
python3 scripts/validate_regex_rules.py
```

### Run Local Wiz CLI Scan
```bash
cp .env.example .env
chmod +x scripts/run-wiz-scan.sh
./scripts/run-wiz-scan.sh
```

### Verify Rules, Policy & Scan Results via Wiz GraphQL API
```bash
python3 scripts/verify_wiz_api.py
```
