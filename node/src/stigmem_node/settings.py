from datetime import datetime
from typing import Annotated

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="STIGMEM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: str = "stigmem.db"
    host: str = "0.0.0.0"  # noqa: S104  # nosec B104 — overridable via STIGMEM_HOST
    port: int = 8765
    # Optional stable node identity for deterministic local/CI federation fixtures.
    # When unset, the node creates and persists a stigmem:node:<uuid> identity.
    node_id: str = ""
    node_url: str = "http://localhost:8765"
    log_level: str = "info"
    cors_allowed_origins: Annotated[list[str], NoDecode] = []
    cors_allowed_origin_regex: str | None = None
    cors_allow_credentials: bool = True
    cors_dev_localhost: bool = False

    # When True (default), every request must carry a valid Bearer token.
    # Set to False only for local development / single-operator installs.
    auth_required: bool = True
    # Static API-key lifecycle controls. 0 disables max-age enforcement.
    api_key_max_age_days: int = 90
    api_key_expiring_soon_days: int = 30
    legacy_sha256_accept_until: datetime | None = None

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _parse_cors_allowed_origins(cls, v: object) -> list[str]:
        if v is None or v == "":
            return []
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return v  # type: ignore[return-value]

    # Federation — Phase 3 (spec §6)
    federation_enabled: bool = False
    # Base64url Ed25519 keypair. If both are empty, auto-generated and stored in node_meta.
    federation_pubkey: str = ""
    federation_privkey: str = ""
    # Pull replication interval in seconds (spec §6.3); advisory pull_interval_s
    # from peer overrides this.
    federation_pull_interval_s: int = 30
    federation_push_enabled: bool = False
    # Explicit dev/test escape hatch for federation without mTLS. Production
    # federation should leave this false and configure STIGMEM_TLS_* instead.
    federation_insecure: bool = False
    # Additional acknowledgement for local Docker/dev networks whose service DNS
    # names are not loopback. Never set in production.
    local_dev_allow_insecure_non_loopback: bool = False
    # Nonce window: how long (seconds) a nonce is kept to detect replays
    # (spec §6.6, default 5 min).
    federation_nonce_window_s: int = 300
    # Clock-skew leeway for peer-token exp/iat/nbf claim checks.
    peer_token_leeway_s: int = 30
    # Maximum accepted remote HLC skew for federated fact ingest. Future skew is
    # strict by default because it can advance local logical time; past skew is a
    # wider archival bound and may be set to 0 for one-off historical backfills.
    federation_hlc_max_future_skew_s: int = 300
    federation_hlc_max_past_skew_s: int = 2_592_000
    # Allow team-scoped facts to cross federation boundaries
    # (must be explicitly enabled; audit-logged).
    federation_allow_team: bool = False

    # Decay sweeper (Phase 6, spec §decay)
    # 0 = disabled; positive = decay non-expiring facts older than N seconds
    # when sweep runs without explicit ttl_seconds
    decay_ttl_seconds: int = 0
    # 0.0 = disabled; positive = decay facts below this confidence when sweep
    # runs without explicit min_confidence
    decay_min_confidence: float = 0.0

    # Track C / C1: require Ed25519 attestation on all fact assertions.
    # When True, POST /v1/facts must include a valid attestation token.
    # Defaults to False for backward compatibility.
    attestation_required: bool = False

    # OIDC bridge (Track B / B3): human identity → scoped API keys.
    # Set oidc_enabled=true and configure the remaining fields to activate.
    oidc_enabled: bool = False
    # IdP issuer URL; discovery doc fetched from {issuer_url}/.well-known/openid-configuration
    oidc_issuer_url: str = ""
    # client_id expected in the id_token's "aud" claim
    oidc_audience: str = ""
    # lifetime of issued API keys in hours (default 8 h working-day session)
    oidc_token_ttl_hours: int = 8
    # Accepted OIDC id_token signing algorithms. Operators can narrow this list.
    oidc_id_token_algorithms: list[str] = ["RS256", "ES256", "PS256", "EdDSA"]
    # comma-separated list of allowed email domains; empty = allow any
    oidc_allowed_domains: str = ""

    # Async job threshold (spec §14.5 / §15.4): scopes with more facts than this
    # trigger the async 202 path. Override in tests to force async path at small scale.
    async_job_threshold: int = 100_000

    # Source attestation mode (legacy compatibility field).
    # Source-attestation runtime behavior is gated by the experimental
    # stigmem-plugin-source-attestation package. Default installs keep this off.
    source_attestation_mode: str = "off"

    # Rate limiting for hosted offering (per API key, sliding 1-hour window).
    # 0 = disabled.
    rate_limit_write_per_hour: int = 1000
    rate_limit_read_per_hour: int = 5000
    rate_limit_disabled_ack: bool = False

    # F-AVAIL-1: ingest size caps (DoS protection). 0 disables the cap.
    max_request_body_bytes: int = 1_048_576  # 1 MiB hard cap on any request body
    max_fact_value_bytes: int = 262_144  # 256 KiB cap on a single fact value

    # Storage backend (Phase 8 / 11).
    # "sqlite"   (default) — local SQLite file at db_path.
    # "libsql"             — libSQL / Turso; uses db_path as the local replica
    #                        file; set libsql_url + libsql_auth_token for
    #                        embedded-replica sync with Turso.
    # "postgres"           — PostgreSQL; set pg_dsn to a libpq connection string.
    storage_backend: str = "sqlite"
    # Turso database endpoint, e.g. "libsql://my-db.turso.io"
    libsql_url: str = ""
    # Turso auth token (from `turso db tokens create`)
    libsql_auth_token: str = ""
    # PostgreSQL connection string, e.g. "postgresql://user:pw@localhost/stigmem"
    pg_dsn: str = ""
    # DATABASE_URL alias (Heroku / PaaS convention); also read from bare DATABASE_URL env var.
    database_url: str = ""
    # PostgreSQL schema for all tables (default: "public").  Use a unique
    # per-test schema to achieve row-level isolation without separate databases.
    pg_schema: str = "public"
    # Connection pool bounds for the Postgres backend.
    postgres_pool_min: int = 2
    postgres_pool_max: int = 10

    # Encryption at rest (Phase 8).
    # "off" (default) — no encryption; plaintext DB (dev-friendly default).
    # "on"            — SQLCipher for SQLite backend; native encryption for libSQL.
    # When "on", exactly one of at_rest_key_passphrase_env / at_rest_key_kms_uri
    # must be set — the node refuses to start otherwise.
    at_rest_encryption: str = "off"
    # Name of the env var whose value is the passphrase (not the passphrase itself).
    # e.g. STIGMEM_AT_REST_KEY_PASSPHRASE_ENV=MY_DB_PASSPHRASE
    at_rest_key_passphrase_env: str = ""
    # KMS URI for raw 32-byte key material. "env://VAR" reads a hex-encoded key
    # from env var VAR. Future schemes: "aws-kms://...", "gcp-kms://...".
    at_rest_key_kms_uri: str = ""

    @field_validator("at_rest_encryption")
    @classmethod
    def _validate_encryption_mode(cls, v: str) -> str:
        if v not in ("on", "off"):
            raise ValueError(f"at_rest_encryption must be 'on' or 'off'; got {v!r}")
        return v

    # Federation Trust — Phase 8 (spec §19)
    # trust_mode controls source-trust scoring and quarantine routing:
    #   "strict"  — trust is computed for all inbound facts; t < 0.2 → quarantine.
    #   "relaxed" — trust is computed but quarantine is not auto-triggered (default).
    #   "off"     — trust not computed; source_trust is null on all facts.
    trust_mode: str = "relaxed"

    # Sanitizer mode (§19.7) applied at recall time:
    #   "block"     — fact excluded, placeholder returned.
    #   "quarantine"— fact moved to quarantine garden.
    #   "warn"      — fact returned with sanitizer_warnings (default).
    #   "off"       — no check (implied by trust_mode=off).
    sanitizer_mode: str = "warn"

    # UUID of the node's designated quarantine garden.
    # Required in strict mode; facts below threshold are rejected with 403 if unset.
    quarantine_garden_id: str = ""

    # Source-trust score weights (§19.4.2).  Must sum to 1.0; deviations are not
    # validated at startup — set incorrectly and t will be out of [0,1] range.
    trust_weight_identity: float = 0.35
    trust_weight_peer_history: float = 0.30
    trust_weight_scope_authority: float = 0.25
    trust_weight_attestation_mode: float = 0.10

    # Path to a newline-delimited file of extra sanitizer regex patterns (§19.7.2).
    sanitizer_extra_patterns_file: str = ""

    # Path to YAML file defining operator auto-trust rules (always_trust / never_trust).
    trust_rules_file: str = ""

    # Plugin signing gate (ADR-011 / PR 4-INF.3).
    # When true, installed entry-point plugins must pass signing verification
    # before registration. Set false only for local development; unsigned plugin
    # loading remains warning- and audit-visible.
    plugin_signing_required: bool = True
    # Required literal acknowledgement before unsigned-plugin loading is allowed.
    plugin_unsigned_ack: str = ""
    # Disable installed entry-point plugin discovery for test and smoke
    # environments that intentionally exercise the default no-plugin node.
    plugin_auto_discovery_enabled: bool = True
    # Comma-separated Sigstore signing identities accepted for production plugin
    # registration when plugin_signing_required=true.
    plugin_trusted_publishers: str = ""
    # Comma-separated signing identities accepted through explicit operator
    # override. Overrides remain audit-visible and are not a substitute for the
    # trusted-publisher allowlist.
    plugin_trust_override_publishers: str = ""

    # Transparency log backend (§19.2.3):
    #   "local"  — append-only JSONL file with hash chain (default, no external deps).
    #   "rekor"  — Sigstore Rekor REST API.
    #   "off"    — no TL submission; inclusion proofs are never verified.
    tl_backend: str = "local"
    tl_local_path: str = "stigmem_tl.jsonl"
    tl_rekor_url: str = "https://rekor.sigstore.dev"
    fact_chain_checkpoint_interval: int = 1000
    fact_chain_checkpoint_max_age_s: int = 60
    fact_chain_checkpoint_retry_s: int = 60

    # Capability token signing — spec §19.3.2 (C-SEC-1).
    # Base64url-encoded raw 32-byte Ed25519 seed used to sign capability tokens and
    # revocation events. If empty, token signing is skipped and verify_token() will
    # reject all tokens (dev/test nodes that don't participate in trust federation).
    node_private_key: str = ""

    @field_validator("node_private_key")
    @classmethod
    def _validate_node_private_key(cls, v: str) -> str:
        if not v:
            return v
        import base64

        padded = v + "=" * (-len(v) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
        except Exception as exc:
            raise ValueError(f"node_private_key is not valid base64url: {exc}") from exc
        if len(raw) != 32:
            raise ValueError(f"node_private_key must decode to exactly 32 bytes; got {len(raw)}")
        return v

    # -------------------------------------------------------------------------
    # Embeddings — Phase 9 (spec §20 / design memo §2)
    # -------------------------------------------------------------------------
    # Set embed_enabled=true to activate sqlite-vec integration.
    # When false (default), no extension is loaded and no embeddings are stored.
    embed_enabled: bool = False

    # "local"  — Ollama HTTP API (default); requires a running Ollama instance.
    # "openai" — OpenAI embeddings API; requires OPENAI_API_KEY (or the env var
    #            named by embed_openai_api_key_env).
    # "stub"   — deterministic test stub; no external dependencies.
    embed_model_provider: str = "local"

    # Model identifier passed to the provider.
    # Local default:  "nomic-embed-text-v1.5" (768-dim, Apache-2.0, runs on laptop).
    # OpenAI default: "text-embedding-3-small" (1536-dim).
    embed_model_id: str = "nomic-embed-text-v1.5"

    # Output dimensionality.  MUST match the model; changing this after the first
    # embedding requires running `stigmem embed reindex` (migration tool).
    embed_dimension: int = 768

    # Ollama base URL (local provider only).
    embed_ollama_url: str = "http://localhost:11434"

    # Name of the env var holding the OpenAI API key (openai provider only).
    embed_openai_api_key_env: str = "OPENAI_API_KEY"

    # Facts with confidence below this threshold have their vec_facts entry
    # deleted during the decay sweep (design memo §2 "Decay interaction").
    embed_tombstone_threshold: float = 0.1

    # Subscription primitive (Phase 9, spec §20)
    # How long (seconds) the replay window extends back from now (default 24 h).
    subscription_replay_s: int = 86400
    # How often (seconds) the background sweep retries pending/failed delivery.
    subscription_delivery_sweep_s: int = 30
    # Consecutive delivery failures before the circuit breaker opens on a subscription.
    subscription_circuit_threshold: int = 10
    # How long (seconds) an event may remain in 'delivering' state before the next
    # ``deliver_pending`` invocation reverts it to 'pending' for redelivery.
    # Guards against crashed workers stranding events.  Must be larger than the
    # worst-case webhook timeout (10 s) by a comfortable margin.
    subscription_claim_timeout_s: int = 300
    # F-AVAIL-3: cap on active subscriptions per (subscriber_identity, tenant).
    # 0 disables the cap. Default is generous; raise for high-fan-out operators.
    max_subscriptions_per_principal: int = 1000

    # -------------------------------------------------------------------------
    # mTLS Federation Transport — Phase 12 (spec §22.1)
    # -------------------------------------------------------------------------
    # Path to the node's PEM-encoded X.509 certificate for mTLS federation.
    # When tls_cert_path + tls_key_path are both set, mTLS is activated:
    # the uvicorn server requires client certs and the pull client presents this
    # cert to peers.  Opt-out is only permitted for localhost deployments
    # (set host to "localhost" / "127.0.0.1" / "::1" and leave paths empty).
    tls_cert_path: str = ""
    # Path to the node's PEM-encoded private key corresponding to tls_cert_path.
    tls_key_path: str = ""
    # Path to a PEM CA bundle used to verify peer certificates.
    # Required when tls_cert_path + tls_key_path are configured.
    tls_ca_bundle: str = ""

    @model_validator(mode="after")
    def _require_ca_bundle_for_mtls(self) -> "Settings":
        if self.tls_cert_path and self.tls_key_path and not self.tls_ca_bundle:
            raise ValueError(
                "STIGMEM_TLS_CA_BUNDLE is required when mTLS is enabled "
                "(STIGMEM_TLS_CERT_PATH + STIGMEM_TLS_KEY_PATH are set). "
                "Without it, peer certs fall back to the system CA store instead "
                "of the closed federation trust bundle (spec §22.1.2.2)."
            )
        return self

    @property
    def mtls_enabled(self) -> bool:
        """True when mTLS cert + key are configured (non-localhost deployments)."""
        return bool(self.tls_cert_path and self.tls_key_path)

    # -------------------------------------------------------------------------
    # Observability — Phase 13 (spec §23)
    # -------------------------------------------------------------------------
    # Set otel_enabled=true to activate OpenTelemetry tracing.
    # Requires stigmem-node[observability] (opentelemetry-sdk + OTLP exporter).
    otel_enabled: bool = False

    # Service name reported in OTel resource attributes.
    otel_service_name: str = "stigmem-node"

    # OTLP collector base URL (HTTP protocol).
    # e.g. "http://localhost:4318" for a local OpenTelemetry Collector or Tempo.
    # Leave empty to disable OTLP export (spans collected locally only).
    otel_exporter_otlp_endpoint: str = ""

    # -------------------------------------------------------------------------
    # Time-travel / as_of — Phase 13 (spec §24.2.2)
    # -------------------------------------------------------------------------
    # Minimum allowed as_of timestamp (ISO 8601 UTC). Queries before this floor
    # return 400 as_of_before_retention_floor. Empty string = no floor enforced.
    as_of_retention_floor: str = ""


settings = Settings()
