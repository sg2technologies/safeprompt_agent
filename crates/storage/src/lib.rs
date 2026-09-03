// Audit Pipeline (Phase 4): durable, encrypted, retention-managed storage
// for DlpEvents. SQLite by default — self-contained, no external service,
// the right fit for Community/Professional's "Embedded" database tier per
// the target architecture (see the SafePrompt SG2 enterprise architecture
// memory). Schema and queries are deliberately kept Postgres-portable
// (plain SQL via runtime-checked `sqlx::query`, no SQLite-only extensions)
// so Enterprise customers who want a real, centralized, on-prem PostgreSQL
// instance instead of N scattered per-device SQLite files can just point
// `SAFEPROMPT_AUDIT_DB_PATH` at their own `postgres://` connection string —
// a connection-string and pool-type change, not a rewrite of the schema or
// the surrounding code (2026-08-01: `init()`'s scheme detection below picks
// the backend via `sqlx::Any`, which dynamically dispatches `.execute()`/
// `.fetch_*()` across backends but, discovered live-testing against a real
// Postgres instance, does NOT rewrite `?` placeholder syntax into
// Postgres's `$1, $2, ...` -- every parameterized query carries two small
// hardcoded SQL variants selected by `is_postgres`, see that field's doc
// comment. The migration DDL has no placeholders and is genuinely
// unmodified across both backends as originally designed). Config-driven,
// not edition-gated in code — the customer
// installs and runs their own Postgres server and hands us the URL; SG2
// has no operational access to it, and the encrypted findings payload
// (below) never leaves the customer's own network either way.
//
// Findings are encrypted at rest (AES-256-GCM) since they can contain
// fragments of the actual secrets/PII that were detected; everything else
// (timestamps, action taken, app/domain/tenant) stays in plaintext columns
// so retention/filtering queries don't need to decrypt every row just to
// filter by date or tenant. This holds regardless of backend -- a
// customer-hosted Postgres box being outside SG2's control is exactly why
// the findings column staying encrypted at rest still matters there too.
//
// Multi-tenant from the start (a `tenant_id` column, filtered on every
// query) even though a single-node Community install only ever has one
// tenant — cheap to build in now, expensive to retrofit later. Also lets
// one Enterprise customer's centralized Postgres cleanly hold every
// device's events from their whole fleet, not just one machine's.

mod encryption;

use anyhow::Context;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use safeprompt_common::{Action, DlpEvent, Finding};
use sha2::Sha256;
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::AnyPool;
use sqlx::Row;
use std::sync::Once;
use uuid::Uuid;

static INSTALL_DRIVERS: Once = Once::new();

/// Masks the password in a `postgres://user:PASSWORD@host/db` connection
/// string, e.g. for logging -- a raw `location` value must never reach a
/// log line unredacted, since it can be a real customer database password
/// (the local file-path case is untouched, nothing to redact there).
pub fn redact_location(location: &str) -> String {
    let Some(scheme_end) = (location.starts_with("postgres://") || location.starts_with("postgresql://"))
        .then(|| location.find("://"))
        .flatten()
    else {
        return location.to_string();
    };
    let after_scheme = &location[scheme_end + 3..];
    let Some(at_pos) = after_scheme.find('@') else {
        return location.to_string();
    };
    let creds = &after_scheme[..at_pos];
    let Some(colon_pos) = creds.find(':') else {
        return location.to_string();
    };
    let user = &creds[..colon_pos];
    let rest = &after_scheme[at_pos..]; // "@host:port/db..."
    format!("{}{}:***{}", &location[..scheme_end + 3], user, rest)
}

/// Builds a `sqlite://` connection URL for a filesystem path -- real bug,
/// found live 2026-08-07 while manually testing the Audit Relay against a
/// custom `SAFEPROMPT_AUDIT_DB_PATH`: the naive `format!("sqlite://{location}")`
/// this replaces silently failed to open with SQLITE_CANTOPEN (error code
/// 14) for *every* absolute Windows path, including the installer's own
/// default (`%ProgramData%\SafePrompt\audit.db`) -- meaning no real Windows
/// install (the only supported platform) had ever actually persisted an
/// audit event, since sqlx's SQLite URL scheme requires a THIRD slash for
/// an absolute path (`sqlite:///C:/path`, empty authority + absolute path)
/// but only two for a relative one (`sqlite://relative/path`, the whole
/// thing parsed as the authority component, which sqlx accepts as a
/// filename). A Unix absolute path (`/var/lib/safeprompt/audit.db`) was
/// never affected -- it already starts with `/`, so the naive two-slash
/// form already produced three slashes by accident. Only a Windows
/// drive-letter absolute path (`C:\...` or `C:/...`, which doesn't start
/// with `/` itself) was missing it. Verified against a real on-disk SQLite
/// file (not just `:memory:`, which every existing test before this one
/// used and is exactly why this went uncaught) in
/// `absolute_windows_style_paths_actually_open` below.
fn sqlite_url_for_path(location: &str) -> String {
    let normalized = location.replace('\\', "/");
    let is_windows_drive_absolute = normalized.as_bytes().get(1) == Some(&b':');
    if is_windows_drive_absolute {
        format!("sqlite:///{normalized}?mode=rwc")
    } else {
        format!("sqlite://{normalized}?mode=rwc")
    }
}

/// `sqlx::Any` requires the compiled-in drivers (sqlite/postgres) to be
/// registered once per process before any `AnyPool::connect` call --
/// idempotent, safe to call from every entry point below.
fn ensure_drivers_installed() {
    INSTALL_DRIVERS.call_once(|| {
        sqlx::any::install_default_drivers();
    });
}

pub struct LocalDatabase {
    pool: AnyPool,
    encryption_secret: String,
    /// `sqlx::Any` dispatches `.execute()`/`.fetch_*()` dynamically across
    /// backends, but it does NOT rewrite bound-parameter placeholder syntax
    /// -- SQLite/MySQL-style `?` is a syntax error against a real Postgres
    /// server, which wants `$1, $2, ...`. Found live-testing against a real
    /// local Postgres instance 2026-08-01 (the DDL in `migrate()` has no
    /// placeholders and is genuinely backend-portable as originally
    /// designed; every parameterized query below is not, and picks its SQL
    /// text based on this flag).
    is_postgres: bool,
}

impl LocalDatabase {
    /// Opens the database at `location` and runs migrations. `location` is
    /// either a local filesystem path (default -- SQLite, created if
    /// needed) or a `postgres://`/`postgresql://` connection URL (Enterprise
    /// customers pointing at their own on-prem server). `encryption_secret`
    /// encrypts/decrypts the findings payload at rest — same "hash a
    /// deployment secret" simplification as the CONNECT-proxy CA key
    /// persistence, not a full KDF.
    pub async fn init(location: &str, encryption_secret: &str) -> anyhow::Result<Self> {
        ensure_drivers_installed();
        let is_postgres = location.starts_with("postgres://") || location.starts_with("postgresql://");
        let url = if is_postgres { location.to_string() } else { sqlite_url_for_path(location) };
        let mut pool_options = AnyPoolOptions::new().max_connections(5);
        // SP-AUD-003/002 "secure deletion": SQLite's own `secure_delete`
        // pragma makes every DELETE (retention purges included) actually
        // overwrite the freed page content with zeroes rather than just
        // unlinking it from the B-tree -- without this, a purged event's
        // encrypted findings blob can still be recovered by reading the raw
        // .db file's freelist pages, which defeats the point of a retention
        // policy that's supposed to make old data actually gone. Applied
        // per-connection (SQLite pragmas are connection-scoped, not
        // persisted in the file) via `after_connect`, so every connection
        // the pool ever hands out has it set, not just the first one.
        // Postgres has no equivalent pragma and doesn't need one -- a
        // customer's own on-prem server is outside this crate's control
        // either way (see this file's own top-of-file doc comment).
        if !is_postgres {
            pool_options = pool_options.after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("PRAGMA secure_delete = ON").execute(&mut *conn).await?;
                    Ok(())
                })
            });
        }
        let pool = pool_options
            .connect(&url)
            .await
            .with_context(|| format!("opening database at {}", redact_location(location)))?;

        Self::migrate(&pool).await?;
        Ok(Self { pool, encryption_secret: encryption_secret.to_string(), is_postgres })
    }

    /// In-memory SQLite database — for tests, or a "don't persist anything"
    /// Community-edition mode. Data doesn't survive past the process.
    pub async fn init_in_memory(encryption_secret: &str) -> anyhow::Result<Self> {
        ensure_drivers_installed();
        let pool = AnyPoolOptions::new()
            .max_connections(1) // a fresh :memory: DB per connection otherwise — must pin to one
            .connect("sqlite::memory:")
            .await
            .context("opening in-memory database")?;
        Self::migrate(&pool).await?;
        Ok(Self { pool, encryption_secret: encryption_secret.to_string(), is_postgres: false })
    }

    async fn migrate(pool: &AnyPool) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                app_name TEXT NOT NULL,
                domain TEXT NOT NULL,
                user_identity TEXT NOT NULL,
                findings_encrypted TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                synced INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(pool)
        .await
        .context("creating audit_events table")?;

        // Best-effort: a database created before the audit relay existed
        // (Reconciled-P0 item #4) won't have this column yet -- `CREATE
        // TABLE IF NOT EXISTS` above is a no-op against it, so it needs
        // adding out of band. Errors (most commonly "duplicate column",
        // which both SQLite and Postgres raise when it already exists) are
        // swallowed rather than propagated: this must never turn "the
        // column is already there" into a fatal startup error, and a
        // genuinely broken database will fail loudly on the next real
        // query against this column anyway.
        let _ = sqlx::query("ALTER TABLE audit_events ADD COLUMN synced INTEGER NOT NULL DEFAULT 0").execute(pool).await;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_timestamp ON audit_events(tenant_id, timestamp)")
            .execute(pool)
            .await
            .context("creating tenant/timestamp index")?;

        // The audit relay's own access pattern (below): "give me this
        // tenant's oldest not-yet-relayed events" -- a dedicated index
        // rather than relying on the timestamp one above, since `synced`
        // is the actual filter predicate, not `timestamp`.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_synced ON audit_events(tenant_id, synced)")
            .execute(pool)
            .await
            .context("creating tenant/synced index")?;

        Ok(())
    }

    pub async fn save_event(&self, tenant_id: &str, event: &DlpEvent) -> anyhow::Result<()> {
        let findings_json = serde_json::to_vec(&event.findings)?;
        let findings_encrypted = encryption::encrypt(&findings_json, &self.encryption_secret)?;

        let sql = if self.is_postgres {
            "INSERT INTO audit_events \
                (id, tenant_id, timestamp, event_type, action_taken, app_name, domain, user_identity, findings_encrypted, finding_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        } else {
            "INSERT INTO audit_events \
                (id, tenant_id, timestamp, event_type, action_taken, app_name, domain, user_identity, findings_encrypted, finding_count) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        };
        sqlx::query(sql)
        .bind(event.id.to_string())
        .bind(tenant_id)
        .bind(event.timestamp.to_rfc3339())
        .bind(&event.event_type)
        .bind(action_to_str(&event.action_taken))
        .bind(&event.app_name)
        .bind(&event.domain)
        .bind(&event.user_identity)
        .bind(findings_encrypted)
        .bind(event.findings.len() as i64)
        .execute(&self.pool)
        .await
        .context("inserting audit event")?;

        Ok(())
    }

    /// Events for `tenant_id` in `[since, until]`, most recent first.
    pub async fn query_events(&self, tenant_id: &str, since: DateTime<Utc>, until: DateTime<Utc>) -> anyhow::Result<Vec<DlpEvent>> {
        let sql = if self.is_postgres {
            "SELECT id, timestamp, event_type, action_taken, app_name, domain, user_identity, findings_encrypted \
             FROM audit_events WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3 ORDER BY timestamp DESC"
        } else {
            "SELECT id, timestamp, event_type, action_taken, app_name, domain, user_identity, findings_encrypted \
             FROM audit_events WHERE tenant_id = ? AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC"
        };
        let rows = sqlx::query(sql)
        .bind(tenant_id)
        .bind(since.to_rfc3339())
        .bind(until.to_rfc3339())
        .fetch_all(&self.pool)
        .await
        .context("querying audit events")?;

        rows.iter().map(|row| self.row_to_event(row)).collect()
    }

    /// Events for `tenant_id` not yet confirmed relayed to the cloud
    /// Control Plane (`synced = 0`), oldest first (so a long backlog drains
    /// in arrival order rather than the newest events perpetually
    /// crowding out the oldest), capped at `limit` -- the audit relay's own
    /// batch size (see `safeprompt_audit_relay::spawn_relay_loop`).
    /// Reconciled-P0 item #4 (agent -> SPOC -> cloud audit relay,
    /// 2026-08-07): this is the "what still needs to go up" query that
    /// didn't exist before this shipped -- every event was previously only
    /// ever readable locally (`query_events`) or via manual CSV/JSON
    /// export.
    pub async fn unsynced_events(&self, tenant_id: &str, limit: i64) -> anyhow::Result<Vec<DlpEvent>> {
        let sql = if self.is_postgres {
            "SELECT id, timestamp, event_type, action_taken, app_name, domain, user_identity, findings_encrypted \
             FROM audit_events WHERE tenant_id = $1 AND synced = 0 ORDER BY timestamp ASC LIMIT $2"
        } else {
            "SELECT id, timestamp, event_type, action_taken, app_name, domain, user_identity, findings_encrypted \
             FROM audit_events WHERE tenant_id = ? AND synced = 0 ORDER BY timestamp ASC LIMIT ?"
        };
        let rows = sqlx::query(sql)
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .context("querying unsynced audit events")?;

        rows.iter().map(|row| self.row_to_event(row)).collect()
    }

    /// Marks the given event ids as relayed. Called only after the Control
    /// Plane has actually accepted a batch -- a relay failure must leave
    /// events unmarked (still `synced = 0`) so they're picked up again by
    /// the next `unsynced_events` call rather than silently lost. One
    /// `UPDATE` per id rather than a single `IN (...)` -- `sqlx::Any`
    /// dispatches across SQLite/Postgres dynamically but doesn't offer a
    /// backend-agnostic way to bind a variable-length list, and relay batch
    /// sizes are small (tens of events, not thousands) so this isn't a
    /// real cost.
    pub async fn mark_synced(&self, ids: &[Uuid]) -> anyhow::Result<()> {
        let sql = if self.is_postgres { "UPDATE audit_events SET synced = 1 WHERE id = $1" } else { "UPDATE audit_events SET synced = 1 WHERE id = ?" };
        for id in ids {
            sqlx::query(sql).bind(id.to_string()).execute(&self.pool).await.context("marking audit event synced")?;
        }
        Ok(())
    }

    /// Count of not-yet-relayed events for `tenant_id` -- diagnostics/tray
    /// visibility ("N events pending upload"), not itself used by the relay
    /// loop (which pages through `unsynced_events` directly).
    pub async fn unsynced_count(&self, tenant_id: &str) -> anyhow::Result<i64> {
        let sql = if self.is_postgres {
            "SELECT COUNT(*) as count FROM audit_events WHERE tenant_id = $1 AND synced = 0"
        } else {
            "SELECT COUNT(*) as count FROM audit_events WHERE tenant_id = ? AND synced = 0"
        };
        let row = sqlx::query(sql).bind(tenant_id).fetch_one(&self.pool).await?;
        Ok(row.try_get("count")?)
    }

    fn row_to_event(&self, row: &AnyRow) -> anyhow::Result<DlpEvent> {
        let id: String = row.try_get("id")?;
        let timestamp: String = row.try_get("timestamp")?;
        let event_type: String = row.try_get("event_type")?;
        let action_taken: String = row.try_get("action_taken")?;
        let app_name: String = row.try_get("app_name")?;
        let domain: String = row.try_get("domain")?;
        let user_identity: String = row.try_get("user_identity")?;
        let findings_encrypted: String = row.try_get("findings_encrypted")?;

        let findings_json = encryption::decrypt(&findings_encrypted, &self.encryption_secret)?;
        let findings: Vec<Finding> = serde_json::from_slice(&findings_json)?;

        Ok(DlpEvent {
            id: Uuid::parse_str(&id)?,
            timestamp: DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc),
            event_type,
            action_taken: str_to_action(&action_taken)?,
            app_name,
            domain,
            user_identity,
            findings,
        })
    }

    /// Deletes events older than `cutoff` across ALL tenants — retention
    /// enforcement. Returns how many rows were removed.
    pub async fn purge_older_than(&self, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
        let sql = if self.is_postgres {
            "DELETE FROM audit_events WHERE timestamp < $1"
        } else {
            "DELETE FROM audit_events WHERE timestamp < ?"
        };
        let result = sqlx::query(sql)
            .bind(cutoff.to_rfc3339())
            .execute(&self.pool)
            .await
            .context("purging old audit events")?;
        Ok(result.rows_affected())
    }

    /// SP-AUD-002 "max size": caps how many events a single tenant can
    /// accumulate, deleting the oldest excess rows first (same "oldest
    /// goes first" ordering `unsynced_events` already uses). This is the
    /// practical, backend-portable stand-in for a byte-size cap -- an exact
    /// on-disk byte count isn't queryable the same way across SQLite and
    /// Postgres through `sqlx::Any` (SQLite's `dbstat`/`page_count` pragmas
    /// have no Postgres equivalent), whereas "at most N events" is a real,
    /// enforceable, backend-agnostic bound that still stops runaway growth
    /// (a misbehaving app generating thousands of findings/day) the way a
    /// byte cap is meant to. Returns how many rows were removed; `Ok(0)`
    /// (not an error) if the tenant is already at or under `max_events`.
    pub async fn enforce_max_events(&self, tenant_id: &str, max_events: i64) -> anyhow::Result<u64> {
        let total = self.count_events(tenant_id).await?;
        let excess = total - max_events;
        if excess <= 0 {
            return Ok(0);
        }
        // Delete the oldest `excess` rows for this tenant only -- a plain
        // `LIMIT` on `DELETE` isn't portable across SQLite/Postgres through
        // `sqlx::Any` (Postgres doesn't support `DELETE ... LIMIT` at all),
        // so the id set to remove is selected first, then deleted by id --
        // same "no backend-agnostic variable-length IN(...) binding"
        // constraint `mark_synced` already documents, same one-at-a-time
        // workaround.
        let select_sql = if self.is_postgres {
            "SELECT id FROM audit_events WHERE tenant_id = $1 ORDER BY timestamp ASC LIMIT $2"
        } else {
            "SELECT id FROM audit_events WHERE tenant_id = ? ORDER BY timestamp ASC LIMIT ?"
        };
        let rows = sqlx::query(select_sql)
            .bind(tenant_id)
            .bind(excess)
            .fetch_all(&self.pool)
            .await
            .context("selecting oldest events for max-events retention")?;

        let delete_sql = if self.is_postgres { "DELETE FROM audit_events WHERE id = $1" } else { "DELETE FROM audit_events WHERE id = ?" };
        let mut removed = 0u64;
        for row in &rows {
            let id: String = row.try_get("id")?;
            sqlx::query(delete_sql).bind(&id).execute(&self.pool).await.context("deleting excess audit event")?;
            removed += 1;
        }
        Ok(removed)
    }

    pub async fn count_events(&self, tenant_id: &str) -> anyhow::Result<i64> {
        let sql = if self.is_postgres {
            "SELECT COUNT(*) as count FROM audit_events WHERE tenant_id = $1"
        } else {
            "SELECT COUNT(*) as count FROM audit_events WHERE tenant_id = ?"
        };
        let row = sqlx::query(sql)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("count")?)
    }

    /// Raw access for tests/diagnostics only — proves findings are actually
    /// encrypted at rest, not something application code should use.
    #[doc(hidden)]
    pub async fn raw_findings_column(&self, event_id: Uuid) -> anyhow::Result<String> {
        let sql = if self.is_postgres {
            "SELECT findings_encrypted FROM audit_events WHERE id = $1"
        } else {
            "SELECT findings_encrypted FROM audit_events WHERE id = ?"
        };
        let row = sqlx::query(sql)
            .bind(event_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("findings_encrypted")?)
    }
}

fn action_to_str(action: &Action) -> &'static str {
    match action {
        Action::Allow => "Allow",
        Action::Warn => "Warn",
        Action::Redact => "Redact",
        Action::Block => "Block",
        Action::Audit => "Audit",
        Action::RequireApproval => "RequireApproval",
    }
}

fn str_to_action(s: &str) -> anyhow::Result<Action> {
    match s {
        "Allow" => Ok(Action::Allow),
        "Warn" => Ok(Action::Warn),
        "Redact" => Ok(Action::Redact),
        "Block" => Ok(Action::Block),
        "Audit" => Ok(Action::Audit),
        "RequireApproval" => Ok(Action::RequireApproval),
        other => Err(anyhow::anyhow!("unknown action in database: {other}")),
    }
}

/// CSV export — hand-rolled (no new dependency): quotes fields containing
/// commas/quotes/newlines, doubling up embedded quotes per the usual CSV
/// escaping rule.
pub fn export_csv(events: &[DlpEvent]) -> String {
    fn csv_field(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }

    let mut out = String::from("id,timestamp,event_type,action_taken,app_name,domain,user_identity,finding_count\n");
    for event in events {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            event.id,
            event.timestamp.to_rfc3339(),
            csv_field(&event.event_type),
            action_to_str(&event.action_taken),
            csv_field(&event.app_name),
            csv_field(&event.domain),
            csv_field(&event.user_identity),
            event.findings.len()
        ));
    }
    out
}

pub fn export_json(events: &[DlpEvent]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(events)?)
}

type HmacSha256 = Hmac<Sha256>;

/// SP-AUD-004 "signed archive" export format: the plain JSON export (via
/// `export_json`) plus a detached `HMAC-SHA256(secret, events_json)`
/// signature, so a customer who exports events for their own compliance
/// records (handing the file to an auditor, archiving it off-box) can later
/// prove the file wasn't edited after export -- a plain JSON/CSV export has
/// no such guarantee, anyone with the file can edit it freely. Reuses the
/// same deployment secret that already encrypts findings at rest
/// (`encryption_secret`) rather than introducing a second key to manage --
/// consistent with this crate's existing "hash a deployment secret, not a
/// full KDF/PKI" posture (see `LocalDatabase::init`'s own doc comment on the
/// same tradeoff). This is integrity/tamper-evidence, not confidentiality:
/// the archive's `events` field is the same plaintext `export_json` would
/// produce, not re-encrypted.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SignedAuditArchive {
    pub exported_at: DateTime<Utc>,
    pub events: Vec<DlpEvent>,
    /// Hex-encoded HMAC-SHA256 over the canonical (compact, not pretty)
    /// JSON encoding of `events` alone -- computed the same way on both the
    /// signing and verifying side, see `signable_bytes`.
    pub signature: String,
}

fn signable_bytes(events: &[DlpEvent]) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(events)?)
}

pub fn export_signed_archive(events: &[DlpEvent], secret: &str) -> anyhow::Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("building HMAC key")?;
    mac.update(&signable_bytes(events)?);
    let signature = hex::encode(mac.finalize().into_bytes());

    let archive = SignedAuditArchive { exported_at: Utc::now(), events: events.to_vec(), signature };
    Ok(serde_json::to_string_pretty(&archive)?)
}

/// Verifies a `SignedAuditArchive` produced by `export_signed_archive`
/// against `secret`, returning the events only if the signature is intact.
/// A constant-time comparison (`Mac::verify_slice`, not `==`) matters less
/// here than it typically would (this isn't checking a live network
/// request, an offline file the caller already possesses), but costs
/// nothing to use anyway.
pub fn verify_signed_archive(archive_json: &str, secret: &str) -> anyhow::Result<Vec<DlpEvent>> {
    let archive: SignedAuditArchive = serde_json::from_str(archive_json).context("parsing signed audit archive")?;
    let expected_signature = hex::decode(&archive.signature).context("decoding archive signature")?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("building HMAC key")?;
    mac.update(&signable_bytes(&archive.events)?);
    mac.verify_slice(&expected_signature).map_err(|_| anyhow::anyhow!("signed audit archive failed signature verification -- it may have been tampered with, or signed with a different secret"))?;

    Ok(archive.events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeprompt_common::FindingCategory;

    fn sample_event(app_name: &str) -> DlpEvent {
        DlpEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "request".to_string(),
            action_taken: Action::Block,
            app_name: app_name.to_string(),
            domain: "api.openai.com".to_string(),
            user_identity: "alice@example.com".to_string(),
            findings: vec![Finding {
                category: FindingCategory::Secret,
                match_name: "AWS_ACCESS_KEY".to_string(),
                snippet: "AKIAIOSFODNN7EXAMPLE".to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_AWS_KEY]".to_string()),
            }],
        }
    }

    #[tokio::test]
    async fn saves_and_queries_an_event_roundtrip() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        let event = sample_event("chrome.exe");
        db.save_event("tenant-a", &event).await.unwrap();

        let events = db.query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
        assert_eq!(events[0].app_name, "chrome.exe");
        assert_eq!(events[0].findings.len(), 1);
        assert_eq!(events[0].findings[0].snippet, "AKIAIOSFODNN7EXAMPLE");
    }

    #[tokio::test]
    async fn audit_and_require_approval_actions_round_trip_through_storage() {
        // SP-RISK-003 added these two Action variants -- action_to_str/
        // str_to_action must handle them, not just the original four.
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        for action in [Action::Audit, Action::RequireApproval] {
            let mut event = sample_event("chrome.exe");
            event.action_taken = action.clone();
            db.save_event("tenant-a", &event).await.unwrap();

            let events = db.query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1)).await.unwrap();
            let saved = events.iter().find(|e| e.id == event.id).expect("just-saved event should be queryable");
            assert_eq!(saved.action_taken, action);
        }
    }

    #[tokio::test]
    async fn findings_are_actually_encrypted_at_rest() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        let event = sample_event("chrome.exe");
        db.save_event("tenant-a", &event).await.unwrap();

        let raw = db.raw_findings_column(event.id).await.unwrap();
        assert!(!raw.contains("AKIAIOSFODNN7EXAMPLE"), "the secret must not be readable in the raw stored column: {raw}");
    }

    #[tokio::test]
    async fn tenants_do_not_see_each_others_events() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        db.save_event("tenant-a", &sample_event("a.exe")).await.unwrap();
        db.save_event("tenant-b", &sample_event("b.exe")).await.unwrap();

        let a_events = db.query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1)).await.unwrap();
        assert_eq!(a_events.len(), 1);
        assert_eq!(a_events[0].app_name, "a.exe");
    }

    #[tokio::test]
    async fn query_events_filters_by_time_range() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        let mut old_event = sample_event("old.exe");
        old_event.timestamp = Utc::now() - chrono::Duration::days(30);
        db.save_event("tenant-a", &old_event).await.unwrap();
        db.save_event("tenant-a", &sample_event("recent.exe")).await.unwrap();

        let recent_only = db
            .query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(recent_only.len(), 1);
        assert_eq!(recent_only[0].app_name, "recent.exe");
    }

    #[tokio::test]
    async fn purge_older_than_removes_only_stale_events() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        let mut old_event = sample_event("old.exe");
        old_event.timestamp = Utc::now() - chrono::Duration::days(100);
        db.save_event("tenant-a", &old_event).await.unwrap();
        db.save_event("tenant-a", &sample_event("recent.exe")).await.unwrap();

        let purged = db.purge_older_than(Utc::now() - chrono::Duration::days(90)).await.unwrap();
        assert_eq!(purged, 1);
        assert_eq!(db.count_events("tenant-a").await.unwrap(), 1);
    }

    /// Real bug, found live 2026-08-07 (see `sqlite_url_for_path`'s own doc
    /// comment): every existing test in this file before this one used
    /// either `:memory:` or a value that was never actually exercised as a
    /// real absolute Windows path, so the SQLITE_CANTOPEN failure this
    /// proves against went uncaught. `std::env::temp_dir()` is always
    /// absolute on every platform this ships to.
    #[tokio::test]
    async fn absolute_windows_style_paths_actually_open() {
        let mut path = std::env::temp_dir();
        path.push(format!("safeprompt-storage-test-{}.db", Uuid::new_v4()));
        // Force Windows-style backslash separators regardless of which OS
        // this test happens to run on -- this is specifically proving the
        // backslash-normalization half of the fix, not just "any absolute
        // path works" (which the forward-slash form could pass even with
        // the old, broken code on a real Windows machine, since sqlite
        // itself tolerates forward slashes -- backslashes are what the
        // naive two-slash URL construction actually choked on).
        let windows_style = path.to_string_lossy().replace('/', "\\");

        let db = LocalDatabase::init(&windows_style, "test-secret").await
            .unwrap_or_else(|e| panic!("expected an absolute path to open successfully, got: {e:?}"));
        db.save_event("tenant-a", &sample_event("chrome.exe")).await.unwrap();
        assert_eq!(db.count_events("tenant-a").await.unwrap(), 1);

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sqlite_url_for_windows_drive_absolute_path_gets_the_third_slash() {
        assert_eq!(sqlite_url_for_path(r"C:\ProgramData\SafePrompt\audit.db"), "sqlite:///C:/ProgramData/SafePrompt/audit.db?mode=rwc");
        assert_eq!(sqlite_url_for_path("C:/ProgramData/SafePrompt/audit.db"), "sqlite:///C:/ProgramData/SafePrompt/audit.db?mode=rwc");
    }

    #[test]
    fn sqlite_url_for_unix_absolute_path_is_unchanged_from_before() {
        assert_eq!(sqlite_url_for_path("/var/lib/safeprompt/audit.db"), "sqlite:///var/lib/safeprompt/audit.db?mode=rwc");
    }

    #[test]
    fn sqlite_url_for_relative_path_is_unchanged_from_before() {
        assert_eq!(sqlite_url_for_path("audit.db"), "sqlite://audit.db?mode=rwc");
        assert_eq!(sqlite_url_for_path("./data/audit.db"), "sqlite://./data/audit.db?mode=rwc");
    }

    #[tokio::test]
    async fn newly_saved_events_are_unsynced_until_marked() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        let event = sample_event("chrome.exe");
        db.save_event("tenant-a", &event).await.unwrap();

        let unsynced = db.unsynced_events("tenant-a", 10).await.unwrap();
        assert_eq!(unsynced.len(), 1);
        assert_eq!(unsynced[0].id, event.id);
        assert_eq!(db.unsynced_count("tenant-a").await.unwrap(), 1);

        db.mark_synced(&[event.id]).await.unwrap();

        assert_eq!(db.unsynced_events("tenant-a", 10).await.unwrap().len(), 0);
        assert_eq!(db.unsynced_count("tenant-a").await.unwrap(), 0);
        // Marking synced must not affect the ordinary time-range query --
        // it's a relay bookkeeping flag, not a soft-delete.
        assert_eq!(db.query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1)).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unsynced_events_respects_the_batch_limit_and_tenant_isolation() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        for i in 0..5 {
            db.save_event("tenant-a", &sample_event(&format!("app-{i}.exe"))).await.unwrap();
        }
        db.save_event("tenant-b", &sample_event("other.exe")).await.unwrap();

        let batch = db.unsynced_events("tenant-a", 3).await.unwrap();
        assert_eq!(batch.len(), 3, "limit should cap the batch even though 5 unsynced events exist");
        assert_eq!(db.unsynced_events("tenant-b", 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unsynced_events_are_returned_oldest_first() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        let mut older = sample_event("older.exe");
        older.timestamp = Utc::now() - chrono::Duration::hours(2);
        let mut newer = sample_event("newer.exe");
        newer.timestamp = Utc::now() - chrono::Duration::minutes(1);
        // Insert newer first to prove the ordering comes from the query, not insertion order.
        db.save_event("tenant-a", &newer).await.unwrap();
        db.save_event("tenant-a", &older).await.unwrap();

        let batch = db.unsynced_events("tenant-a", 10).await.unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].app_name, "older.exe");
        assert_eq!(batch[1].app_name, "newer.exe");
    }

    #[tokio::test]
    async fn mark_synced_with_no_ids_is_a_harmless_no_op() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        db.save_event("tenant-a", &sample_event("chrome.exe")).await.unwrap();
        db.mark_synced(&[]).await.unwrap();
        assert_eq!(db.unsynced_count("tenant-a").await.unwrap(), 1, "an empty id slice must not touch any row");
    }

    #[test]
    fn csv_export_escapes_fields_with_commas() {
        let event = DlpEvent {
            app_name: "some,app".to_string(),
            ..sample_event("unused")
        };
        let csv = export_csv(&[event]);
        assert!(csv.contains("\"some,app\""));
    }

    #[test]
    fn redact_location_masks_a_postgres_password() {
        assert_eq!(
            redact_location("postgres://sp_agent:hunter2@db.customer.local:5432/audit"),
            "postgres://sp_agent:***@db.customer.local:5432/audit"
        );
        assert_eq!(
            redact_location("postgresql://sp_agent:hunter2@db.customer.local/audit"),
            "postgresql://sp_agent:***@db.customer.local/audit"
        );
    }

    #[test]
    fn redact_location_leaves_a_local_file_path_unchanged() {
        assert_eq!(redact_location(r"C:\ProgramData\SafePrompt\audit.db"), r"C:\ProgramData\SafePrompt\audit.db");
        assert_eq!(redact_location("./audit.db"), "./audit.db");
    }

    #[test]
    fn redact_location_leaves_a_credential_free_postgres_url_unchanged() {
        assert_eq!(redact_location("postgres://db.customer.local/audit"), "postgres://db.customer.local/audit");
    }

    #[tokio::test]
    async fn enforce_max_events_deletes_only_the_oldest_excess_rows_for_the_right_tenant() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        for i in 0..5 {
            let mut event = sample_event(&format!("app-{i}.exe"));
            event.timestamp = Utc::now() - chrono::Duration::minutes(5 - i);
            db.save_event("tenant-a", &event).await.unwrap();
        }
        db.save_event("tenant-b", &sample_event("other.exe")).await.unwrap();

        let removed = db.enforce_max_events("tenant-a", 3).await.unwrap();
        assert_eq!(removed, 2, "5 events capped to 3 should remove the 2 oldest");
        assert_eq!(db.count_events("tenant-a").await.unwrap(), 3);
        assert_eq!(db.count_events("tenant-b").await.unwrap(), 1, "the cap must not touch a different tenant's events");

        let remaining = db.query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1)).await.unwrap();
        let names: std::collections::HashSet<_> = remaining.iter().map(|e| e.app_name.clone()).collect();
        assert_eq!(names, std::collections::HashSet::from(["app-2.exe".to_string(), "app-3.exe".to_string(), "app-4.exe".to_string()]), "the 3 most recent events must be the ones kept");
    }

    #[tokio::test]
    async fn enforce_max_events_is_a_no_op_when_already_under_the_cap() {
        let db = LocalDatabase::init_in_memory("test-secret").await.unwrap();
        db.save_event("tenant-a", &sample_event("chrome.exe")).await.unwrap();
        let removed = db.enforce_max_events("tenant-a", 100).await.unwrap();
        assert_eq!(removed, 0);
        assert_eq!(db.count_events("tenant-a").await.unwrap(), 1);
    }

    #[test]
    fn signed_archive_roundtrips_and_verifies() {
        let event = sample_event("chrome.exe");
        let archive = export_signed_archive(&[event.clone()], "test-secret").unwrap();
        let verified = verify_signed_archive(&archive, "test-secret").unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].id, event.id);
        assert_eq!(verified[0].app_name, "chrome.exe");
    }

    #[test]
    fn signed_archive_verification_fails_if_the_events_are_tampered_with_after_export() {
        let event = sample_event("chrome.exe");
        let archive = export_signed_archive(&[event], "test-secret").unwrap();
        let tampered = archive.replace("chrome.exe", "malicious.exe");
        let result = verify_signed_archive(&tampered, "test-secret");
        assert!(result.is_err(), "a tampered archive must fail signature verification, not silently return the edited events");
    }

    #[test]
    fn signed_archive_verification_fails_with_the_wrong_secret() {
        let event = sample_event("chrome.exe");
        let archive = export_signed_archive(&[event], "correct-secret").unwrap();
        let result = verify_signed_archive(&archive, "wrong-secret");
        assert!(result.is_err(), "verifying with a different secret than the one used to sign must fail");
    }

    #[test]
    fn json_export_roundtrips() {
        let event = sample_event("chrome.exe");
        let json = export_json(&[event.clone()]).unwrap();
        let parsed: Vec<DlpEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].app_name, "chrome.exe");
    }

    /// Proves the Enterprise on-prem Postgres path actually works end to
    /// end, not just "the code compiles against `sqlx::Any`" -- same
    /// save/query/encryption/purge behavior the SQLite tests above already
    /// cover, run against a real server. Skipped (not failed) unless
    /// `SAFEPROMPT_TEST_POSTGRES_URL` is set, since most environments
    /// (including normal CI, once this repo has one) won't have a live
    /// Postgres available -- point it at a scratch/throwaway database, this
    /// test purges every row it inserts but isn't isolated across runs.
    #[tokio::test]
    async fn postgres_backend_roundtrips_when_a_real_instance_is_configured() {
        let Ok(url) = std::env::var("SAFEPROMPT_TEST_POSTGRES_URL") else {
            eprintln!("skipping postgres_backend_roundtrips_when_a_real_instance_is_configured: SAFEPROMPT_TEST_POSTGRES_URL not set");
            return;
        };

        let db = LocalDatabase::init(&url, "test-secret").await.expect("connecting to the configured Postgres instance");
        let event = sample_event("chrome.exe");
        db.save_event("tenant-a", &event).await.unwrap();

        let events = db
            .query_events("tenant-a", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
        assert_eq!(events[0].findings.len(), 1);
        assert_eq!(events[0].findings[0].snippet, "AKIAIOSFODNN7EXAMPLE");

        let raw = db.raw_findings_column(event.id).await.unwrap();
        assert!(!raw.contains("AKIAIOSFODNN7EXAMPLE"), "findings must be encrypted at rest on Postgres too, not just SQLite");

        // Also exercises multi-tenant isolation and retention purge against the real backend.
        db.save_event("tenant-b", &sample_event("other.exe")).await.unwrap();
        let tenant_b_events = db
            .query_events("tenant-b", Utc::now() - chrono::Duration::hours(1), Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(tenant_b_events.len(), 1);
        assert_eq!(tenant_b_events[0].app_name, "other.exe");

        let purged = db.purge_older_than(Utc::now() + chrono::Duration::hours(2)).await.unwrap();
        assert_eq!(purged, 2, "purge_older_than should have cleaned up both events this test inserted");
        assert_eq!(db.count_events("tenant-a").await.unwrap(), 0);
        assert_eq!(db.count_events("tenant-b").await.unwrap(), 0);
    }
}
