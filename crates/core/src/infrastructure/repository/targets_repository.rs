//! 2.5.0 fleet (ADR-0023).
//!
//! A flat registry of named targets. Each row is
//! a (environment, name) pair with a filesystem
//! path on the operator's box. The 2.5.0 server
//! stores the metadata; the operator's CLI reads
//! the path at deploy time. 3.x is when the
//! server itself runs the deploy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

use super::pending_deploys_repository::Environment;

/// 2.5.1 (ADR-0029) — discriminator for cross-team
/// path sharing. `Posix` is the 2.5.0 default
/// (every existing row was registered as POSIX).
/// `Windows` is for the cross-team case where a
/// Stockholm admin wants to register
/// `C:\deploy\prod-blue` and a Berlin operator
/// on Linux needs to see "this target is Windows
/// — not for me" in the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Posix,
    Windows,
}

impl PathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Posix => "posix",
            PathKind::Windows => "windows",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "posix" => Ok(PathKind::Posix),
            "windows" => Ok(PathKind::Windows),
            other => Err(CoreError::ErrSchemaInvalid {
                path: "targets.path_kind".to_string(),
                reason: format!("unknown path_kind `{other}`"),
            }),
        }
    }

    /// Validate a path against the discriminator
    /// rules. The check is platform-agnostic
    /// (does NOT use `Path::is_absolute`, which
    /// disagrees across Windows and POSIX).
    /// Returns `Ok(())` on a match, `Err` on a
    /// mismatch.
    pub fn validate_path(self, path: &str) -> CoreResult<()> {
        match self {
            PathKind::Posix => {
                if path.starts_with('/') {
                    Ok(())
                } else {
                    Err(CoreError::ErrSchemaInvalid {
                        path: "targets.path".to_string(),
                        reason: format!(
                            "path `{path}` is not a POSIX absolute path \
                             (must start with `/`)"
                        ),
                    })
                }
            }
            PathKind::Windows => {
                // Windows: `<letter>:\` (drive
                // letter) OR `\\server\share\...`
                // (UNC). The regex is intentionally
                // permissive on the rest.
                let is_drive = path.len() >= 3
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && (path.as_bytes()[1] == b':')
                    && (path.as_bytes()[2] == b'\\' || path.as_bytes()[2] == b'/');
                let is_unc = path.starts_with("\\\\") || path.starts_with("//");
                if is_drive || is_unc {
                    Ok(())
                } else {
                    Err(CoreError::ErrSchemaInvalid {
                        path: "targets.path".to_string(),
                        reason: format!(
                            "path `{path}` is not a Windows absolute path \
                             (must be `C:\\...` or `\\\\server\\share\\...`)"
                        ),
                    })
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRow {
    pub id: i64,
    pub name: String,
    pub environment: Environment,
    pub path: String,
    pub path_kind: PathKind,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct TargetRepository {
    pool: SqlitePool,
}

impl TargetRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new target. Returns the new row.
    /// Fails with `ErrSchemaInvalid` if the path
    /// is empty, the name is empty, the path
    /// doesn't match `path_kind`, or
    /// `(environment, name)` already exists.
    ///
    /// 2.5.0 stored paths verbatim without
    /// validating the style. 2.5.1 (ADR-0029)
    /// adds a `PathKind` discriminator and
    /// validates each path against it. Existing
    /// 2.5.0 callers that omit `path_kind` get
    /// `PathKind::Posix` (the 2.5.0 default).
    pub async fn create(
        &self,
        name: &str,
        environment: Environment,
        path: &str,
        path_kind: PathKind,
        description: Option<&str>,
    ) -> CoreResult<TargetRow> {
        if name.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "targets.name".to_string(),
                reason: "name must not be empty".to_string(),
            });
        }
        if path.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "targets.path".to_string(),
                reason: "path must not be empty".to_string(),
            });
        }
        path_kind.validate_path(path)?;
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO targets \
             (name, environment, path, path_kind, description, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6) RETURNING id",
        )
        .bind(name)
        .bind(environment.as_str())
        .bind(path)
        .bind(path_kind.as_str())
        .bind(description)
        .bind(&now_str)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                CoreError::ErrSchemaInvalid {
                    path: "targets.name".to_string(),
                    reason: format!(
                        "a target named `{name}` already exists in environment `{}`",
                        environment.as_str()
                    ),
                }
            }
            _ => CoreError::ErrSqlx(e),
        })?;
        Ok(TargetRow {
            id: row.0,
            name: name.to_string(),
            environment,
            path: path.to_string(),
            path_kind,
            description: description.map(|s| s.to_string()),
            created_at: now_str.clone(),
            updated_at: now_str,
        })
    }

    /// Read a single target by id.
    pub async fn get(&self, id: i64) -> CoreResult<Option<TargetRow>> {
        let row: Option<TargetRowTuple> = sqlx::query_as(
            "SELECT id, name, environment, path, path_kind, description, created_at, updated_at \
             FROM targets WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode).transpose()
    }

    /// Look up a target by its `(environment, name)`
    /// pair. This is the hot path for
    /// `POST /v1/deploys` — the deploy flow
    /// resolves the operator-typed `target: "name"`
    /// through this lookup.
    pub async fn find_by_env_name(
        &self,
        environment: Environment,
        name: &str,
    ) -> CoreResult<Option<TargetRow>> {
        let row: Option<TargetRowTuple> = sqlx::query_as(
            "SELECT id, name, environment, path, path_kind, description, created_at, updated_at \
             FROM targets WHERE environment = ?1 AND name = ?2",
        )
        .bind(environment.as_str())
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode).transpose()
    }

    /// List every target, oldest-first. `env_filter`
    /// is optional.
    pub async fn list(&self, env_filter: Option<Environment>) -> CoreResult<Vec<TargetRow>> {
        let rows: Vec<TargetRowTuple> = match env_filter {
            Some(e) => {
                sqlx::query_as(
                    "SELECT id, name, environment, path, path_kind, description, created_at, updated_at \
                 FROM targets WHERE environment = ?1 ORDER BY id ASC",
                )
                .bind(e.as_str())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT id, name, environment, path, path_kind, description, created_at, updated_at \
                 FROM targets ORDER BY id ASC",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.into_iter().map(decode).collect()
    }

    /// Hard-delete a target. Returns `true` if a
    /// row was removed.
    pub async fn delete(&self, id: i64) -> CoreResult<bool> {
        let affected = sqlx::query("DELETE FROM targets WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    /// Count rows. The 2.5.x start-up check
    /// refuses to migrate an empty targets table
    /// plus a non-empty pending_deploys table
    /// (different from the 2.3.0 vault check,
    /// which refuses the opposite).
    pub async fn count(&self) -> CoreResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM targets")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// 2.11.0 (P1-D-02, TZ #1 §10 /
    /// D-02, CWE-362): read the
    /// current `deployment_version`
    /// of a target. Returns `Ok(None)`
    /// if the target does not exist.
    /// Used by `PendingDeployRepository::mark_applied`
    /// to read the post-increment
    /// value and by `request` to
    /// capture the fencing token at
    /// request time.
    ///
    /// Distinct from `targets.version`
    /// (P1-D-01b config-drift
    /// counter). `version` bumps on
    /// every `PUT /v1/targets/:id`;
    /// `deployment_version` bumps on
    /// every successful
    /// `mark_applied`. The two
    /// counters serve different
    /// freshness checks.
    pub async fn deployment_version(&self, id: i64) -> CoreResult<Option<i64>> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT deployment_version FROM targets WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

    /// 2.11.0 (P1-D-02): atomic
    /// compare-and-swap increment of
    /// `targets.deployment_version`.
    /// Returns the **new** value on
    /// success, or `Ok(None)` if the
    /// CAS failed (someone else
    /// bumped the version between
    /// our SELECT and our UPDATE).
    ///
    /// The CAS is the only thing that
    /// makes the fence commit atomic
    /// against a concurrent apply:
    /// `mark_applied` reads the
    /// current version, runs the
    /// `pending_deploys` UPDATE, and
    /// then `increment_deployment_version`s
    /// with the expected pre-increment
    /// value. A second concurrent
    /// `mark_applied` would race the
    /// first through the same flow;
    /// one of them sees the CAS
    /// return 0 rows, and that one
    /// is rejected.
    ///
    /// SQLite serializes writes per
    /// pool, so in the single-process
    /// server the race is impossible
    /// at the SQL level — but the CAS
    /// is the right semantic and
    /// makes the check obvious to a
    /// reviewer. The `expected`
    /// argument is the pre-increment
    /// value the caller observed; the
    /// returned value is
    /// `expected + 1` on success.
    pub async fn increment_deployment_version(
        &self,
        id: i64,
        expected: i64,
    ) -> CoreResult<Option<i64>> {
        let affected = sqlx::query(
            "UPDATE targets \
             SET deployment_version = ?1 \
             WHERE id = ?2 AND deployment_version = ?3",
        )
        .bind(expected + 1)
        .bind(id)
        .bind(expected)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 0 {
            Ok(None)
        } else {
            Ok(Some(expected + 1))
        }
    }
}

type TargetRowTuple = (
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
);

fn decode(row: TargetRowTuple) -> CoreResult<TargetRow> {
    let (id, name, environment, path, path_kind, description, created_at, updated_at) = row;
    Ok(TargetRow {
        id,
        name,
        environment: Environment::parse(&environment)?,
        path,
        path_kind: PathKind::parse(&path_kind)?,
        description,
        created_at,
        updated_at,
    })
}

#[cfg(test)]
#[path = "targets_repository_tests.rs"]
mod tests;
