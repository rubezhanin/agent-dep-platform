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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRow {
    pub id: i64,
    pub name: String,
    pub environment: Environment,
    pub path: String,
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
    /// is not absolute, the name is empty, or
    /// `(environment, name)` already exists.
    pub async fn create(
        &self,
        name: &str,
        environment: Environment,
        path: &str,
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
        // The path is interpreted by the operator's
        // CLI on the operator's box. Cross-platform
        // "is_absolute" is unreliable (Windows
        // rejects POSIX absolute paths, POSIX
        // rejects Windows paths), so we do not
        // enforce it server-side. The 2.5.0
        // contract is "the path is whatever the
        // operator's CLI can read"; the server
        // just stores it. 2.5.1 adds a
        // `target_path_kind` discriminator
        // (`posix` / `windows`) if cross-team
        // sharing is required.
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO targets (name, environment, path, description, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5) RETURNING id",
        )
        .bind(name)
        .bind(environment.as_str())
        .bind(path)
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
            description: description.map(|s| s.to_string()),
            created_at: now_str.clone(),
            updated_at: now_str,
        })
    }

    /// Read a single target by id.
    pub async fn get(&self, id: i64) -> CoreResult<Option<TargetRow>> {
        let row: Option<TargetRowTuple> = sqlx::query_as(
            "SELECT id, name, environment, path, description, created_at, updated_at \
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
            "SELECT id, name, environment, path, description, created_at, updated_at \
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
                    "SELECT id, name, environment, path, description, created_at, updated_at \
                 FROM targets WHERE environment = ?1 ORDER BY id ASC",
                )
                .bind(e.as_str())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT id, name, environment, path, description, created_at, updated_at \
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
}

type TargetRowTuple = (i64, String, String, String, Option<String>, String, String);

fn decode(row: TargetRowTuple) -> CoreResult<TargetRow> {
    let (id, name, environment, path, description, created_at, updated_at) = row;
    Ok(TargetRow {
        id,
        name,
        environment: Environment::parse(&environment)?,
        path,
        description,
        created_at,
        updated_at,
    })
}

#[cfg(test)]
#[path = "targets_repository_tests.rs"]
mod tests;
