//! Persistence for `deployed_artifacts` (TZ v2 §20).
//!
//! One row per `(system_id, target)` pair, written by
//! `DeploymentService::apply` and read by `PlanService`
//! to compute the real diff against the desired state.
//!
//! MVP-1.0 uses this only for the `Noop` / `Add` half;
//! the `Update` / `Delete` / `Backup` / `Verify` paths
//! are wired in Phase 5 remaining (1.x).

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};

/// Row read back from `deployed_artifacts`. The hashes
/// are sha256-hex strings (64 chars) or `None` when
/// the file is missing on disk.
#[derive(Debug, Clone)]
pub struct DeployedArtifactRow {
    pub system_id: String,
    pub target: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub state: String,
    pub deployed_at: String,
    pub last_verified_at: Option<String>,
}

pub struct DeployedArtifactsRepository {
    pool: SqlitePool,
}

impl DeployedArtifactsRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Upsert one row per `(system_id, target)`. The
    /// caller is responsible for the transaction; this
    /// function is intentionally one-statement-per-row
    /// so a deploy loop can interleave with a verify
    /// pass without taking a long-running lock.
    pub async fn upsert(&self, row: &DeployedArtifactRow) -> CoreResult<()> {
        sqlx::query(
            "INSERT INTO deployed_artifacts
                (system_id, target, expected_sha256, actual_sha256,
                 state, deployed_at, last_verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(system_id, target) DO UPDATE SET
                expected_sha256 = excluded.expected_sha256,
                actual_sha256 = excluded.actual_sha256,
                state = excluded.state,
                deployed_at = excluded.deployed_at,
                last_verified_at = excluded.last_verified_at",
        )
        .bind(&row.system_id)
        .bind(&row.target)
        .bind(&row.expected_sha256)
        .bind(row.actual_sha256.as_deref())
        .bind(&row.state)
        .bind(&row.deployed_at)
        .bind(row.last_verified_at.as_deref())
        .execute(&self.pool)
        .await
        .map_err(CoreError::ErrSqlx)?;
        Ok(())
    }

    /// All rows for a system, in `(target, expected, actual)`
    /// projection — exactly the columns `PlanService`
    /// needs for the diff.
    pub async fn list_for_system(
        &self,
        system_id: &str,
    ) -> CoreResult<Vec<(String, String, Option<String>)>> {
        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT target, expected_sha256, actual_sha256
             FROM deployed_artifacts
             WHERE system_id = ?1
             ORDER BY target",
        )
        .bind(system_id)
        .fetch_all(&self.pool)
        .await
        .map_err(CoreError::ErrSqlx)?;
        Ok(rows)
    }

    /// Look up a single row by `(system_id, target)`. None
    /// if no deploy has been recorded for this artifact
    /// yet.
    pub async fn get(
        &self,
        system_id: &str,
        target: &str,
    ) -> CoreResult<Option<DeployedArtifactRow>> {
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT system_id, target, expected_sha256, actual_sha256,
                    state, deployed_at, last_verified_at
             FROM deployed_artifacts
             WHERE system_id = ?1 AND target = ?2",
        )
        .bind(system_id)
        .bind(target)
        .fetch_optional(&self.pool)
        .await
        .map_err(CoreError::ErrSqlx)?;
        Ok(row.map(|(s, t, e, a, st, d, v)| DeployedArtifactRow {
            system_id: s,
            target: t,
            expected_sha256: e,
            actual_sha256: a,
            state: st,
            deployed_at: d,
            last_verified_at: v,
        }))
    }

    /// Drop every row for a system. Used by the rollback
    /// flow (Phase 5 remaining) and by the catalog
    /// rotation path.
    pub async fn delete_for_system(&self, system_id: &str) -> CoreResult<u64> {
        let res = sqlx::query("DELETE FROM deployed_artifacts WHERE system_id = ?1")
            .bind(system_id)
            .execute(&self.pool)
            .await
            .map_err(CoreError::ErrSqlx)?;
        Ok(res.rows_affected())
    }

    /// All distinct `system_id` values present in
    /// `deployed_artifacts`, sorted alphabetically. Used by
    /// the Svelte systems route to render a list of systems
    /// that have ever been deployed through the platform.
    pub async fn list_distinct_systems(&self) -> CoreResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT system_id FROM deployed_artifacts ORDER BY system_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(CoreError::ErrSqlx)?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }
}

#[cfg(test)]
#[path = "deployed_artifacts_repository_tests.rs"]
mod tests;
