//! SQLite metadata store. Schema is migration-based (`migrations/*.sql`).
//!
//! Per TZ §11.1: SQLite stores metadata only (sources, snapshots, agents, skills,
//! systems, deployments, operations, audit, policy). Immutable content lives in
//! the content-addressed store (Task 5). SQLite MUST NOT be a source of truth
//! for System definitions (TZ §26.2) — those are YAML/JSON in Git.

use crate::error::CoreResult;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

pub struct Db {
    pool: SqlitePool,
}

impl Db {
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn migrate(&self) -> CoreResult<()> {
        // `./migrations` is resolved against the `crates/core/` package root,
        // not the source file. The migration files live at
        // `crates/core/migrations/*.sql`.
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| crate::error::CoreError::ErrSqlx(sqlx::Error::Migrate(Box::new(e))))?;
        Ok(())
    }
}

pub async fn connect(path: &Path) -> CoreResult<Db> {
    let url = if path == Path::new(":memory:") {
        "sqlite::memory:".to_string()
    } else {
        format!("sqlite://{}", path.to_string_lossy())
    };
    let opts = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    Ok(Db { pool })
}

pub async fn schema_version(db: &Db) -> CoreResult<i64> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM meta WHERE key = 'schema_version'")
            .fetch_optional(db.pool())
            .await?;
    match row {
        Some((v,)) => v.parse::<i64>().map_err(|e| {
            crate::error::CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad schema_version: {e}"),
            ))
        }),
        None => Ok(0),
    }
}

#[cfg(test)]
#[path = "sqlite_tests.rs"]
mod sqlite_tests;
