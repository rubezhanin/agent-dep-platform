//! Persistence for skills (TZ Enterprise v2 §7).
//!
//! Phase 1B addition. Skills are per-snapshot and live in the
//! `skills` table along with their tag/dependency/permission
//! rows (migration 005). The repository mirrors the
//! `IngestRepository` pattern: one transaction per snapshot,
// child rows written after the parent `skills` rows.

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::domain::skill::{Skill, SkillDependency, SkillPermission};
use crate::domain::version::Version;
use crate::error::{CoreError, CoreResult};

pub struct SkillRepository {
    pool: SqlitePool,
}

impl SkillRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Insert all skills for a snapshot in a single transaction.
    /// Existing rows for the same `(snapshot_id, skill_id)` are
    /// replaced (the caller is expected to have flipped the
    /// previous Active snapshot to Superseded before calling).
    pub async fn insert_snapshot_skills(
        &self,
        snapshot_id: Uuid,
        skills: &[Skill],
    ) -> CoreResult<()> {
        let mut tx = self.pool.begin().await?;
        for skill in skills {
            // Replace any previous row for this key.
            sqlx::query("DELETE FROM skills WHERE snapshot_id = ?1 AND id = ?2")
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM skill_tags WHERE snapshot_id = ?1 AND skill_id = ?2")
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM skill_dependencies WHERE snapshot_id = ?1 AND skill_id = ?2")
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM skill_permissions WHERE snapshot_id = ?1 AND skill_id = ?2")
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .execute(&mut *tx)
                .await?;

            sqlx::query(
                "INSERT INTO skills
                    (id, snapshot_id, name, version, description, body, body_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&skill.id)
            .bind(snapshot_id.to_string())
            .bind(&skill.name)
            .bind(skill.version.to_string())
            .bind(&skill.description)
            .bind(&skill.body)
            .bind(&skill.body_hash)
            .execute(&mut *tx)
            .await?;

            for (i, tag) in skill.tags.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO skill_tags
                        (snapshot_id, skill_id, position, tag)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .bind(i as i64)
                .bind(tag)
                .execute(&mut *tx)
                .await?;
            }
            for (i, dep) in skill.dependencies.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO skill_dependencies
                        (snapshot_id, skill_id, position, dependency)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .bind(i as i64)
                .bind(format!("{}@{}", dep.id, dep.version))
                .execute(&mut *tx)
                .await?;
            }
            for (i, perm) in skill.permissions.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO skill_permissions
                        (snapshot_id, skill_id, position, permission)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(snapshot_id.to_string())
                .bind(&skill.id)
                .bind(i as i64)
                .bind(perm_to_str(perm))
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Load all skills for a snapshot, ordered by id.
    pub async fn list_skills_for_snapshot(&self, snapshot_id: Uuid) -> CoreResult<Vec<Skill>> {
        let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, name, version, description, body, body_hash
                 FROM skills
                 WHERE snapshot_id = ?1
                 ORDER BY id",
        )
        .bind(snapshot_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<Skill> = Vec::with_capacity(rows.len());
        for (id, name, version, description, body, body_hash) in rows {
            let version = Version::parse(&version).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "skills.version".to_string(),
                reason: format!("{e}"),
            })?;
            let tags: Vec<String> = sqlx::query_as::<_, (i64, String)>(
                "SELECT position, tag FROM skill_tags
                 WHERE snapshot_id = ?1 AND skill_id = ?2
                 ORDER BY position",
            )
            .bind(snapshot_id.to_string())
            .bind(&id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|(_, t)| t)
            .collect();
            let deps: Vec<SkillDependency> = sqlx::query_as::<_, (String,)>(
                "SELECT dependency FROM skill_dependencies
                 WHERE snapshot_id = ?1 AND skill_id = ?2
                 ORDER BY position",
            )
            .bind(snapshot_id.to_string())
            .bind(&id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .filter_map(|(s,)| {
                let (did, ver) = s.split_once('@')?;
                let v = Version::parse(ver).ok()?;
                Some(SkillDependency {
                    id: did.to_string(),
                    version: v,
                })
            })
            .collect();
            let perms: Vec<SkillPermission> = sqlx::query_as::<_, (String,)>(
                "SELECT permission FROM skill_permissions
                 WHERE snapshot_id = ?1 AND skill_id = ?2
                 ORDER BY position",
            )
            .bind(snapshot_id.to_string())
            .bind(&id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .filter_map(|(s,)| perm_from_str(&s))
            .collect();
            out.push(Skill {
                snapshot_id,
                id,
                name,
                version,
                description,
                tags,
                body: body.clone(),
                body_hash,
                dependencies: deps,
                permissions: perms,
            });
        }
        Ok(out)
    }
}

fn perm_to_str(p: &SkillPermission) -> &'static str {
    match p {
        SkillPermission::ReadEnv => "read_env",
        SkillPermission::SpawnProcess => "spawn_process",
        SkillPermission::Network => "network",
        SkillPermission::Filesystem => "filesystem",
    }
}

fn perm_from_str(s: &str) -> Option<SkillPermission> {
    match s {
        "read_env" => Some(SkillPermission::ReadEnv),
        "spawn_process" => Some(SkillPermission::SpawnProcess),
        "network" => Some(SkillPermission::Network),
        "filesystem" => Some(SkillPermission::Filesystem),
        _ => None,
    }
}

#[cfg(test)]
#[path = "skill_repository_tests.rs"]
mod tests;
