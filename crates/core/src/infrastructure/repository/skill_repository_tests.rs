use super::*;
use crate::domain::version::Version;
use uuid::Uuid;

async fn make_db_with_snapshot() -> (tempfile::TempDir, SkillRepository, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let db = crate::infrastructure::sqlite::connect(&path)
        .await
        .unwrap();
    db.migrate().await.unwrap();
    // Create a minimal `sources` row so the FK on
    // `source_snapshots.source_id` is satisfied.
    let source_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sources (id, kind, location, display_name, created_at)
         VALUES (?1, 'local', '/tmp/skill-test', 'skill-test', '2026-01-01T00:00:00Z')",
    )
    .bind(source_id.to_string())
    .execute(db.pool())
    .await
    .unwrap();
    let snap_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_snapshots
            (id, source_id, commit_sha, status, agent_count, division_count, created_at)
         VALUES (?1, ?2, 'deadbeef', 'active', 0, 0, '2026-01-01T00:00:00Z')",
    )
    .bind(snap_id.to_string())
    .bind(source_id.to_string())
    .execute(db.pool())
    .await
    .unwrap();
    (dir, SkillRepository::new(db.pool().clone()), snap_id)
}

fn make_skill(id: &str, version: &str) -> Skill {
    Skill {
        snapshot_id: Uuid::nil(),
        id: id.to_string(),
        name: format!("{id} display"),
        version: Version::parse(version).unwrap(),
        description: format!("{id} desc"),
        tags: vec!["t1".to_string(), "t2".to_string()],
        body: format!("{id} body"),
        body_hash: Skill::sha256_hex(format!("{id} body").as_bytes()),
        dependencies: vec![SkillDependency {
            id: "other".to_string(),
            version: Version::parse("1.0.0").unwrap(),
        }],
        permissions: vec![
            SkillPermission::ReadEnv,
            SkillPermission::Filesystem,
        ],
    }
}

#[tokio::test]
async fn insert_then_list_round_trips_skills() {
    let (_dir, repo, snap) = make_db_with_snapshot().await;
    let skills = vec![make_skill("postgres", "3.1.0")];
    repo.insert_snapshot_skills(snap, &skills)
        .await
        .expect("insert");

    let loaded = repo.list_skills_for_snapshot(snap).await.expect("list");
    assert_eq!(loaded.len(), 1);
    let s = &loaded[0];
    assert_eq!(s.id, "postgres");
    assert_eq!(s.version, Version::parse("3.1.0").unwrap());
    assert_eq!(s.tags, vec!["t1".to_string(), "t2".to_string()]);
    assert_eq!(s.dependencies.len(), 1);
    assert_eq!(s.dependencies[0].id, "other");
    assert_eq!(
        s.permissions,
        vec![SkillPermission::ReadEnv, SkillPermission::Filesystem]
    );
}

#[tokio::test]
async fn insert_replaces_existing_skill_in_same_snapshot() {
    let (_dir, repo, snap) = make_db_with_snapshot().await;
    let s1 = Skill {
        body: "v1".to_string(),
        body_hash: Skill::sha256_hex(b"v1"),
        ..make_skill("postgres", "3.1.0")
    };
    repo.insert_snapshot_skills(snap, &[s1])
        .await
        .expect("first");

    let s2 = Skill {
        body: "v2".to_string(),
        body_hash: Skill::sha256_hex(b"v2"),
        ..make_skill("postgres", "3.1.0")
    };
    repo.insert_snapshot_skills(snap, &[s2])
        .await
        .expect("second (replace)");

    let loaded = repo.list_skills_for_snapshot(snap).await.unwrap();
    assert_eq!(loaded.len(), 1, "no duplicate row");
    assert_eq!(loaded[0].body, "v2");
    assert_eq!(loaded[0].body_hash, Skill::sha256_hex(b"v2"));
}

#[tokio::test]
async fn list_for_unknown_snapshot_is_empty() {
    let (_dir, repo, _snap) = make_db_with_snapshot().await;
    let loaded = repo
        .list_skills_for_snapshot(Uuid::new_v4())
        .await
        .expect("list empty");
    assert!(loaded.is_empty());
}
