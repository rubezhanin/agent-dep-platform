use clap::CommandFactory;

#[test]
fn cli_parses_help() {
    let cmd = crate::Cli::command();
    let help = cmd.clone().render_help();
    assert!(help.to_string().contains("agency"));
}

#[test]
fn cli_has_deploy_status_and_catalog_system_subcommands() {
    let cmd = crate::Cli::command();
    let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
    assert!(names.contains(&"deploy"));
    assert!(names.contains(&"status"));
    assert!(names.contains(&"catalog"));
    assert!(names.contains(&"system"));
}

#[test]
fn system_subcommand_has_plan() {
    let cmd = crate::Cli::command();
    let system = cmd
        .get_subcommands()
        .find(|c| c.get_name() == "system")
        .expect("system subcommand");
    let sub_names: Vec<&str> = system.get_subcommands().map(|c| c.get_name()).collect();
    assert!(sub_names.contains(&"plan"));
}

#[test]
fn catalog_subcommand_has_update() {
    let cmd = crate::Cli::command();
    let catalog = cmd
        .get_subcommands()
        .find(|c| c.get_name() == "catalog")
        .expect("catalog subcommand");
    let sub_names: Vec<&str> = catalog.get_subcommands().map(|c| c.get_name()).collect();
    assert!(sub_names.contains(&"update"));
}

// -----------------------------------------------------------------------
// End-to-end tests for `catalog::update_at`
// -----------------------------------------------------------------------

mod catalog_e2e {
    use std::fs;
    use std::path::PathBuf;

    use agent_dep_core::infrastructure::repository::IngestRepository;
    use agent_dep_core::infrastructure::sqlite::{connect, schema_version};

    fn write_fixture(root: &std::path::Path) {
        fs::write(
            root.join("divisions.json"),
            r#"{
                "_note": "e2e",
                "divisions": [
                    {"id": "engineering", "order": 1, "label": "Engineering"}
                ]
            }"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("agents/engineering")).unwrap();
        fs::write(
            root.join("agents/engineering/dev.md"),
            "---\n\
             id: dev\n\
             name: Dev\n\
             division: engineering\n\
             role: x\n\
             description: x\n\
             version: 1.0.0\n\
             ---\n\
             body\n",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn update_at_persists_snapshot_and_advances_schema() {
        let cat_dir = tempfile::tempdir().unwrap();
        write_fixture(cat_dir.path());

        let db_dir = tempfile::tempdir().unwrap();
        let db_path: PathBuf = db_dir.path().join("agency.db");

        let s = crate::commands::catalog::update_at(cat_dir.path(), &db_path)
            .await
            .expect("update_at");

        assert_eq!(s.agent_count, 1);
        assert_eq!(s.division_count, 1);
        assert_eq!(s.rejected, 0);
        assert!(s.commit_sha.len() == 64, "sha256 hex = 64 chars");
        assert!(s.snapshot_id.to_string().len() == 36);

        // Re-open the DB and verify state.
        let db = connect(&db_path).await.expect("reopen");
        assert_eq!(schema_version(&db).await.unwrap(), 4);
        let repo = IngestRepository::new(db.pool().clone());
        let source = repo
            .find_source_by_location("local", &cat_dir.path().to_string_lossy())
            .await
            .unwrap()
            .expect("source");
        let snaps = repo.list_snapshots(source.id).await.unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].snapshot.commit_sha, s.commit_sha);
    }

    #[tokio::test]
    async fn update_at_rejects_missing_directory() {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path: PathBuf = db_dir.path().join("agency.db");
        let missing = db_dir.path().join("does-not-exist");
        let err = crate::commands::catalog::update_at(&missing, &db_path)
            .await
            .expect_err("should error on missing dir");
        assert!(err.to_string().contains("not a directory"));
    }

    #[tokio::test]
    async fn update_at_is_idempotent_across_runs() {
        let cat_dir = tempfile::tempdir().unwrap();
        write_fixture(cat_dir.path());
        let db_dir = tempfile::tempdir().unwrap();
        let db_path: PathBuf = db_dir.path().join("agency.db");

        let s1 = crate::commands::catalog::update_at(cat_dir.path(), &db_path)
            .await
            .unwrap();
        let s2 = crate::commands::catalog::update_at(cat_dir.path(), &db_path)
            .await
            .unwrap();

        assert_eq!(s1.commit_sha, s2.commit_sha);
        // Two snapshot rows (one Active, one Superseded) on the same source.
        let db = connect(&db_path).await.unwrap();
        let repo = IngestRepository::new(db.pool().clone());
        let source = repo
            .find_source_by_location("local", &cat_dir.path().to_string_lossy())
            .await
            .unwrap()
            .unwrap();
        let snaps = repo.list_snapshots(source.id).await.unwrap();
        assert_eq!(snaps.len(), 2);
    }

    #[tokio::test]
    async fn update_at_blocks_snapshot_when_scanner_finds_secret() {
        // Catalog with a legitimate agent AND a malicious file in
        // the agents/ tree. The scanner should fire on the AWS key
        // pattern and the snapshot should be Blocked.
        let cat_dir = tempfile::tempdir().unwrap();
        write_fixture(cat_dir.path());
        fs::write(
            cat_dir.path().join("agents/engineering/secret.md"),
            "---\n\
             id: secret\n\
             name: Bad\n\
             division: engineering\n\
             role: x\n\
             description: leaked\n\
             version: 1.0.0\n\
             ---\n\
             # Setup\n\
             Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in your env.\n",
        )
        .unwrap();

        let db_dir = tempfile::tempdir().unwrap();
        let db_path: PathBuf = db_dir.path().join("agency.db");

        let s = crate::commands::catalog::update_at(cat_dir.path(), &db_path)
            .await
            .expect("update_at");

        assert_eq!(s.findings_block, 1, "one BLOCK finding for the AWS key");
        assert!(s.snapshot_status.contains("Blocked"));
        assert!(!s.top_findings.is_empty());
        assert_eq!(s.top_findings[0].rule, "secret.aws-access-key");

        // DB should reflect Blocked status + the persisted finding.
        let db = connect(&db_path).await.expect("reopen");
        let repo = IngestRepository::new(db.pool().clone());
        let source = repo
            .find_source_by_location("local", &cat_dir.path().to_string_lossy())
            .await
            .unwrap()
            .unwrap();
        let snaps = repo.list_snapshots(source.id).await.unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(
            snaps[0].snapshot.status,
            agent_dep_core::domain::source::SnapshotStatus::Blocked
        );
        assert_eq!(snaps[0].finding_count, 1);
        let detail = repo
            .get_snapshot_detail(snaps[0].snapshot.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(detail.findings.len(), 1);
        assert_eq!(
            detail.findings[0].severity,
            agent_dep_core::application::scanner::Severity::Block
        );
        assert_eq!(detail.findings[0].rule, "secret.aws-access-key");
        assert!(detail.findings[0].path.ends_with("secret.md"));
    }
}

// -----------------------------------------------------------------------
// End-to-end tests for `system::plan_at`
// -----------------------------------------------------------------------

mod system_e2e {
    use std::fs;

    fn write_catalog(root: &std::path::Path) {
        fs::write(
            root.join("divisions.json"),
            r#"{
                "_note": "e2e",
                "divisions": [
                    {"id": "engineering", "order": 1, "label": "Engineering"}
                ]
            }"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("agents/engineering")).unwrap();
        fs::write(
            root.join("agents/engineering/be.md"),
            "---\n\
             id: be\n\
             name: Backend Engineer\n\
             division: engineering\n\
             role: builds APIs\n\
             description: backend\n\
             version: 1.0.0\n\
             ---\n\
             body\n",
        )
        .unwrap();
        fs::write(
            root.join("agents/engineering/fe.md"),
            "---\n\
             id: fe\n\
             name: Frontend Engineer\n\
             division: engineering\n\
             role: builds UIs\n\
             description: frontend\n\
             version: 1.0.0\n\
             ---\n\
             body\n",
        )
        .unwrap();
    }

    fn write_system_yaml(path: &std::path::Path, refs: &[&str]) {
        let yaml = format!(
            "apiVersion: agent-dep/v1\n\
             kind: System\n\
             metadata:\n  \
               id: saas\n  \
               name: SaaS\n\
             spec:\n  \
               source: agency-agents\n  \
               agents:\n{}\n",
            refs.iter()
                .map(|r| format!("    - ref: {r}\n"))
                .collect::<String>()
        );
        fs::write(path, yaml).unwrap();
    }

    #[tokio::test]
    async fn plan_at_resolves_refs_against_local_catalog() {
        let cat_dir = tempfile::tempdir().unwrap();
        write_catalog(cat_dir.path());

        let sys_file = tempfile::tempdir().unwrap();
        let sys_path = sys_file.path().join("system.yaml");
        write_system_yaml(&sys_path, &["be@1.0.0", "fe@1.0.0"]);

        let s = crate::commands::system::plan_at(&sys_path, cat_dir.path())
            .await
            .expect("plan_at");

        assert_eq!(s.system_id, "saas");
        assert_eq!(s.operations.len(), 2);
        assert!(s.operations.iter().all(|o| o.kind == "ADD"));
        let targets: Vec<&str> = s.operations.iter().map(|o| o.target.as_str()).collect();
        assert!(targets.contains(&"agent:be@1.0.0"));
        assert!(targets.contains(&"agent:fe@1.0.0"));
        assert_eq!(s.risk, "low");
    }

    #[tokio::test]
    async fn plan_at_rejects_missing_agent() {
        let cat_dir = tempfile::tempdir().unwrap();
        write_catalog(cat_dir.path());

        let sys_file = tempfile::tempdir().unwrap();
        let sys_path = sys_file.path().join("system.yaml");
        write_system_yaml(&sys_path, &["be@1.0.0", "ghost@1.0.0"]);

        let err = crate::commands::system::plan_at(&sys_path, cat_dir.path())
            .await
            .expect_err("ghost agent");
        assert!(err.to_string().contains("ghost"));
    }

    #[tokio::test]
    async fn plan_at_rejects_missing_system_file() {
        let cat_dir = tempfile::tempdir().unwrap();
        let missing = cat_dir.path().join("system.yaml");
        let err = crate::commands::system::plan_at(&missing, cat_dir.path())
            .await
            .expect_err("missing file");
        assert!(err.to_string().contains("not a file"));
    }

    #[tokio::test]
    async fn plan_at_rejects_missing_catalog_dir() {
        let sys_file = tempfile::tempdir().unwrap();
        let sys_path = sys_file.path().join("system.yaml");
        write_system_yaml(&sys_path, &["be@1.0.0"]);
        let missing = sys_file.path().join("nope");
        let err = crate::commands::system::plan_at(&sys_path, &missing)
            .await
            .expect_err("missing dir");
        assert!(err.to_string().contains("not a directory"));
    }

    #[tokio::test]
    async fn plan_at_rejects_malformed_yaml() {
        let cat_dir = tempfile::tempdir().unwrap();
        write_catalog(cat_dir.path());
        let sys_file = tempfile::tempdir().unwrap();
        let sys_path = sys_file.path().join("system.yaml");
        fs::write(&sys_path, "not: a: system: file").unwrap();
        let err = crate::commands::system::plan_at(&sys_path, cat_dir.path())
            .await
            .expect_err("bad yaml");
        assert!(err.to_string().contains("parse"));
    }
}
