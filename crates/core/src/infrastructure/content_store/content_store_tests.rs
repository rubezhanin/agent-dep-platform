use crate::infrastructure::content_store::ContentStore;

fn temp_root() -> std::path::PathBuf {
    let d = tempfile::tempdir().unwrap();
    d.keep()
}

#[test]
fn put_and_get_roundtrip() {
    let root = temp_root();
    let cas = ContentStore::new(root.clone()).unwrap();
    let data = b"hello world";
    let hash = cas.put(data).unwrap();
    assert_eq!(hash.len(), 64); // sha256 hex
    let got = cas.get(&hash).unwrap().unwrap();
    assert_eq!(got, data);
}

#[test]
fn put_is_deterministic() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let h1 = cas.put(b"abc").unwrap();
    let h2 = cas.put(b"abc").unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn put_uses_sha256_layout() {
    let root = temp_root();
    let cas = ContentStore::new(root.clone()).unwrap();
    let data = b"test";
    let hash = cas.put(data).unwrap();
    let expected = root
        .join("sha256")
        .join(&hash[..2])
        .join(&hash[2..4])
        .join(&hash);
    assert!(expected.exists(), "expected {expected:?} to exist");
}

#[test]
fn get_nonexistent_returns_none() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let got = cas
        .get("0000000000000000000000000000000000000000000000000000000000000000")
        .unwrap();
    assert!(got.is_none());
}

#[test]
fn exists_correct() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let hash = cas.put(b"present").unwrap();
    assert!(cas.exists(&hash));
    assert!(!cas.exists("0000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn new_creates_root_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cas-root");
    assert!(!root.exists());
    let _ = ContentStore::new(root.clone()).unwrap();
    assert!(root.exists());
    let cas_root = root.join("sha256");
    assert!(cas_root.is_dir());
}

#[test]
fn path_uses_safe_path() {
    let root = temp_root();
    let cas = ContentStore::new(root.clone()).unwrap();
    let hash = "ab".to_string() + &"c".repeat(62);
    let p = cas.path(&hash).unwrap();
    assert!(p.to_string_lossy().contains("sha256"));
    assert!(p.to_string_lossy().contains(&hash[..2]));
}

#[test]
fn large_content_roundtrip() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let big = vec![0xABu8; 1024 * 1024]; // 1 MiB
    let hash = cas.put(&big).unwrap();
    let got = cas.get(&hash).unwrap().unwrap();
    assert_eq!(got.len(), big.len());
    assert_eq!(got, big);
}

#[test]
fn empty_content_is_allowed() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let hash = cas.put(b"").unwrap();
    let got = cas.get(&hash).unwrap().unwrap();
    assert!(got.is_empty());
}

#[test]
fn rejects_malformed_hash() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    // Too short
    let r = cas.path("abc");
    assert!(r.is_err());
    // Non-hex
    let r = cas.path("zz".to_string().repeat(32).as_str());
    assert!(r.is_err());
}
