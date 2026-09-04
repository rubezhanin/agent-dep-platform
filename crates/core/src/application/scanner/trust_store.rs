//! 2.7.4 (ADR-0032) — plugin manifest
//! signature + trust store.
//!
//! A `plugin.toml` may carry an
//! `ed25519` `signature` over a
//! canonicalised form of the rest
//! of the manifest. The verifier
//! looks up the public key by
//! `signer_id` in a [`TrustStore`]
//! and rejects the plugin if either
//! lookup or verification fails.
//!
//! The trust store is operator-supplied
//! (a JSON file at
//! `~/.config/agency/trust.json` by
//! convention; the in-memory
//! `TrustStore` here is what the
//! rest of the codebase consumes).
//! Adding a new signer is an explicit
//! operator action — there is no
//! TOFU, no auto-trust.
//!
//! The canonical bytes that get
//! signed are the `plugin.toml`
//! file with the `signature` and
//! `signer_id` fields removed (so a
//! re-signing does not invalidate
//! verification). See
//! `canonical_bytes` below.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// One trusted plugin signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedSigner {
    /// Stable opaque ID referenced by
    /// `PluginManifest::signer_id`. The
    /// operator picks this — we
    /// recommend the SHA-256 of the
    /// public key (first 16 hex
    /// chars) for uniqueness, but any
    /// ASCII string works.
    pub id: String,
    /// Base64-url (no pad) Ed25519
    /// public key, 32 bytes decoded.
    pub public_key: String,
    /// Human-readable label, e.g.
    /// `acme-security@example.com`.
    /// Surfaced in error messages so
    /// the operator knows which key
    /// signed a rejected plugin.
    #[serde(default)]
    pub label: Option<String>,
}

/// In-memory trust store. The
/// operator-supplied JSON file is
/// parsed into this struct; the
/// rest of the code only ever
/// talks to `verify` / `get`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustStore {
    /// Signer-ID → public key.
    #[serde(default)]
    signers: BTreeMap<String, TrustedSigner>,
}

impl TrustStore {
    /// Parse a trust-store JSON
    /// document. The expected shape
    /// is `{ "signers": [ { id,
    /// public_key, label }, ... ] }`
    /// — the `signers` array form is
    /// what an operator would hand-
    /// write; a `signers` map is
    /// also accepted (the keys
    /// supply the `id` field).
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        // Try the array form first
        // (canonical for hand-written
        // config), then fall back to
        // the map form. The map
        // variant uses a *partial*
        // signer so the JSON may
        // omit `id` (we fill it in
        // from the map key).
        #[derive(Deserialize)]
        struct PartialSigner {
            #[serde(default)]
            id: String,
            public_key: String,
            #[serde(default)]
            label: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Array {
                signers: Vec<TrustedSigner>,
            },
            Map {
                signers: BTreeMap<String, PartialSigner>,
            },
        }
        let parsed: Either = serde_json::from_slice(bytes).map_err(|e| {
            CoreError::ErrSchemaInvalid {
                path: "trust_store".to_string(),
                reason: format!("parse: {e}"),
            }
        })?;
        let mut store = TrustStore::default();
        match parsed {
            Either::Array { signers } => {
                for s in signers {
                    Self::validate_signer(&s)?;
                    store.signers.insert(s.id.clone(), s);
                }
            }
            Either::Map { signers } => {
                for (id, p) in signers {
                    let s = TrustedSigner {
                        id: p.id.clone(),
                        public_key: p.public_key,
                        label: p.label,
                    };
                    // The map key is the
                    // canonical id; if
                    // the operator also
                    // put an `id` inside
                    // the object, the two
                    // must agree.
                    if !p.id.is_empty() && p.id != id {
                        return Err(CoreError::ErrSchemaInvalid {
                            path: "trust_store.signer.id".to_string(),
                            reason: format!(
                                "id mismatch: map key `{id}` vs object `{}`",
                                p.id
                            ),
                        });
                    }
                    let s = TrustedSigner {
                        id: id.clone(),
                        ..s
                    };
                    Self::validate_signer(&s)?;
                    store.signers.insert(s.id.clone(), s);
                }
            }
        }
        Ok(store)
    }

    /// Load from a file. A missing
    /// file is not an error — it
    /// yields an empty trust store,
    /// which rejects every signed
    /// manifest.
    pub fn load(path: &Path) -> CoreResult<Self> {
        if !path.exists() {
            return Ok(TrustStore::default());
        }
        let bytes = std::fs::read(path).map_err(CoreError::ErrIo)?;
        Self::parse(&bytes)
    }

    fn validate_signer(s: &TrustedSigner) -> CoreResult<()> {
        if s.id.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "trust_store.signer.id".to_string(),
                reason: "id must not be empty".to_string(),
            });
        }
        let key_bytes = decode_public_key(&s.public_key)?;
        // 32 bytes for Ed25519.
        if key_bytes.len() != 32 {
            return Err(CoreError::ErrSchemaInvalid {
                path: "trust_store.signer.public_key".to_string(),
                reason: format!(
                    "expected 32 bytes, got {}",
                    key_bytes.len()
                ),
            });
        }
        // Construct the key once so
        // an off-curve / non-canonical
        // key fails at parse time, not
        // at every verify call.
        let key_arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            CoreError::ErrSchemaInvalid {
                path: "trust_store.signer.public_key".to_string(),
                reason: format!("expected 32 bytes, got {}", key_bytes.len()),
            }
        })?;
        VerifyingKey::from_bytes(&key_arr).map_err(|e| {
            CoreError::ErrSchemaInvalid {
                path: "trust_store.signer.public_key".to_string(),
                reason: format!("invalid Ed25519 key: {e}"),
            }
        })?;
        Ok(())
    }

    /// Look up a signer by `id`.
    pub fn get(&self, id: &str) -> Option<&TrustedSigner> {
        self.signers.get(id)
    }

    /// Number of trusted signers.
    pub fn len(&self) -> usize {
        self.signers.len()
    }

    /// `true` if the trust store has
    /// no signers (every signed
    /// manifest is rejected).
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }

    /// Verify an Ed25519 signature
    /// over `message` produced by
    /// the signer with id `signer_id`.
    /// Returns `Ok(())` on success.
    pub fn verify(
        &self,
        signer_id: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> CoreResult<()> {
        let signer = self.get(signer_id).ok_or_else(|| {
            CoreError::ErrSchemaInvalid {
                path: "plugin.signature.signer_id".to_string(),
                reason: format!("unknown signer `{signer_id}`"),
            }
        })?;
        let key_bytes = decode_public_key(&signer.public_key)?;
        let key_arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            CoreError::ErrSchemaInvalid {
                path: "trust_store.signer.public_key".to_string(),
                reason: format!("expected 32 bytes, got {}", key_bytes.len()),
            }
        })?;
        let key = VerifyingKey::from_bytes(&key_arr).map_err(|e| {
            CoreError::ErrSchemaInvalid {
                path: "trust_store.signer.public_key".to_string(),
                reason: format!("invalid Ed25519 key: {e}"),
            }
        })?;
        let sig_bytes = decode_signature(signature_b64)?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            CoreError::ErrSchemaInvalid {
                path: "plugin.signature".to_string(),
                reason: format!("expected 64 bytes, got {}", sig_bytes.len()),
            }
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        key.verify(message, &sig).map_err(|e| {
            CoreError::ErrSchemaInvalid {
                path: "plugin.signature".to_string(),
                reason: format!(
                    "signature verification failed (signer=`{}` label={:?}): {e}",
                    signer.id, signer.label
                ),
            }
        })?;
        Ok(())
    }
}

/// Decode a base64-url (no pad)
/// Ed25519 public key.
fn decode_public_key(s: &str) -> CoreResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CoreError::ErrSchemaInvalid {
            path: "trust_store.signer.public_key".to_string(),
            reason: format!("base64: {e}"),
        })
}

/// Decode a base64-url (no pad)
/// 64-byte Ed25519 signature.
fn decode_signature(s: &str) -> CoreResult<Vec<u8>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CoreError::ErrSchemaInvalid {
            path: "plugin.signature".to_string(),
            reason: format!("base64: {e}"),
        })?;
    if bytes.len() != 64 {
        return Err(CoreError::ErrSchemaInvalid {
            path: "plugin.signature".to_string(),
            reason: format!(
                "expected 64 bytes, got {}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    /// Generate a fresh Ed25519 key
    /// pair; return (signer_id,
    /// public_b64, signing_key,
    /// label).
    fn fresh_signer(_label: &str) -> (String, String, SigningKey) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_bytes);
        // Derive signer_id from the
        // public key (first 16 hex of
        // sha256) — the recommended
        // convention in the ADR.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(pk_bytes);
        let id = hex::encode(&h.finalize()[..8]);
        (id, pk_b64, sk)
    }

    fn trust_store(signers: Vec<TrustedSigner>) -> TrustStore {
        let mut ts = TrustStore::default();
        for s in signers {
            ts.signers.insert(s.id.clone(), s);
        }
        ts
    }

    #[test]
    fn parse_array_form() {
        let (_id, pk, _sk) = fresh_signer("acme");
        let json = serde_json::json!({
            "signers": [{
                "id": "acme",
                "public_key": pk,
                "label": "acme@example.com",
            }]
        })
        .to_string();
        let ts = TrustStore::parse(json.as_bytes()).expect("parse");
        assert_eq!(ts.len(), 1);
        assert_eq!(ts.get("acme").unwrap().label.as_deref(), Some("acme@example.com"));
    }

    #[test]
    fn parse_map_form_uses_keys_as_ids() {
        let (_id, pk, _sk) = fresh_signer("acme");
        let json = serde_json::json!({
            "signers": {
                "acme": {
                    "public_key": pk,
                    "label": "acme@example.com",
                }
            }
        })
        .to_string();
        let ts = TrustStore::parse(json.as_bytes()).expect("parse");
        assert_eq!(ts.get("acme").map(|s| s.id.clone()), Some("acme".to_string()));
    }

    #[test]
    fn parse_rejects_malformed_key() {
        // 31 bytes — not a valid Ed25519 key.
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(vec![0u8; 31]);
        let json = serde_json::json!({
            "signers": [{
                "id": "acme",
                "public_key": bad,
            }]
        })
        .to_string();
        let err = TrustStore::parse(json.as_bytes()).expect_err("must reject");
        assert!(format!("{err:?}").contains("expected 32 bytes"));
    }

    #[test]
    fn verify_happy_path() {
        let (id, pk, sk) = fresh_signer("acme");
        let ts = trust_store(vec![TrustedSigner {
            id: id.clone(),
            public_key: pk,
            label: Some("acme@example.com".to_string()),
        }]);
        let msg = b"plugin manifest canonical bytes";
        let sig = sk.sign(msg);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sig.to_bytes());
        ts.verify(&id, msg, &sig_b64).expect("verify must pass");
    }

    #[test]
    fn verify_rejects_unknown_signer() {
        let ts = TrustStore::default();
        let err = ts.verify("nobody", b"msg", "AAAA")
            .expect_err("must reject");
        assert!(format!("{err:?}").contains("unknown signer"));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (id, pk, sk) = fresh_signer("acme");
        let ts = trust_store(vec![TrustedSigner {
            id: id.clone(),
            public_key: pk,
            label: None,
        }]);
        let sig = sk.sign(b"original message");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sig.to_bytes());
        let err = ts
            .verify(&id, b"tampered message", &sig_b64)
            .expect_err("must reject");
        assert!(format!("{err:?}").contains("signature verification failed"));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (id, _pk, _sk) = fresh_signer("acme");
        // Build a trust store whose
        // entry for `id` points at a
        // *different* key.
        let (_id2, pk_other, _sk2) = fresh_signer("other");
        let ts = trust_store(vec![TrustedSigner {
            id: id.clone(),
            public_key: pk_other,
            label: None,
        }]);
        let sk3 = SigningKey::generate(&mut rand::rngs::OsRng);
        let msg = b"some bytes";
        let sig = sk3.sign(msg);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sig.to_bytes());
        let err = ts
            .verify(&id, msg, &sig_b64)
            .expect_err("must reject (signer ID matches but key does not)");
        assert!(format!("{err:?}").contains("signature verification failed"));
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let (id, pk, _sk) = fresh_signer("acme");
        let ts = trust_store(vec![TrustedSigner {
            id: id.clone(),
            public_key: pk,
            label: None,
        }]);
        // 63 bytes — too short.
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(vec![0u8; 63]);
        let err = ts
            .verify(&id, b"msg", &bad)
            .expect_err("must reject");
        assert!(format!("{err:?}").contains("expected 64 bytes"));
    }
}
