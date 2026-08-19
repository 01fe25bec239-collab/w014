//! Unit tests for authentication, session, rotation, and transaction invariants in w014-authn.

use chrono::{Duration, Utc};
use w014_authn::error::AuthnError;
use w014_authn::identity::OidcIdentity;
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{Session, SessionId, SessionStatus};
use w014_authn::transaction::OidcTransaction;
use w014_domain::ids::PrincipalId;

#[test]
fn test_oidc_identity_invariants() {
    let p_id = PrincipalId::new();
    let claims = serde_json::json!({
        "iss": "https://accounts.google.com",
        "sub": "user-sub-12345",
        "email": "user@example.com"
    });

    let identity = OidcIdentity::new(
        p_id,
        "https://accounts.google.com",
        "user-sub-12345",
        Some("user@example.com"),
        claims.clone(),
    )
    .unwrap();

    assert_eq!(identity.principal_id, p_id);
    assert_eq!(identity.issuer, "https://accounts.google.com");
    assert_eq!(identity.subject, "user-sub-12345");
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
    assert_eq!(
        identity.identity_key(),
        ("https://accounts.google.com", "user-sub-12345")
    );

    // Empty issuer/subject rejected
    assert!(OidcIdentity::new(p_id, "   ", "sub", None::<&str>, claims.clone()).is_err());
    assert!(OidcIdentity::new(p_id, "https://issuer.com", "   ", None::<&str>, claims).is_err());
}

#[test]
fn test_session_lifecycle_and_status_invariants() {
    let p_id = PrincipalId::new();
    let now = Utc::now();
    let idle_expires = now + Duration::hours(12);
    let abs_expires = now + Duration::days(7);

    let mut session = Session::new(
        p_id,
        b"session_hash_abcdef0123456789012".to_vec(),
        b"csrf_secret_hash_abcdef012345678".to_vec(),
        idle_expires,
        abs_expires,
    )
    .unwrap();

    assert_eq!(session.status_at(now), SessionStatus::Active);
    assert!(session.is_active_at(now));
    assert!(!session.is_expired_at(now));

    // Touch session
    let touch_time = now + Duration::hours(1);
    let idle_ttl = Duration::hours(12);
    session.touch(touch_time, idle_ttl).unwrap();
    assert_eq!(session.last_seen_at, touch_time);
    assert_eq!(session.idle_expires_at, touch_time + idle_ttl);

    // Revocation
    session.revoke(touch_time);
    assert_eq!(session.status_at(touch_time), SessionStatus::Revoked);
    assert!(!session.is_active_at(touch_time));
    assert!(
        session
            .touch(touch_time + Duration::minutes(1), idle_ttl)
            .is_err()
    );
}

#[test]
fn test_session_rotation_invariants() {
    let s_id = SessionId::new();

    // Valid rotation
    let rot = SessionRotation::new(
        s_id,
        b"old_token_hash_val".to_vec(),
        b"new_token_hash_val".to_vec(),
        Some("10.0.0.1"),
    )
    .unwrap();

    assert_eq!(rot.session_id, s_id);
    assert_eq!(rot.old_handle_hash, b"old_token_hash_val".to_vec());
    assert_eq!(rot.new_handle_hash, b"new_token_hash_val".to_vec());

    // Identical hash rejected
    let err = SessionRotation::new(
        s_id,
        b"same_hash".to_vec(),
        b"same_hash".to_vec(),
        None::<&str>,
    )
    .unwrap_err();
    assert_eq!(err, AuthnError::IdenticalRotationHashes);
}

#[test]
fn test_oidc_transaction_validity_invariants() {
    let now = Utc::now();
    let expires = now + Duration::minutes(5);

    let tx = OidcTransaction::new(
        "state_token_12345",
        "nonce_67890",
        Some("pkce_verifier_abcde"),
        "https://app.local/callback",
        expires,
    )
    .unwrap();

    assert!(tx.is_valid_at(now));
    assert!(!tx.is_valid_at(expires + Duration::seconds(1)));
}
