//! Integration tests for server-side opaque session lifecycle, keyed HMAC hashing, rotation, and cookies.

use chrono::{Duration, Utc};
use http::HeaderMap;
use http::header::COOKIE;
use w014_authn::error::AuthnError;
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{
    Session, SessionConfig, SessionCookieBuilder, SessionEvaluator, SessionId, SessionStatus,
    generate_session_token, hash_session_token,
};
use w014_domain::ids::PrincipalId;

#[test]
fn test_keyed_hmac_sha256_session_token_hashing_and_uniqueness() {
    let key1 = b"w014-session-key-primary-1234567";
    let key2 = b"w014-session-key-secondary-98765";

    let raw1 = generate_session_token();
    let raw2 = generate_session_token();
    assert_ne!(raw1, raw2);

    let hash1_k1 = hash_session_token(&raw1, key1);
    let hash2_k1 = hash_session_token(&raw2, key1);
    assert_ne!(hash1_k1, hash2_k1);
    assert_eq!(hash1_k1.len(), 64);

    let bin_hash1_k1 = w014_authn::session::hash_session_handle(&raw1, key1);
    let bin_hash2_k1 = w014_authn::session::hash_session_handle(&raw2, key1);
    assert_ne!(bin_hash1_k1, bin_hash2_k1);
    assert_eq!(bin_hash1_k1.len(), 32);

    // 1. Same token under different HMAC keys produces DIFFERENT hashes (keyed HMAC property)
    let hash1_k2 = hash_session_token(&raw1, key2);
    assert_ne!(
        hash1_k1, hash1_k2,
        "Same token under different keys must produce distinct HMAC digests"
    );

    // 2. Hash is deterministic under the same key
    assert_eq!(hash_session_token(&raw1, key1), hash1_k1);

    // 3. Raw token is never equal to the hash
    assert_ne!(raw1, hash1_k1);
}

#[test]
fn test_session_config_redacts_hmac_secret_in_debug() {
    let config = SessionConfig::default()
        .with_previous_hmac_secret(b"previous-secret-retained-8d!".to_vec());
    let debug_repr = format!("{:?}", config);
    assert!(debug_repr.contains("[REDACTED_SESSION_HMAC_SECRET]"));
    assert!(!debug_repr.contains("w014-default-dev-session-secret"));
    assert!(!debug_repr.contains("previous-secret-retained"));
}

#[test]
fn test_session_lifecycle_expiry_and_idle_policies() {
    let p_id = PrincipalId::new();
    let now = Utc::now();
    let idle_ttl = Duration::hours(12); // 12 hours idle
    let idle_expires = now + idle_ttl;
    let abs_expires = now + Duration::days(7); // 7 days absolute

    let mut session = Session::new(
        p_id,
        b"session_hash_1_abcdef0123456789".to_vec(),
        b"csrf_secret_hash_abcdef01234567".to_vec(),
        idle_expires,
        abs_expires,
    )
    .unwrap();

    assert_eq!(session.status_at(now), SessionStatus::Active);

    // 1. Valid session within idle and absolute windows
    assert!(
        SessionEvaluator::evaluate_active(&session, idle_ttl, now + Duration::hours(4)).is_ok()
    );

    // 2. Touch session advances last_seen_at and idle_expires_at
    let touch_time = now + Duration::hours(6);
    session.touch(touch_time, idle_ttl).unwrap();
    assert_eq!(session.last_seen_at, touch_time);
    assert_eq!(session.idle_expires_at, touch_time + idle_ttl);

    // 3. Idle timeout (12h) exceeded past last touch
    let past_idle = touch_time + Duration::hours(13);
    assert!(SessionEvaluator::evaluate_active(&session, idle_ttl, past_idle).is_err());

    // 4. Absolute expiration exceeded (7d)
    let past_abs = abs_expires + Duration::minutes(1);
    assert!(SessionEvaluator::evaluate_active(&session, idle_ttl, past_abs).is_err());

    // 5. Explicit revocation
    session.revoke(touch_time);
    assert_eq!(session.status_at(touch_time), SessionStatus::Revoked);
    assert!(SessionEvaluator::evaluate_active(&session, idle_ttl, touch_time).is_err());
    assert!(
        session
            .touch(touch_time + Duration::minutes(5), idle_ttl)
            .is_err()
    );
}

#[test]
fn test_session_rotation_semantics() {
    let s_id = SessionId::new();
    let key = b"w014-rotation-key-12345678901234";

    let old_raw = generate_session_token();
    let old_hash = w014_authn::session::hash_session_handle(&old_raw, key);

    let new_raw = generate_session_token();
    let new_hash = w014_authn::session::hash_session_handle(&new_raw, key);

    // 1. Distinct rotation succeeds
    let rotation =
        SessionRotation::new(s_id, old_hash.to_vec(), new_hash.to_vec(), Some("10.0.0.1")).unwrap();
    assert_eq!(rotation.session_id, s_id);
    assert_eq!(rotation.old_handle_hash, old_hash.to_vec());
    assert_eq!(rotation.new_handle_hash, new_hash.to_vec());

    // 2. Identical rotation hash is rejected
    let same_err =
        SessionRotation::new(s_id, old_hash.to_vec(), old_hash.to_vec(), None::<&str>).unwrap_err();
    assert_eq!(same_err, AuthnError::IdenticalRotationHashes);
}

#[test]
fn test_session_cookie_attributes_and_extraction() {
    let config = SessionConfig {
        absolute_ttl_secs: 7 * 24 * 3600,
        idle_ttl_secs: 12 * 3600,
        cookie_name: "__Host-w014_session".to_string(),
        cookie_secure: true,
        cookie_path: "/".to_string(),
        active_hmac_secret: b"secret-for-cookie-test-key-32b!".to_vec(),
        previous_hmac_secret: None,
        periodic_rotation_interval_secs: 4 * 3600,
        activity_touch_interval_secs: 300,
        max_concurrent_sessions: 5,
    };

    let raw_token = generate_session_token();

    // 1. Set-Cookie format
    let set_cookie = SessionCookieBuilder::build_set_cookie(&config, &raw_token);
    assert!(set_cookie.starts_with("__Host-w014_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Path=/"));
    assert!(set_cookie.contains("Secure"));
    assert!(!set_cookie.contains("Domain="));

    // 2. Extraction from HeaderMap
    let mut headers = HeaderMap::new();
    let cookie_val = format!("other_cookie=123; __Host-w014_session={raw_token}; tracking=abc");
    headers.insert(COOKIE, cookie_val.parse().unwrap());

    let extracted = SessionCookieBuilder::extract_token(&headers, "__Host-w014_session").unwrap();
    assert_eq!(extracted, raw_token);

    // 3. Clear cookie format
    let clear_cookie = SessionCookieBuilder::build_clear_cookie(&config);
    assert!(clear_cookie.contains("__Host-w014_session="));
    assert!(clear_cookie.contains("Max-Age=0"));
    assert!(clear_cookie.contains("Path=/"));
    assert!(clear_cookie.contains("HttpOnly"));
}
