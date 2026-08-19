//! Integration tests for CSRF Exact Origin validation, 3-way binding, and X-W014-CSRF token defense.
//!
//! Frozen Verification Requirements (Matrix):
//! 1. CSRF_MISSING_ORIGIN: 403 CSRF_FAILED
//! 2. CSRF_OPAQUE_ORIGIN: 403 CSRF_FAILED
//! 3. CSRF_MALFORMED_ORIGIN: 403 CSRF_FAILED
//! 4. CSRF_WRONG_ORIGIN: 403 CSRF_FAILED
//! 5. CSRF_VALID_REFERER_MISSING_ORIGIN: 403 CSRF_FAILED (No Referer fallback)
//! 6. CSRF_VALID_REFERER_WRONG_ORIGIN: 403 CSRF_FAILED (No Referer fallback)
//! 7. CSRF_MISSING_HEADER: 403 CSRF_FAILED
//! 8. CSRF_WRONG_TOKEN: 403 CSRF_FAILED
//! 9. CSRF_TOKEN_FROM_OTHER_ORIGIN: 403 CSRF_FAILED (Origin bound)
//! 10. CSRF_TOKEN_FROM_PREVIOUS_SESSION_ROTATION: 403 CSRF_FAILED (Rotation identity bound)
//! 11. CSRF_VALID_CURRENT_ROTATION_AND_ORIGIN: PASS (200 OK)
//! 12. SAFE_GET_HEAD_OPTIONS: side-effect free; application CSRF header not required

use http::header::{ORIGIN, REFERER};
use http::{HeaderMap, HeaderValue, Method};
use w014_authn::csrf::{CSRF_HEADER_NAME, CsrfConfig, CsrfProtector};
use w014_authn::error::AuthnError;

#[test]
fn test_csrf_safe_methods_bypass_all_csrf_checks() {
    let config = CsrfConfig::new(vec!["https://platform.w014.internal".to_string()]);
    let protector = CsrfProtector::new(config);

    let empty_headers = HeaderMap::new();

    // Safe methods (GET, HEAD, OPTIONS) do not require Origin or X-W014-CSRF
    for method in &[Method::GET, Method::HEAD, Method::OPTIONS] {
        assert!(
            protector
                .validate_request(method, &empty_headers, true, None)
                .is_ok(),
            "Safe method {method} must bypass CSRF check"
        );
    }
}

#[test]
fn test_csrf_non_cookie_authenticated_bypasses() {
    let config = CsrfConfig::new(vec!["https://platform.w014.internal".to_string()]);
    let protector = CsrfProtector::new(config);

    let empty_headers = HeaderMap::new();

    // Non-cookie-authenticated requests (is_cookie_authenticated = false) bypass
    for method in &[Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        assert!(
            protector
                .validate_request(method, &empty_headers, false, None)
                .is_ok(),
            "Non-cookie authenticated request for {method} must bypass CSRF check"
        );
    }
}

#[test]
fn test_csrf_negative_and_positive_matrix() {
    let allowed_origin = "https://platform.w014.internal";
    let other_allowed_origin = "http://localhost:8080";
    let config = CsrfConfig::new(vec![
        allowed_origin.to_string(),
        other_allowed_origin.to_string(),
    ]);
    let protector = CsrfProtector::new(config);

    let current_rotation = "rotation_token_hash_current_v2_12345";
    let previous_rotation = "rotation_token_hash_previous_v1_98765";

    let valid_csrf_token = protector.derive_token(current_rotation, allowed_origin);
    let previous_rotation_csrf_token = protector.derive_token(previous_rotation, allowed_origin);
    let other_origin_csrf_token = protector.derive_token(current_rotation, other_allowed_origin);

    let unsafe_methods = [Method::POST, Method::PUT, Method::DELETE, Method::PATCH];

    for method in &unsafe_methods {
        // 1. CSRF_MISSING_ORIGIN
        let mut missing_origin_req = HeaderMap::new();
        missing_origin_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res =
            protector.validate_request(method, &missing_origin_req, true, Some(current_rotation));
        assert_eq!(
            res,
            Err(AuthnError::CsrfMissingOrigin),
            "CSRF_MISSING_ORIGIN must fail with 403 on {method}"
        );

        // 2. CSRF_OPAQUE_ORIGIN ("null")
        let mut opaque_origin_req = HeaderMap::new();
        opaque_origin_req.insert(ORIGIN, HeaderValue::from_static("null"));
        opaque_origin_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res =
            protector.validate_request(method, &opaque_origin_req, true, Some(current_rotation));
        assert!(
            matches!(res, Err(AuthnError::CsrfOriginMismatch(_))),
            "CSRF_OPAQUE_ORIGIN must fail with 403 on {method}"
        );

        // 3. CSRF_MALFORMED_ORIGIN
        let mut malformed_origin_req = HeaderMap::new();
        malformed_origin_req.insert(ORIGIN, HeaderValue::from_static("not-a-valid-origin-uri"));
        malformed_origin_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res =
            protector.validate_request(method, &malformed_origin_req, true, Some(current_rotation));
        assert!(
            matches!(res, Err(AuthnError::CsrfOriginMismatch(_))),
            "CSRF_MALFORMED_ORIGIN must fail with 403 on {method}"
        );

        // 4. CSRF_WRONG_ORIGIN
        let mut wrong_origin_req = HeaderMap::new();
        wrong_origin_req.insert(
            ORIGIN,
            HeaderValue::from_static("https://evil-attacker.com"),
        );
        wrong_origin_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res =
            protector.validate_request(method, &wrong_origin_req, true, Some(current_rotation));
        assert!(
            matches!(res, Err(AuthnError::CsrfOriginMismatch(_))),
            "CSRF_WRONG_ORIGIN must fail with 403 on {method}"
        );

        // 5. CSRF_VALID_REFERER_MISSING_ORIGIN (No Referer Fallback)
        let mut referer_no_origin_req = HeaderMap::new();
        referer_no_origin_req.insert(
            REFERER,
            HeaderValue::from_static("https://platform.w014.internal/app/dashboard"),
        );
        referer_no_origin_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res = protector.validate_request(
            method,
            &referer_no_origin_req,
            true,
            Some(current_rotation),
        );
        assert_eq!(
            res,
            Err(AuthnError::CsrfMissingOrigin),
            "CSRF_VALID_REFERER_MISSING_ORIGIN must fail with 403 on {method}"
        );

        // 6. CSRF_VALID_REFERER_WRONG_ORIGIN (No Referer Fallback)
        let mut referer_wrong_origin_req = HeaderMap::new();
        referer_wrong_origin_req.insert(
            ORIGIN,
            HeaderValue::from_static("https://evil-attacker.com"),
        );
        referer_wrong_origin_req.insert(
            REFERER,
            HeaderValue::from_static("https://platform.w014.internal/app/dashboard"),
        );
        referer_wrong_origin_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res = protector.validate_request(
            method,
            &referer_wrong_origin_req,
            true,
            Some(current_rotation),
        );
        assert!(
            matches!(res, Err(AuthnError::CsrfOriginMismatch(_))),
            "CSRF_VALID_REFERER_WRONG_ORIGIN must fail with 403 on {method}"
        );

        // 7. CSRF_MISSING_HEADER
        let mut missing_header_req = HeaderMap::new();
        missing_header_req.insert(ORIGIN, HeaderValue::from_static(allowed_origin));
        let res =
            protector.validate_request(method, &missing_header_req, true, Some(current_rotation));
        assert_eq!(
            res,
            Err(AuthnError::CsrfMissingHeader),
            "CSRF_MISSING_HEADER must fail with 403 on {method}"
        );

        // 8. CSRF_WRONG_TOKEN
        let mut wrong_token_req = HeaderMap::new();
        wrong_token_req.insert(ORIGIN, HeaderValue::from_static(allowed_origin));
        wrong_token_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_static("invalid_tampered_token_string"),
        );
        let res =
            protector.validate_request(method, &wrong_token_req, true, Some(current_rotation));
        assert_eq!(
            res,
            Err(AuthnError::CsrfTokenMismatch),
            "CSRF_WRONG_TOKEN must fail with 403 on {method}"
        );

        // 9. CSRF_TOKEN_FROM_OTHER_ORIGIN (Token derived for Origin A used on Origin B)
        let mut cross_origin_token_req = HeaderMap::new();
        cross_origin_token_req.insert(ORIGIN, HeaderValue::from_static(allowed_origin));
        cross_origin_token_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&other_origin_csrf_token).unwrap(),
        );
        let res = protector.validate_request(
            method,
            &cross_origin_token_req,
            true,
            Some(current_rotation),
        );
        assert_eq!(
            res,
            Err(AuthnError::CsrfTokenMismatch),
            "CSRF_TOKEN_FROM_OTHER_ORIGIN must fail with 403 on {method}"
        );

        // 10. CSRF_TOKEN_FROM_PREVIOUS_SESSION_ROTATION
        let mut old_rotation_req = HeaderMap::new();
        old_rotation_req.insert(ORIGIN, HeaderValue::from_static(allowed_origin));
        old_rotation_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&previous_rotation_csrf_token).unwrap(),
        );
        let res =
            protector.validate_request(method, &old_rotation_req, true, Some(current_rotation));
        assert_eq!(
            res,
            Err(AuthnError::CsrfTokenMismatch),
            "CSRF_TOKEN_FROM_PREVIOUS_SESSION_ROTATION must fail with 403 on {method}"
        );

        // 11. CSRF_VALID_CURRENT_ROTATION_AND_ORIGIN (Positive Case)
        let mut valid_req = HeaderMap::new();
        valid_req.insert(ORIGIN, HeaderValue::from_static(allowed_origin));
        valid_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        let res = protector.validate_request(method, &valid_req, true, Some(current_rotation));
        assert!(
            res.is_ok(),
            "CSRF_VALID_CURRENT_ROTATION_AND_ORIGIN must PASS on {method}"
        );
    }
}
