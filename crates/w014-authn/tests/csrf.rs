//! Integration tests for CSRF Exact Origin validation and X-W014-CSRF token defense behavior.
//!
//! Frozen Verification Requirements:
//! 1. Unsafe request + Origin missing + Referer valid/same-origin => 403 CSRF_FAILED (No Referer fallback)
//! 2. Unsafe request + Origin malformed + Referer valid => 403 CSRF_FAILED
//! 3. Unsafe request + Origin wrong/non-allowlisted + Referer valid => 403 CSRF_FAILED
//! 4. Unsafe request + Origin exact allowed + valid X-W014-CSRF => allowed subject to normal route authorization
//! 5. Missing X-W014-CSRF => 403 CSRF_FAILED
//! 6. Wrong X-W014-CSRF => 403 CSRF_FAILED
//! 7. Safe GET/HEAD/OPTIONS remain side-effect-free and do not require application CSRF header.

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
fn test_csrf_unsafe_methods_strict_origin_and_no_referer_fallback() {
    let config = CsrfConfig::new(vec![
        "https://platform.w014.internal".to_string(),
        "http://localhost:8080".to_string(),
    ]);
    let protector = CsrfProtector::new(config);
    let raw_session = "sample_session_raw_handle_12345678901234567890";
    let valid_csrf_token = protector.derive_token(raw_session);

    let unsafe_methods = [Method::POST, Method::PUT, Method::DELETE, Method::PATCH];

    for method in &unsafe_methods {
        // 1. Requirement 1: Origin missing, but valid same-origin Referer present => MUST FAIL CLOSED (No Referer Fallback)
        let mut missing_origin_valid_referer = HeaderMap::new();
        missing_origin_valid_referer.insert(
            REFERER,
            HeaderValue::from_static("https://platform.w014.internal/app/dashboard"),
        );
        missing_origin_valid_referer.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );

        let res1 = protector.validate_request(
            method,
            &missing_origin_valid_referer,
            true,
            Some(&valid_csrf_token),
        );
        assert_eq!(
            res1,
            Err(AuthnError::CsrfMissingOrigin),
            "Referer must NOT rescue missing Origin on {method}"
        );

        // 2. Requirement 2: Origin malformed, valid Referer present => MUST FAIL CLOSED
        let mut malformed_origin_valid_referer = HeaderMap::new();
        malformed_origin_valid_referer
            .insert(ORIGIN, HeaderValue::from_static("not-a-valid-url-origin"));
        malformed_origin_valid_referer.insert(
            REFERER,
            HeaderValue::from_static("https://platform.w014.internal/app/dashboard"),
        );
        malformed_origin_valid_referer.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );

        let res2 = protector.validate_request(
            method,
            &malformed_origin_valid_referer,
            true,
            Some(&valid_csrf_token),
        );
        assert!(
            matches!(res2, Err(AuthnError::CsrfOriginMismatch(_))),
            "Malformed Origin must fail closed on {method}"
        );

        // Opaque Origin ("null") => MUST FAIL CLOSED
        let mut opaque_origin = HeaderMap::new();
        opaque_origin.insert(ORIGIN, HeaderValue::from_static("null"));
        opaque_origin.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );
        assert!(matches!(
            protector.validate_request(method, &opaque_origin, true, Some(&valid_csrf_token)),
            Err(AuthnError::CsrfOriginMismatch(_))
        ));

        // 3. Requirement 3: Origin wrong/non-allowlisted, valid Referer present => MUST FAIL CLOSED
        let mut wrong_origin_valid_referer = HeaderMap::new();
        wrong_origin_valid_referer.insert(
            ORIGIN,
            HeaderValue::from_static("https://evil-attacker.com"),
        );
        wrong_origin_valid_referer.insert(
            REFERER,
            HeaderValue::from_static("https://platform.w014.internal/app/dashboard"),
        );
        wrong_origin_valid_referer.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );

        let res3 = protector.validate_request(
            method,
            &wrong_origin_valid_referer,
            true,
            Some(&valid_csrf_token),
        );
        assert!(
            matches!(res3, Err(AuthnError::CsrfOriginMismatch(_))),
            "Wrong Origin must fail closed even with valid Referer on {method}"
        );

        // 4. Requirement 4: Origin exact allowed + valid X-W014-CSRF => MUST SUCCEED
        let mut valid_req = HeaderMap::new();
        valid_req.insert(
            ORIGIN,
            HeaderValue::from_static("https://platform.w014.internal"),
        );
        valid_req.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_str(&valid_csrf_token).unwrap(),
        );

        let res4 = protector.validate_request(method, &valid_req, true, Some(&valid_csrf_token));
        assert!(
            res4.is_ok(),
            "Exact allowed Origin + valid X-W014-CSRF must succeed on {method}"
        );

        // 5. Requirement 5: Missing X-W014-CSRF => MUST FAIL CLOSED
        let mut missing_csrf_header = HeaderMap::new();
        missing_csrf_header.insert(
            ORIGIN,
            HeaderValue::from_static("https://platform.w014.internal"),
        );

        let res5 =
            protector.validate_request(method, &missing_csrf_header, true, Some(&valid_csrf_token));
        assert_eq!(
            res5,
            Err(AuthnError::CsrfMissingHeader),
            "Missing X-W014-CSRF must fail closed on {method}"
        );

        // 6. Requirement 6: Wrong X-W014-CSRF => MUST FAIL CLOSED
        let mut wrong_csrf_header = HeaderMap::new();
        wrong_csrf_header.insert(
            ORIGIN,
            HeaderValue::from_static("https://platform.w014.internal"),
        );
        wrong_csrf_header.insert(
            CSRF_HEADER_NAME,
            HeaderValue::from_static("tampered-or-wrong-csrf-token"),
        );

        let res6 =
            protector.validate_request(method, &wrong_csrf_header, true, Some(&valid_csrf_token));
        assert_eq!(
            res6,
            Err(AuthnError::CsrfTokenMismatch),
            "Wrong X-W014-CSRF must fail closed on {method}"
        );
    }
}
