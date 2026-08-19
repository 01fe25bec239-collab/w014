//! Integration tests for CSRF Exact Origin validation and defense behavior.

use http::header::{ORIGIN, REFERER};
use http::{HeaderMap, HeaderValue, Method};
use w014_authn::csrf::{CsrfConfig, CsrfProtector};
use w014_authn::error::AuthnError;

#[test]
fn test_csrf_safe_methods_allowed_without_origin() {
    let config = CsrfConfig::new(vec!["https://platform.w014.internal".to_string()]);
    let protector = CsrfProtector::new(config);

    let headers = HeaderMap::new();

    // GET, HEAD, OPTIONS bypass origin checks
    assert!(
        protector
            .validate_request(&Method::GET, &headers, true)
            .is_ok()
    );
    assert!(
        protector
            .validate_request(&Method::HEAD, &headers, true)
            .is_ok()
    );
    assert!(
        protector
            .validate_request(&Method::OPTIONS, &headers, true)
            .is_ok()
    );
}

#[test]
fn test_csrf_unsafe_methods_require_valid_origin() {
    let config = CsrfConfig::new(vec![
        "https://platform.w014.internal".to_string(),
        "http://localhost:8080".to_string(),
    ]);
    let protector = CsrfProtector::new(config);

    let unsafe_methods = [Method::POST, Method::PUT, Method::DELETE, Method::PATCH];

    for method in &unsafe_methods {
        // 1. Valid Origin succeeds
        let mut valid_headers = HeaderMap::new();
        valid_headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://platform.w014.internal"),
        );
        assert!(
            protector
                .validate_request(method, &valid_headers, true)
                .is_ok()
        );

        // 2. Mismatched Origin fails
        let mut attacker_headers = HeaderMap::new();
        attacker_headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://evil-cross-site.com"),
        );
        assert!(matches!(
            protector.validate_request(method, &attacker_headers, true),
            Err(AuthnError::CsrfOriginMismatch(_))
        ));

        // 3. Missing both Origin and Referer fails closed
        let empty_headers = HeaderMap::new();
        assert!(matches!(
            protector.validate_request(method, &empty_headers, true),
            Err(AuthnError::CsrfMissingOrigin)
        ));

        // 4. Valid Referer fallback succeeds
        let mut referer_headers = HeaderMap::new();
        referer_headers.insert(
            REFERER,
            HeaderValue::from_static("http://localhost:8080/app/dashboard"),
        );
        assert!(
            protector
                .validate_request(method, &referer_headers, true)
                .is_ok()
        );

        // 5. Invalid Referer fails
        let mut bad_referer = HeaderMap::new();
        bad_referer.insert(
            REFERER,
            HeaderValue::from_static("http://attacker.com/localhost:8080"),
        );
        assert!(matches!(
            protector.validate_request(method, &bad_referer, true),
            Err(AuthnError::CsrfOriginMismatch(_))
        ));
    }
}
