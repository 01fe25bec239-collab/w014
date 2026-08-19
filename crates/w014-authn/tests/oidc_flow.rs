//! Integration tests for OIDC Authorization Code Flow, PKCE, JWKS, and ID token validation.

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use w014_authn::error::AuthnError;
use w014_authn::oidc::jwks::validate_algorithm;
use w014_authn::oidc::pkce::{PkceCodeVerifier, PkceMethod};
use w014_authn::oidc::token::{AudienceClaim, IdTokenValidator, RawIdTokenClaims};
use w014_authn::oidc::{OidcClient, OidcConfig};

const TEST_RSA_PRIVATE_KEY_PEM: &[u8] = include_bytes!("test_keys/rsa_private.pem");
const TEST_RSA_PUBLIC_KEY_PEM: &[u8] = include_bytes!("test_keys/rsa_public.pem");

#[test]
fn test_pkce_s256_strict_enforcement() {
    let verifier = PkceCodeVerifier::generate();
    assert!(verifier.secret().len() >= 43);
    assert!(verifier.secret().len() <= 128);

    let challenge = verifier.challenge();
    assert_eq!(challenge.method, PkceMethod::S256);

    // Correct verifier matches
    assert!(challenge.verify(&verifier));

    // Tampered verifier fails
    let bad_verifier = PkceCodeVerifier::generate();
    assert!(!challenge.verify(&bad_verifier));
}

#[test]
fn test_algorithm_allowlist_and_rejection_of_none_and_symmetric() {
    // Approved asymmetric algorithms
    assert!(validate_algorithm(Algorithm::RS256).is_ok());
    assert!(validate_algorithm(Algorithm::RS384).is_ok());
    assert!(validate_algorithm(Algorithm::RS512).is_ok());
    assert!(validate_algorithm(Algorithm::ES256).is_ok());
    assert!(validate_algorithm(Algorithm::ES384).is_ok());
    assert!(validate_algorithm(Algorithm::EdDSA).is_ok());

    // Symmetric algorithms prohibited
    assert_eq!(
        validate_algorithm(Algorithm::HS256),
        Err(AuthnError::SymmetricAlgorithmRejected("HS256".to_string()))
    );
    assert_eq!(
        validate_algorithm(Algorithm::HS384),
        Err(AuthnError::SymmetricAlgorithmRejected("HS384".to_string()))
    );
    assert_eq!(
        validate_algorithm(Algorithm::HS512),
        Err(AuthnError::SymmetricAlgorithmRejected("HS512".to_string()))
    );
}

#[test]
fn test_oidc_authorization_request_url_construction() {
    let config = OidcConfig {
        issuer: "https://auth.example.com".to_string(),
        issuer_allowlist: vec!["https://auth.example.com".to_string()],
        authorization_endpoint: "https://auth.example.com/oauth2/v1/authorize".to_string(),
        token_endpoint: "https://auth.example.com/oauth2/v1/token".to_string(),
        jwks_uri: "https://auth.example.com/oauth2/v1/keys".to_string(),
        client_id: "client-w014".to_string(),
        client_secret: None,
        redirect_uri: "https://app.example.com/api/v1/auth/callback".to_string(),
        scopes: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        state_ttl_secs: 600,
    };

    let client = OidcClient::new(config);
    let params = client.create_authorization_request().unwrap();

    let url = params.authorization_url;
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("auth.example.com"));
    assert_eq!(url.path(), "/oauth2/v1/authorize");

    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query.get("response_type"), Some(&"code".to_string()));
    assert_eq!(query.get("client_id"), Some(&"client-w014".to_string()));
    assert_eq!(
        query.get("redirect_uri"),
        Some(&"https://app.example.com/api/v1/auth/callback".to_string())
    );
    assert_eq!(
        query.get("scope"),
        Some(&"openid email profile".to_string())
    );
    assert_eq!(query.get("state"), Some(&params.state_token));
    assert_eq!(query.get("nonce"), Some(&params.nonce));
    assert_eq!(
        query.get("code_challenge_method"),
        Some(&"S256".to_string())
    );
    assert_eq!(
        query.get("code_challenge"),
        Some(&params.pkce_verifier.challenge().challenge)
    );
}

#[test]
fn test_id_token_validation_with_rsa_signatures() {
    let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM).unwrap();
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM).unwrap();

    let validator = IdTokenValidator::new(
        "https://auth.example.com",
        vec!["https://auth.example.com".to_string()],
        "client-w014",
    );

    let now = Utc::now();
    let nonce = "test_nonce_98765";

    // 1. Valid token
    let claims = RawIdTokenClaims {
        iss: "https://auth.example.com".to_string(),
        sub: "user_sub_12345".to_string(),
        aud: AudienceClaim::Single("client-w014".to_string()),
        exp: (now + Duration::minutes(15)).timestamp(),
        iat: now.timestamp(),
        nbf: Some(now.timestamp()),
        nonce: Some(nonce.to_string()),
        azp: None,
        email: Some("alice@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Alice Smith".to_string()),
        extra: serde_json::json!({"org": "w014"}),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("key-rsa-1".to_string());

    let token_str = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    let verified = validator
        .validate_with_key(&token_str, nonce, &decoding_key, Algorithm::RS256)
        .expect("token should be valid");

    assert_eq!(verified.issuer, "https://auth.example.com");
    assert_eq!(verified.subject, "user_sub_12345");
    assert_eq!(verified.email.as_deref(), Some("alice@example.com"));
    assert_eq!(
        verified.identity_key(),
        ("https://auth.example.com", "user_sub_12345")
    );

    // 2. Nonce mismatch fails
    let err = validator
        .validate_with_key(&token_str, "wrong_nonce", &decoding_key, Algorithm::RS256)
        .unwrap_err();
    assert_eq!(err, AuthnError::NonceMismatch);

    // 3. Issuer mismatch fails
    let bad_iss_claims = RawIdTokenClaims {
        iss: "https://untrusted-idp.com".to_string(),
        ..claims.clone()
    };
    let bad_iss_token = jsonwebtoken::encode(&header, &bad_iss_claims, &encoding_key).unwrap();
    assert!(matches!(
        validator.validate_with_key(&bad_iss_token, nonce, &decoding_key, Algorithm::RS256),
        Err(AuthnError::InvalidIssuer(_))
    ));

    // 4. Audience mismatch fails
    let bad_aud_claims = RawIdTokenClaims {
        aud: AudienceClaim::Single("other-client-id".to_string()),
        ..claims.clone()
    };
    let bad_aud_token = jsonwebtoken::encode(&header, &bad_aud_claims, &encoding_key).unwrap();
    assert!(matches!(
        validator.validate_with_key(&bad_aud_token, nonce, &decoding_key, Algorithm::RS256),
        Err(AuthnError::InvalidAudience { .. })
    ));

    // 5. Multiple aud without matching azp fails
    let multi_aud_claims = RawIdTokenClaims {
        aud: AudienceClaim::Multiple(vec![
            "client-w014".to_string(),
            "other-audience".to_string(),
        ]),
        azp: None,
        ..claims.clone()
    };
    let multi_aud_token = jsonwebtoken::encode(&header, &multi_aud_claims, &encoding_key).unwrap();
    assert!(matches!(
        validator.validate_with_key(&multi_aud_token, nonce, &decoding_key, Algorithm::RS256),
        Err(AuthnError::InvalidAzp { .. })
    ));

    // 6. Multiple aud WITH matching azp succeeds
    let multi_aud_valid_azp_claims = RawIdTokenClaims {
        aud: AudienceClaim::Multiple(vec![
            "client-w014".to_string(),
            "other-audience".to_string(),
        ]),
        azp: Some("client-w014".to_string()),
        ..claims.clone()
    };
    let multi_aud_valid_token =
        jsonwebtoken::encode(&header, &multi_aud_valid_azp_claims, &encoding_key).unwrap();
    assert!(
        validator
            .validate_with_key(
                &multi_aud_valid_token,
                nonce,
                &decoding_key,
                Algorithm::RS256
            )
            .is_ok()
    );

    // 7. Expired token past clock skew fails
    let expired_claims = RawIdTokenClaims {
        exp: (now - Duration::minutes(5)).timestamp(),
        ..claims.clone()
    };
    let expired_token = jsonwebtoken::encode(&header, &expired_claims, &encoding_key).unwrap();
    assert!(matches!(
        validator.validate_with_key(&expired_token, nonce, &decoding_key, Algorithm::RS256),
        Err(AuthnError::TokenExpired { .. })
    ));

    // 8. Expired token WITHIN 60s clock skew succeeds
    let near_expired_claims = RawIdTokenClaims {
        exp: (now - Duration::seconds(30)).timestamp(),
        ..claims.clone()
    };
    let near_expired_token =
        jsonwebtoken::encode(&header, &near_expired_claims, &encoding_key).unwrap();
    assert!(
        validator
            .validate_with_key(&near_expired_token, nonce, &decoding_key, Algorithm::RS256)
            .is_ok()
    );

    // 9. Rejection of symmetric token with same claims
    let symmetric_key = EncodingKey::from_secret(b"secret_key_1234567890123456789012345");
    let sym_header = Header::new(Algorithm::HS256);
    let sym_token = jsonwebtoken::encode(&sym_header, &claims, &symmetric_key).unwrap();
    assert!(matches!(
        validator.validate_with_key(
            &sym_token,
            nonce,
            &jsonwebtoken::DecodingKey::from_secret(b"secret_key_1234567890123456789012345"),
            Algorithm::HS256
        ),
        Err(AuthnError::SymmetricAlgorithmRejected(_))
    ));
}
