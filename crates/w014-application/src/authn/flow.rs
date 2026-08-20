//! OIDC authentication and server-side session orchestration services.

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use w014_authn::error::AuthnError;
use w014_authn::oidc::{AuthorizationParameters, IdTokenClaims, OidcClient};
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{
    AuthenticationResult, Session, SessionConfig, SessionEvaluator, SessionId,
    generate_session_token,
};
use w014_domain::ids::{OrganizationId, PrincipalId};
use w014_domain::principal::Principal;

use crate::error::ApplicationError;
use crate::persistence::{OidcIdentityRepository, PrincipalRepository, SessionRepository};
use crate::services::{OidcPersistenceService, SessionService};

/// Service orchestrating OIDC login flows and callback resolution.
pub struct OidcFlowService;

impl OidcFlowService {
    /// Initiates an OIDC login flow, persisting the transient transaction parameters.
    pub async fn initiate_login(
        tx: &mut PgConnection,
        oidc_client: &OidcClient,
    ) -> Result<AuthorizationParameters, ApplicationError> {
        let auth_params = oidc_client.create_authorization_request()?;

        let state_hash = Sha256::digest(auth_params.state_token.as_bytes()).to_vec();
        let nonce_hash = Sha256::digest(auth_params.nonce.as_bytes()).to_vec();
        let pkce_ciphertext = auth_params.pkce_verifier.secret().as_bytes().to_vec();

        OidcPersistenceService::store_transaction(
            tx,
            state_hash,
            nonce_hash,
            Some(pkce_ciphertext),
            "/",
            auth_params.expires_at,
        )
        .await?;

        Ok(auth_params)
    }

    /// Handles OIDC authorization callback, validating state single-use, exchanging tokens,
    /// resolving principal identity, and establishing a server-side session with concurrent bounding.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_callback(
        tx: &mut PgConnection,
        oidc_client: &OidcClient,
        code: &str,
        state: &str,
        session_config: &SessionConfig,
        default_org_id: Option<OrganizationId>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<(Session, String, PrincipalId), ApplicationError> {
        // 1. Consume transient transaction by state token (single-use semantics)
        let state_hash = Sha256::digest(state.as_bytes()).to_vec();
        let transaction = OidcPersistenceService::consume_transaction(tx, &state_hash)
            .await?
            .ok_or(AuthnError::StateMismatch)?;

        let now = Utc::now();
        if !transaction.is_valid_at(now) {
            return Err(ApplicationError::Authn(AuthnError::TransactionExpired));
        }

        // 2. PKCE code verifier is required
        let pkce_bytes = transaction
            .pkce_verifier_ciphertext
            .as_ref()
            .ok_or_else(|| {
                AuthnError::InvalidPkce("Missing PKCE verifier in transaction".into())
            })?;
        let pkce_verifier = std::str::from_utf8(pkce_bytes)
            .map_err(|_| AuthnError::InvalidPkce("Malformed PKCE verifier".into()))?;

        // 3. Exchange authorization code at IdP token endpoint
        let token_resp = oidc_client
            .exchange_code(code, pkce_verifier, &oidc_client.config().redirect_uri)
            .await?;

        // 4. Extract nonce from token, verify nonce_hash, and cryptographically validate ID token against IdP JWKS
        let parts: Vec<&str> = token_resp.id_token.split('.').collect();
        if parts.len() < 2 {
            return Err(ApplicationError::Authn(AuthnError::InvalidToken(
                "Malformed JWT".into(),
            )));
        }
        use base64::Engine;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[1]))
            .map_err(|e| ApplicationError::Authn(AuthnError::InvalidToken(e.to_string())))?;
        let raw_claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| ApplicationError::Authn(AuthnError::InvalidToken(e.to_string())))?;
        let nonce_str = raw_claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let computed_nonce_hash = Sha256::digest(nonce_str.as_bytes()).to_vec();
        if computed_nonce_hash != transaction.nonce_hash {
            return Err(ApplicationError::Authn(AuthnError::NonceMismatch));
        }

        let claims = oidc_client
            .validate_id_token(&token_resp.id_token, nonce_str)
            .await?;

        // 5. Authoritatively resolve identity by composite (issuer, subject)
        let principal_id = Self::resolve_or_create_principal(tx, &claims, default_org_id).await?;

        // 6. Create authoritative server-side session with fresh opaque handle (bounded to max 5 active)
        let raw_token = generate_session_token();
        let handle_hash = session_config.hash_handle(&raw_token);
        let csrf_secret_material = generate_session_token();
        let csrf_secret_hash = session_config.hash_handle(&csrf_secret_material);
        let idle_expires_at = now + Duration::seconds(session_config.idle_ttl_secs);
        let absolute_expires_at = now + Duration::seconds(session_config.absolute_ttl_secs);

        let session = SessionService::create_session(
            tx,
            principal_id,
            handle_hash.to_vec(),
            csrf_secret_hash.to_vec(),
            idle_expires_at,
            absolute_expires_at,
        )
        .await?;

        Ok((session, raw_token, principal_id))
    }

    /// Resolves an existing principal by (issuer, subject) or provisions a new one.
    /// Email is NEVER used for automatic account relinking.
    async fn resolve_or_create_principal(
        tx: &mut PgConnection,
        claims: &IdTokenClaims,
        _default_org_id: Option<OrganizationId>,
    ) -> Result<PrincipalId, ApplicationError> {
        // Check for existing identity linkage
        if let Some(identity) =
            OidcIdentityRepository::get_by_issuer_subject(tx, &claims.issuer, &claims.subject)
                .await?
        {
            return Ok(identity.principal_id);
        }

        let display_name = claims
            .name
            .as_deref()
            .unwrap_or_else(|| claims.email.as_deref().unwrap_or("OIDC User"));

        let principal = Principal::new(display_name, claims.email.as_deref())?;

        PrincipalRepository::insert(tx, &principal).await?;

        // Link identity record
        OidcPersistenceService::link_identity(
            tx,
            principal.id,
            &claims.issuer,
            &claims.subject,
            claims.email.as_deref(),
        )
        .await?;

        Ok(principal.id)
    }
}

/// Service managing session authentication, verification, key rollover rotation, and revocation.
pub struct SessionAuthnService;

impl SessionAuthnService {
    /// Authenticates a raw opaque session token against the database.
    pub async fn authenticate(
        tx: &mut PgConnection,
        raw_token: &str,
        session_config: &SessionConfig,
        _ip_address: Option<&str>,
    ) -> Result<AuthenticationResult, ApplicationError> {
        let now = Utc::now();
        let idle_ttl = Duration::seconds(session_config.idle_ttl_secs);

        // 1. Try active HMAC key lookup
        let active_hash = session_config.hash_handle(raw_token);
        let (mut session, is_previous_key) =
            match SessionRepository::get_by_handle_hash(tx, &active_hash).await? {
                Some(sess) => (sess, false),
                None => {
                    let prev_sess = match session_config.hash_handle_previous(raw_token) {
                        Some(prev_hash) => {
                            SessionRepository::get_by_handle_hash(tx, &prev_hash).await?
                        }
                        None => None,
                    };
                    match prev_sess {
                        Some(sess) => (sess, true),
                        None => return Err(ApplicationError::Authn(AuthnError::SessionNotFound)),
                    }
                }
            };

        // 3. Evaluate active status and idle/absolute expiry
        if let Err(err) = SessionEvaluator::evaluate_active(&session, idle_ttl, now) {
            return Err(ApplicationError::Authn(err));
        }

        let mut rotated_token = None;

        // 4. If validated under previous key, rotate immediately to active key
        if is_previous_key {
            let (rotation, new_raw_token) = Self::rotate(
                tx,
                session.session_id,
                session_config,
                Some("manual_refresh"),
            )
            .await?;
            session.handle_hash = rotation.new_handle_hash;
            session.rotation_counter += 1;
            rotated_token = Some(new_raw_token);
        } else {
            // 5. Periodic 4-hour rotation: if active use >= 4 hours since creation
            let periodic_ttl = Duration::seconds(session_config.periodic_rotation_interval_secs);
            if now - session.created_at >= periodic_ttl {
                let (rotation, new_raw_token) =
                    Self::rotate(tx, session.session_id, session_config, Some("periodic")).await?;
                session.handle_hash = rotation.new_handle_hash;
                session.rotation_counter += 1;
                rotated_token = Some(new_raw_token);
            } else {
                // 6. Throttled activity touch (at most once every 5 minutes)
                let touch_threshold =
                    Duration::seconds(session_config.activity_touch_interval_secs);
                if now - session.last_seen_at >= touch_threshold {
                    session.touch(now, idle_ttl)?;
                    SessionRepository::update(tx, &session).await?;
                }
            }
        }

        Ok(AuthenticationResult {
            session,
            rotated_token,
        })
    }

    /// Rotates a session, generating a new raw token and appending an immutable rotation record.
    pub async fn rotate(
        tx: &mut PgConnection,
        session_id: SessionId,
        session_config: &SessionConfig,
        reason: Option<&str>,
    ) -> Result<(SessionRotation, String), ApplicationError> {
        let new_raw_token = generate_session_token();
        let new_handle_hash = session_config.hash_handle(&new_raw_token);
        let now = Utc::now();
        let new_idle_expires_at = now + Duration::seconds(session_config.idle_ttl_secs);
        let new_absolute_expires_at = now + Duration::seconds(session_config.absolute_ttl_secs);

        let rotation = SessionService::rotate_session(
            tx,
            session_id,
            new_handle_hash.to_vec(),
            new_idle_expires_at,
            new_absolute_expires_at,
            reason,
        )
        .await?;

        Ok((rotation, new_raw_token))
    }

    /// Revokes an existing session.
    pub async fn revoke(
        tx: &mut PgConnection,
        session_id: SessionId,
    ) -> Result<(), ApplicationError> {
        SessionService::revoke_session(tx, session_id).await
    }

    /// Revokes all active sessions for a principal (e.g. on privilege, role, or membership change).
    pub async fn revoke_all_for_principal(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
    ) -> Result<u64, ApplicationError> {
        SessionService::revoke_all_for_principal(tx, principal_id).await
    }
}
