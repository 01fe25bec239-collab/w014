//! OIDC authentication and server-side session orchestration services.

use chrono::{Duration, Utc};
use sqlx::PgConnection;
use w014_authn::error::AuthnError;
use w014_authn::oidc::{AuthorizationParameters, IdTokenClaims, OidcClient};
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{
    Session, SessionConfig, SessionEvaluator, SessionId, SessionStatus, generate_session_token,
};
use w014_domain::ids::{OrganizationId, PrincipalId};
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};

use crate::error::ApplicationError;
use crate::persistence::{
    OidcIdentityRepository, OrganizationRepository, PrincipalRepository, SessionRepository,
};
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

        OidcPersistenceService::store_transaction(
            tx,
            &auth_params.state_token,
            &auth_params.nonce,
            Some(auth_params.pkce_verifier.secret()),
            &auth_params.redirect_uri,
            auth_params.expires_at,
        )
        .await?;

        Ok(auth_params)
    }

    /// Handles OIDC authorization callback, validating state single-use, exchanging tokens,
    /// resolving principal identity, and establishing a server-side session.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_callback(
        tx: &mut PgConnection,
        oidc_client: &OidcClient,
        code: &str,
        state: &str,
        session_config: &SessionConfig,
        default_org_id: Option<OrganizationId>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(Session, String, PrincipalId), ApplicationError> {
        // 1. Consume transient transaction by state token (single-use semantics)
        let transaction = OidcPersistenceService::consume_transaction(tx, state)
            .await?
            .ok_or(AuthnError::StateMismatch)?;

        let now = Utc::now();
        if !transaction.is_valid_at(now) {
            return Err(ApplicationError::Authn(AuthnError::TransactionExpired));
        }

        // 2. PKCE code verifier is required
        let pkce_verifier = transaction.pkce_verifier.as_ref().ok_or_else(|| {
            AuthnError::InvalidPkce("Missing PKCE verifier in transaction".into())
        })?;

        // 3. Exchange authorization code at IdP token endpoint
        let token_resp = oidc_client
            .exchange_code(code, pkce_verifier, &transaction.redirect_uri)
            .await?;

        // 4. Cryptographically validate ID token against transaction nonce and IdP JWKS
        let claims = oidc_client
            .validate_id_token(&token_resp.id_token, &transaction.nonce)
            .await?;

        // 5. Authoritatively resolve identity by composite (issuer, subject)
        let principal_id = Self::resolve_or_create_principal(tx, &claims, default_org_id).await?;

        // 6. Create authoritative server-side session with fresh opaque handle
        let raw_token = generate_session_token();
        let token_hash = session_config.hash_token(&raw_token);
        let expires_at = now + Duration::seconds(session_config.absolute_ttl_secs);

        let session = SessionService::create_session(
            tx,
            principal_id,
            None,
            token_hash,
            expires_at,
            ip_address,
            user_agent,
        )
        .await?;

        Ok((session, raw_token, principal_id))
    }

    /// Resolves an existing principal by (issuer, subject) or provisions a new one.
    /// Email is NEVER used for automatic account relinking.
    async fn resolve_or_create_principal(
        tx: &mut PgConnection,
        claims: &IdTokenClaims,
        default_org_id: Option<OrganizationId>,
    ) -> Result<PrincipalId, ApplicationError> {
        // Check for existing identity linkage
        if let Some(identity) =
            OidcIdentityRepository::get_by_issuer_subject(tx, &claims.issuer, &claims.subject)
                .await?
        {
            return Ok(identity.principal_id);
        }

        // No existing identity: Provision new principal
        let org_id = match default_org_id {
            Some(id) => id,
            None => {
                // Ensure default organization exists
                let org = match OrganizationRepository::get_by_slug(tx, "default").await? {
                    Some(existing_org) => existing_org,
                    None => {
                        let new_org = Organization::new("Default Organization", "default")?;
                        OrganizationRepository::insert(tx, &new_org).await?;
                        new_org
                    }
                };
                org.id
            }
        };

        let display_name = claims
            .name
            .as_deref()
            .unwrap_or_else(|| claims.email.as_deref().unwrap_or("OIDC User"));

        let principal = Principal::new(
            org_id,
            PrincipalType::User,
            claims.email.as_deref(),
            display_name,
        )?;

        PrincipalRepository::insert(tx, &principal).await?;

        // Link identity record
        OidcPersistenceService::link_identity(
            tx,
            principal.id,
            &claims.issuer,
            &claims.subject,
            claims.email.as_deref(),
            claims.claims.clone(),
        )
        .await?;

        Ok(principal.id)
    }
}

/// Service managing session authentication, verification, rotation, and revocation.
pub struct SessionAuthnService;

impl SessionAuthnService {
    /// Authenticates a raw opaque session token against the database, validating status and idle/absolute expiry.
    pub async fn authenticate(
        tx: &mut PgConnection,
        raw_token: &str,
        session_config: &SessionConfig,
    ) -> Result<Session, ApplicationError> {
        let token_hash = session_config.hash_token(raw_token);

        let mut session = SessionRepository::get_by_token_hash(tx, &token_hash)
            .await?
            .ok_or(AuthnError::SessionNotFound)?;

        let now = Utc::now();
        let idle_ttl = Duration::seconds(session_config.idle_ttl_secs);

        // Evaluate active status and timeouts
        if let Err(err) = SessionEvaluator::evaluate_active(&session, idle_ttl, now) {
            if session.status == SessionStatus::Active
                && (now >= session.expires_at || now - session.last_seen_at > idle_ttl)
            {
                session.status = SessionStatus::Expired;
                let _ = SessionRepository::update(tx, &session).await;
            }
            return Err(ApplicationError::Authn(err));
        }

        // Touch active session
        session.touch(now)?;
        SessionRepository::update(tx, &session).await?;

        Ok(session)
    }

    /// Rotates a session, generating a new raw token and appending an immutable rotation record.
    pub async fn rotate(
        tx: &mut PgConnection,
        session_id: SessionId,
        session_config: &SessionConfig,
        ip_address: Option<&str>,
    ) -> Result<(SessionRotation, String), ApplicationError> {
        let new_raw_token = generate_session_token();
        let new_token_hash = session_config.hash_token(&new_raw_token);
        let new_expires_at = Utc::now() + Duration::seconds(session_config.absolute_ttl_secs);

        let rotation = SessionService::rotate_session(
            tx,
            session_id,
            new_token_hash,
            new_expires_at,
            ip_address,
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
}
