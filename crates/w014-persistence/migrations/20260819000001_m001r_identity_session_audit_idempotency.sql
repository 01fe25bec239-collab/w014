-- M001R: Physical Migration for W1 Identity, Session, Audit Chain, and Idempotency Substrate
-- Conforming to frozen Prompt-12 specifications and Staged-FK controls.

-- ============================================================================
-- 1. Identity & Organization Domain Tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_organizations_name_non_empty CHECK (length(trim(name)) > 0),
    CONSTRAINT chk_organizations_slug_non_empty CHECK (length(trim(slug)) > 0)
);

CREATE TABLE IF NOT EXISTS principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL,
    email TEXT,
    display_name TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_principals_type CHECK (principal_type IN ('user', 'service', 'system')),
    CONSTRAINT chk_principals_display_name_non_empty CHECK (length(trim(display_name)) > 0),
    CONSTRAINT uq_principals_org_email UNIQUE (organization_id, email)
);
CREATE INDEX IF NOT EXISTS idx_principals_org ON principals(organization_id);

CREATE TABLE IF NOT EXISTS programs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_programs_name_non_empty CHECK (length(trim(name)) > 0),
    CONSTRAINT chk_programs_slug_non_empty CHECK (length(trim(slug)) > 0),
    CONSTRAINT uq_programs_org_slug UNIQUE (organization_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_programs_org ON programs(organization_id);

CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    -- STAGED FK: Nullable in W1, NO FK to effective_contract_states (deferred to W3)
    current_source_state_id UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_workspaces_name_non_empty CHECK (length(trim(name)) > 0),
    CONSTRAINT chk_workspaces_slug_non_empty CHECK (length(trim(slug)) > 0),
    CONSTRAINT uq_workspaces_program_slug UNIQUE (program_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_workspaces_program ON workspaces(program_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_org ON workspaces(organization_id);

CREATE TABLE IF NOT EXISTS memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_memberships_role CHECK (role IN ('owner', 'admin', 'member', 'viewer', 'auditor')),
    CONSTRAINT uq_memberships_workspace_principal UNIQUE (workspace_id, principal_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_workspace ON memberships(workspace_id);
CREATE INDEX IF NOT EXISTS idx_memberships_principal ON memberships(principal_id);

CREATE TABLE IF NOT EXISTS capability_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    granted_by UUID REFERENCES principals(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_capability_grants_capability_non_empty CHECK (length(trim(capability)) > 0),
    CONSTRAINT uq_capability_grants_workspace_principal_cap UNIQUE (workspace_id, principal_id, capability)
);
CREATE INDEX IF NOT EXISTS idx_capability_grants_lookup ON capability_grants(workspace_id, principal_id);

CREATE TABLE IF NOT EXISTS oidc_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    claims JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_oidc_identities_issuer_non_empty CHECK (length(trim(issuer)) > 0),
    CONSTRAINT chk_oidc_identities_subject_non_empty CHECK (length(trim(subject)) > 0),
    CONSTRAINT uq_oidc_identities_issuer_subject UNIQUE (issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_principal ON oidc_identities(principal_id);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL,
    session_token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_sessions_status CHECK (status IN ('active', 'revoked', 'expired')),
    CONSTRAINT chk_sessions_token_hash_non_empty CHECK (length(trim(session_token_hash)) > 0)
);
CREATE INDEX IF NOT EXISTS idx_sessions_principal ON sessions(principal_id);
CREATE INDEX IF NOT EXISTS idx_sessions_workspace ON sessions(workspace_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(session_token_hash);

CREATE TABLE IF NOT EXISTS session_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    old_token_hash TEXT NOT NULL,
    new_token_hash TEXT NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    CONSTRAINT chk_session_rotations_old_hash_non_empty CHECK (length(trim(old_token_hash)) > 0),
    CONSTRAINT chk_session_rotations_new_hash_non_empty CHECK (length(trim(new_token_hash)) > 0)
);
CREATE INDEX IF NOT EXISTS idx_session_rotations_session ON session_rotations(session_id);

CREATE TABLE IF NOT EXISTS oidc_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_token TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL,
    pkce_verifier TEXT,
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT chk_oidc_transactions_state_non_empty CHECK (length(trim(state_token)) > 0),
    CONSTRAINT chk_oidc_transactions_nonce_non_empty CHECK (length(trim(nonce)) > 0)
);
CREATE INDEX IF NOT EXISTS idx_oidc_transactions_state ON oidc_transactions(state_token);

-- ============================================================================
-- 2. Persistence-State Owned Tables: Audit & Idempotency
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_chain_heads (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE RESTRICT,
    head_sequence_num BIGINT NOT NULL DEFAULT 0,
    head_event_hash TEXT NOT NULL,
    genesis_hash TEXT NOT NULL,
    last_appended_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_audit_chain_heads_seq_non_negative CHECK (head_sequence_num >= 0),
    CONSTRAINT chk_audit_chain_heads_hash_len CHECK (length(head_event_hash) = 64),
    CONSTRAINT chk_audit_chain_heads_genesis_len CHECK (length(genesis_hash) = 64)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    sequence_num BIGINT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_principal_id UUID REFERENCES principals(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- STAGED FK: Nullable in W1, NO FK to jobs table (deferred to W2)
    job_id UUID NULL,
    correlation_id TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_audit_events_seq_positive CHECK (sequence_num > 0),
    CONSTRAINT chk_audit_events_prev_hash_len CHECK (length(previous_event_hash) = 64),
    CONSTRAINT chk_audit_events_hash_len CHECK (length(event_hash) = 64),
    CONSTRAINT chk_audit_events_type_non_empty CHECK (length(trim(event_type)) > 0),
    CONSTRAINT chk_audit_events_action_non_empty CHECK (length(trim(action)) > 0),
    CONSTRAINT chk_audit_events_res_type_non_empty CHECK (length(trim(resource_type)) > 0),
    CONSTRAINT chk_audit_events_res_id_non_empty CHECK (length(trim(resource_id)) > 0),
    CONSTRAINT uq_audit_events_workspace_seq UNIQUE (workspace_id, sequence_num),
    CONSTRAINT uq_audit_events_workspace_hash UNIQUE (workspace_id, event_hash)
);
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_seq ON audit_events(workspace_id, sequence_num ASC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation ON audit_events(correlation_id);

CREATE TABLE IF NOT EXISTS idempotency_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    response_status_code INT,
    response_headers JSONB,
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT chk_idempotency_status CHECK (status IN ('in_progress', 'completed', 'failed')),
    CONSTRAINT chk_idempotency_key_non_empty CHECK (length(trim(idempotency_key)) > 0),
    CONSTRAINT chk_idempotency_req_hash_len CHECK (length(request_hash) = 64)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_idempotency_workspace_key 
ON idempotency_records(COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), idempotency_key);
CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_records(expires_at);

-- ============================================================================
-- 3. Immutability Triggers for Authoritative Audit History
-- ============================================================================

CREATE OR REPLACE FUNCTION fn_prevent_audit_events_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE and DELETE operations are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_prevent_audit_events_mutation
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION fn_prevent_audit_events_mutation();

CREATE OR REPLACE FUNCTION fn_prevent_audit_chain_heads_deletion()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain_heads is protected: DELETE operations are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_prevent_audit_chain_heads_deletion
BEFORE DELETE ON audit_chain_heads
FOR EACH ROW EXECUTE FUNCTION fn_prevent_audit_chain_heads_deletion();

CREATE OR REPLACE FUNCTION fn_enforce_audit_chain_heads_progression()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.head_sequence_num < OLD.head_sequence_num THEN
        RAISE EXCEPTION 'audit_chain_heads sequence cannot decrease: % < %', NEW.head_sequence_num, OLD.head_sequence_num;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_enforce_audit_chain_heads_progression
BEFORE UPDATE ON audit_chain_heads
FOR EACH ROW EXECUTE FUNCTION fn_enforce_audit_chain_heads_progression();

-- ============================================================================
-- 4. Row Level Security (RLS) Mechanics & Tenant Isolation
-- ============================================================================

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;

ALTER TABLE capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE capability_grants FORCE ROW LEVEL SECURITY;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_workspaces_isolation ON workspaces
    FOR ALL
    USING (id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY rls_memberships_isolation ON memberships
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY rls_capability_grants_isolation ON capability_grants
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY rls_sessions_isolation ON sessions
    FOR ALL
    USING (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY rls_audit_chain_heads_isolation ON audit_chain_heads
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY rls_audit_events_isolation ON audit_events
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY rls_idempotency_records_isolation ON idempotency_records
    FOR ALL
    USING (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

-- ============================================================================
-- 5. Database Roles & Grants for Application & Readonly Access
-- ============================================================================

DO $$
BEGIN
    BEGIN
        CREATE ROLE w014_app WITH LOGIN PASSWORD 'w014_app_pass';
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;

    BEGIN
        CREATE ROLE w014_readonly WITH LOGIN PASSWORD 'w014_readonly_pass';
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;
END $$;

GRANT USAGE ON SCHEMA public TO w014_app, w014_readonly;

-- Identity & Domain tables: standard application CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON principals TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON programs TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON workspaces TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON memberships TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON capability_grants TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_identities TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON session_rotations TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_transactions TO w014_app;

-- Idempotency: SELECT, INSERT, UPDATE
GRANT SELECT, INSERT, UPDATE ON idempotency_records TO w014_app;

-- Audit chain heads: SELECT, INSERT, UPDATE (NO DELETE)
GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO w014_app;

-- Audit events: SELECT, INSERT only (NO UPDATE, NO DELETE)
GRANT SELECT, INSERT ON audit_events TO w014_app;

-- Readonly role grants
GRANT SELECT ON ALL TABLES IN SCHEMA public TO w014_readonly;
