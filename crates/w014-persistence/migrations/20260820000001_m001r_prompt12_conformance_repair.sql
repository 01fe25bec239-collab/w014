-- M001R-F1: Physical Forward Migration for Prompt-12 / Prompt-13 Conformance Repair
-- Conforming to exact frozen Prompt-12 specifications and Staged-FK controls.

-- ============================================================================
-- 0. Ambiguous Legacy State Verification (Fail Closed Policy)
-- ============================================================================

DO $$
BEGIN
    -- Check if any table contains semantically ambiguous legacy data that cannot be losslessly converted
    IF EXISTS (SELECT 1 FROM principals) THEN
        RAISE EXCEPTION 'Ambiguous legacy data in principals: nonproduction database must be rebuilt from corrected migration chain';
    END IF;
    IF EXISTS (SELECT 1 FROM memberships) THEN
        RAISE EXCEPTION 'Ambiguous legacy data in memberships: nonproduction database must be rebuilt from corrected migration chain';
    END IF;
    IF EXISTS (SELECT 1 FROM capability_grants) THEN
        RAISE EXCEPTION 'Ambiguous legacy data in capability_grants: nonproduction database must be rebuilt from corrected migration chain';
    END IF;
    IF EXISTS (SELECT 1 FROM oidc_transactions) THEN
        RAISE EXCEPTION 'Ambiguous legacy data in oidc_transactions: nonproduction database must be rebuilt from corrected migration chain';
    END IF;
    IF EXISTS (SELECT 1 FROM audit_events) THEN
        RAISE EXCEPTION 'Ambiguous legacy data in audit_events: nonproduction database must be rebuilt from corrected migration chain';
    END IF;
    IF EXISTS (SELECT 1 FROM idempotency_records) THEN
        RAISE EXCEPTION 'Ambiguous legacy data in idempotency_records: nonproduction database must be rebuilt from corrected migration chain';
    END IF;
END $$;

-- ============================================================================
-- 1. Required PostgreSQL Extensions
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS citext;

-- ============================================================================
-- 2. Drop Legacy Constraints, Triggers, Policies & Indexes
-- ============================================================================

-- Drop old RLS policies
DROP POLICY IF EXISTS rls_workspaces_isolation ON workspaces;
DROP POLICY IF EXISTS rls_memberships_isolation ON memberships;
DROP POLICY IF EXISTS rls_capability_grants_isolation ON capability_grants;
DROP POLICY IF EXISTS rls_sessions_isolation ON sessions;
DROP POLICY IF EXISTS rls_audit_chain_heads_isolation ON audit_chain_heads;
DROP POLICY IF EXISTS rls_audit_events_isolation ON audit_events;
DROP POLICY IF EXISTS rls_idempotency_records_isolation ON idempotency_records;

-- Drop old triggers
DROP TRIGGER IF EXISTS trg_prevent_audit_events_mutation ON audit_events;
DROP TRIGGER IF EXISTS trg_prevent_audit_chain_heads_deletion ON audit_chain_heads;
DROP TRIGGER IF EXISTS trg_enforce_audit_chain_heads_progression ON audit_chain_heads;

-- Drop old Foreign Keys to permit non-blocking schema transformation
ALTER TABLE IF EXISTS workspaces DROP CONSTRAINT IF EXISTS fk_workspaces_program_org;
ALTER TABLE IF EXISTS workspaces DROP CONSTRAINT IF EXISTS workspaces_program_id_fkey;
ALTER TABLE IF EXISTS workspaces DROP CONSTRAINT IF EXISTS workspaces_organization_id_fkey;
ALTER TABLE IF EXISTS programs DROP CONSTRAINT IF EXISTS programs_organization_id_fkey;
ALTER TABLE IF EXISTS principals DROP CONSTRAINT IF EXISTS principals_organization_id_fkey;
ALTER TABLE IF EXISTS memberships DROP CONSTRAINT IF EXISTS memberships_workspace_id_fkey;
ALTER TABLE IF EXISTS memberships DROP CONSTRAINT IF EXISTS memberships_principal_id_fkey;
ALTER TABLE IF EXISTS capability_grants DROP CONSTRAINT IF EXISTS capability_grants_workspace_id_fkey;
ALTER TABLE IF EXISTS capability_grants DROP CONSTRAINT IF EXISTS capability_grants_principal_id_fkey;
ALTER TABLE IF EXISTS capability_grants DROP CONSTRAINT IF EXISTS capability_grants_granted_by_fkey;
ALTER TABLE IF EXISTS oidc_identities DROP CONSTRAINT IF EXISTS oidc_identities_principal_id_fkey;
ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_principal_id_fkey;
ALTER TABLE IF EXISTS session_rotations DROP CONSTRAINT IF EXISTS session_rotations_session_id_fkey;
ALTER TABLE IF EXISTS audit_chain_heads DROP CONSTRAINT IF EXISTS audit_chain_heads_workspace_id_fkey;
ALTER TABLE IF EXISTS audit_events DROP CONSTRAINT IF EXISTS audit_events_workspace_id_fkey;
ALTER TABLE IF EXISTS audit_events DROP CONSTRAINT IF EXISTS audit_events_actor_principal_id_fkey;
ALTER TABLE IF EXISTS idempotency_records DROP CONSTRAINT IF EXISTS idempotency_records_workspace_id_fkey;

-- ============================================================================
-- 3. Transform Domain & Identity Tables to Exact Prompt-12 Specifications
-- ============================================================================

-- 3.1 Organizations
ALTER TABLE organizations RENAME COLUMN id TO organization_id;
ALTER TABLE organizations RENAME COLUMN name TO display_name;
ALTER TABLE organizations ALTER COLUMN slug TYPE CITEXT;
ALTER TABLE organizations DROP COLUMN IF EXISTS updated_at;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS chk_organizations_name_non_empty;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS chk_organizations_slug_non_empty;
ALTER TABLE organizations ADD CONSTRAINT chk_organizations_display_name_non_empty CHECK (length(trim(display_name)) > 0);
ALTER TABLE organizations ADD CONSTRAINT chk_organizations_slug_non_empty CHECK (length(trim(slug::text)) > 0);

-- 3.2 Principals (Organization-independent in Prompt-12)
ALTER TABLE principals RENAME COLUMN id TO principal_id;
ALTER TABLE principals DROP COLUMN IF EXISTS organization_id;
ALTER TABLE principals DROP COLUMN IF EXISTS principal_type;
ALTER TABLE principals DROP COLUMN IF EXISTS is_active;
ALTER TABLE principals DROP COLUMN IF EXISTS updated_at;
ALTER TABLE principals ALTER COLUMN email TYPE CITEXT;
ALTER TABLE principals ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE principals DROP CONSTRAINT IF EXISTS chk_principals_type;
ALTER TABLE principals DROP CONSTRAINT IF EXISTS chk_principals_display_name_non_empty;
ALTER TABLE principals DROP CONSTRAINT IF EXISTS uq_principals_org_email;
ALTER TABLE principals DROP CONSTRAINT IF EXISTS uq_principals_id_org;
ALTER TABLE principals ADD CONSTRAINT chk_principals_display_name_non_empty CHECK (length(trim(display_name)) > 0);
ALTER TABLE principals ADD CONSTRAINT chk_principals_status CHECK (status IN ('active', 'suspended', 'deactivated'));
DROP INDEX IF EXISTS idx_principals_org;
CREATE INDEX IF NOT EXISTS idx_principals_email ON principals(email);
CREATE INDEX IF NOT EXISTS idx_principals_status ON principals(status);

-- 3.3 Programs
ALTER TABLE programs RENAME COLUMN id TO program_id;
ALTER TABLE programs RENAME COLUMN slug TO program_code;
ALTER TABLE programs DROP COLUMN IF EXISTS description;
ALTER TABLE programs DROP COLUMN IF EXISTS updated_at;
ALTER TABLE programs ADD COLUMN IF NOT EXISTS row_version INT NOT NULL DEFAULT 1;
ALTER TABLE programs DROP CONSTRAINT IF EXISTS chk_programs_name_non_empty;
ALTER TABLE programs DROP CONSTRAINT IF EXISTS chk_programs_slug_non_empty;
ALTER TABLE programs DROP CONSTRAINT IF EXISTS uq_programs_org_slug;
ALTER TABLE programs DROP CONSTRAINT IF EXISTS uq_programs_id_org;
ALTER TABLE programs ADD CONSTRAINT chk_programs_name_non_empty CHECK (length(trim(name)) > 0);
ALTER TABLE programs ADD CONSTRAINT chk_programs_program_code_non_empty CHECK (length(trim(program_code)) > 0);
ALTER TABLE programs ADD CONSTRAINT chk_programs_row_version_positive CHECK (row_version > 0);
ALTER TABLE programs ADD CONSTRAINT fk_programs_organization FOREIGN KEY (organization_id) REFERENCES organizations(organization_id) ON DELETE CASCADE;
ALTER TABLE programs ADD CONSTRAINT uq_programs_org_program_code UNIQUE (organization_id, program_code);
ALTER TABLE programs ADD CONSTRAINT uq_programs_id_org UNIQUE (program_id, organization_id);
DROP INDEX IF EXISTS idx_programs_org;
CREATE INDEX IF NOT EXISTS idx_programs_organization_id ON programs(organization_id);

-- 3.4 Workspaces
ALTER TABLE workspaces RENAME COLUMN id TO workspace_id;
ALTER TABLE workspaces RENAME COLUMN slug TO workspace_code;
ALTER TABLE workspaces DROP COLUMN IF EXISTS updated_at;
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS row_version INT NOT NULL DEFAULT 1;
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS chk_workspaces_name_non_empty;
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS chk_workspaces_slug_non_empty;
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS uq_workspaces_program_slug;
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS uq_workspaces_id_org;
ALTER TABLE workspaces ADD CONSTRAINT chk_workspaces_name_non_empty CHECK (length(trim(name)) > 0);
ALTER TABLE workspaces ADD CONSTRAINT chk_workspaces_workspace_code_non_empty CHECK (length(trim(workspace_code)) > 0);
ALTER TABLE workspaces ADD CONSTRAINT chk_workspaces_row_version_positive CHECK (row_version > 0);
ALTER TABLE workspaces ADD CONSTRAINT fk_workspaces_organization FOREIGN KEY (organization_id) REFERENCES organizations(organization_id) ON DELETE CASCADE;
ALTER TABLE workspaces ADD CONSTRAINT fk_workspaces_program_org FOREIGN KEY (program_id, organization_id) REFERENCES programs(program_id, organization_id) ON DELETE CASCADE;
ALTER TABLE workspaces ADD CONSTRAINT uq_workspaces_program_workspace_code UNIQUE (program_id, workspace_code);
ALTER TABLE workspaces ADD CONSTRAINT uq_workspaces_id_org UNIQUE (workspace_id, organization_id);
DROP INDEX IF EXISTS idx_workspaces_org;
DROP INDEX IF EXISTS idx_workspaces_program;
CREATE INDEX IF NOT EXISTS idx_workspaces_organization_id ON workspaces(organization_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_program_id ON workspaces(program_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_program_org ON workspaces(program_id, organization_id);

-- 3.5 Memberships
ALTER TABLE memberships RENAME COLUMN id TO membership_id;
ALTER TABLE memberships DROP COLUMN IF EXISTS role;
ALTER TABLE memberships DROP COLUMN IF EXISTS updated_at;
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS role_code TEXT NOT NULL DEFAULT 'reader';
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ NULL;
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS row_version INT NOT NULL DEFAULT 1;
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS chk_memberships_role;
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS uq_memberships_workspace_principal;
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS uq_memberships_id_workspace;
ALTER TABLE memberships ADD CONSTRAINT chk_memberships_role_code CHECK (role_code IN ('admin', 'operator', 'reviewer', 'reader'));
ALTER TABLE memberships ADD CONSTRAINT chk_memberships_status CHECK (status IN ('active', 'suspended', 'revoked', 'expired'));
ALTER TABLE memberships ADD CONSTRAINT chk_memberships_validity_interval CHECK (valid_until IS NULL OR valid_until > valid_from);
ALTER TABLE memberships ADD CONSTRAINT chk_memberships_row_version_positive CHECK (row_version > 0);
ALTER TABLE memberships ADD CONSTRAINT fk_memberships_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE;
ALTER TABLE memberships ADD CONSTRAINT fk_memberships_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE;
ALTER TABLE memberships ADD CONSTRAINT uq_memberships_id_workspace UNIQUE (membership_id, workspace_id);
DROP INDEX IF EXISTS idx_memberships_workspace;
DROP INDEX IF EXISTS idx_memberships_principal;
CREATE INDEX IF NOT EXISTS idx_memberships_workspace_id ON memberships(workspace_id);
CREATE INDEX IF NOT EXISTS idx_memberships_principal_id ON memberships(principal_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_memberships_active_workspace_principal ON memberships(workspace_id, principal_id) WHERE status = 'active';

-- 3.6 Capability Grants (Dual-scope workspace/program)
ALTER TABLE capability_grants RENAME COLUMN id TO capability_grant_id;
ALTER TABLE capability_grants RENAME COLUMN capability TO capability_code;
ALTER TABLE capability_grants RENAME COLUMN granted_by TO granted_by_principal_id;
ALTER TABLE capability_grants ALTER COLUMN workspace_id DROP NOT NULL;
ALTER TABLE capability_grants ADD COLUMN IF NOT EXISTS program_id UUID NULL;
ALTER TABLE capability_grants ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;
ALTER TABLE capability_grants ADD COLUMN IF NOT EXISTS revoked_by_principal_id UUID NULL;
ALTER TABLE capability_grants ADD COLUMN IF NOT EXISTS grant_reason TEXT NULL;
ALTER TABLE capability_grants DROP CONSTRAINT IF EXISTS chk_capability_grants_capability_non_empty;
ALTER TABLE capability_grants DROP CONSTRAINT IF EXISTS uq_capability_grants_workspace_principal_cap;
ALTER TABLE capability_grants DROP CONSTRAINT IF EXISTS uq_capability_grants_id_workspace;
ALTER TABLE capability_grants ADD CONSTRAINT chk_capability_grants_capability_code_non_empty CHECK (length(trim(capability_code)) > 0);
ALTER TABLE capability_grants ADD CONSTRAINT chk_capability_grants_scope CHECK ((workspace_id IS NOT NULL AND program_id IS NULL) OR (workspace_id IS NULL AND program_id IS NOT NULL));
ALTER TABLE capability_grants ADD CONSTRAINT chk_capability_grants_expiry CHECK (expires_at IS NULL OR expires_at > granted_at);
ALTER TABLE capability_grants ADD CONSTRAINT chk_capability_grants_revocation CHECK (revoked_at IS NULL OR revoked_at >= granted_at);
ALTER TABLE capability_grants ADD CONSTRAINT fk_capability_grants_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE;
ALTER TABLE capability_grants ADD CONSTRAINT fk_capability_grants_program FOREIGN KEY (program_id) REFERENCES programs(program_id) ON DELETE CASCADE;
ALTER TABLE capability_grants ADD CONSTRAINT fk_capability_grants_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE;
ALTER TABLE capability_grants ADD CONSTRAINT fk_capability_grants_granted_by FOREIGN KEY (granted_by_principal_id) REFERENCES principals(principal_id) ON DELETE SET NULL;
ALTER TABLE capability_grants ADD CONSTRAINT fk_capability_grants_revoked_by FOREIGN KEY (revoked_by_principal_id) REFERENCES principals(principal_id) ON DELETE SET NULL;
ALTER TABLE capability_grants ADD CONSTRAINT uq_capability_grants_id_workspace UNIQUE (capability_grant_id, workspace_id);
DROP INDEX IF EXISTS idx_capability_grants_lookup;
CREATE INDEX IF NOT EXISTS idx_capability_grants_workspace_principal ON capability_grants(workspace_id, principal_id);
CREATE INDEX IF NOT EXISTS idx_capability_grants_program_principal ON capability_grants(program_id, principal_id);
CREATE INDEX IF NOT EXISTS idx_capability_grants_principal_id ON capability_grants(principal_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_capability_grants_active_workspace ON capability_grants(workspace_id, principal_id, capability_code) WHERE workspace_id IS NOT NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_capability_grants_active_program ON capability_grants(program_id, principal_id, capability_code) WHERE program_id IS NOT NULL AND revoked_at IS NULL;

-- 3.7 OIDC Identities
ALTER TABLE oidc_identities RENAME COLUMN id TO oidc_identity_id;
ALTER TABLE oidc_identities DROP COLUMN IF EXISTS claims;
ALTER TABLE oidc_identities DROP COLUMN IF EXISTS updated_at;
ALTER TABLE oidc_identities RENAME COLUMN email TO email_at_link;
ALTER TABLE oidc_identities ALTER COLUMN email_at_link TYPE CITEXT;
ALTER TABLE oidc_identities RENAME COLUMN created_at TO linked_at;
ALTER TABLE oidc_identities ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NULL;
ALTER TABLE oidc_identities DROP CONSTRAINT IF EXISTS chk_oidc_identities_issuer_non_empty;
ALTER TABLE oidc_identities DROP CONSTRAINT IF EXISTS chk_oidc_identities_subject_non_empty;
ALTER TABLE oidc_identities DROP CONSTRAINT IF EXISTS uq_oidc_identities_issuer_subject;
ALTER TABLE oidc_identities ADD CONSTRAINT chk_oidc_identities_issuer_non_empty CHECK (length(trim(issuer)) > 0);
ALTER TABLE oidc_identities ADD CONSTRAINT chk_oidc_identities_subject_non_empty CHECK (length(trim(subject)) > 0);
ALTER TABLE oidc_identities ADD CONSTRAINT fk_oidc_identities_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE;
ALTER TABLE oidc_identities ADD CONSTRAINT uq_oidc_identities_issuer_subject UNIQUE (issuer, subject);
DROP INDEX IF EXISTS idx_oidc_identities_principal;
CREATE INDEX IF NOT EXISTS idx_oidc_identities_principal_id ON oidc_identities(principal_id);

-- 3.8 Sessions (Disable non-frozen RLS policy)
ALTER TABLE sessions ADD CONSTRAINT fk_sessions_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE;
ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE sessions NO FORCE ROW LEVEL SECURITY;

-- 3.9 Session Rotations
ALTER TABLE session_rotations RENAME COLUMN id TO session_rotation_id;
ALTER TABLE session_rotations DROP COLUMN IF EXISTS ip_address;
ALTER TABLE session_rotations ADD COLUMN IF NOT EXISTS rotation_number INT NOT NULL DEFAULT 1;
ALTER TABLE session_rotations ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT 'periodic';
ALTER TABLE session_rotations DROP CONSTRAINT IF EXISTS session_rotations_session_id_fkey;
ALTER TABLE session_rotations ADD CONSTRAINT fk_session_rotations_session FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE;
ALTER TABLE session_rotations ADD CONSTRAINT chk_session_rotations_rotation_number CHECK (rotation_number > 0);
ALTER TABLE session_rotations ADD CONSTRAINT chk_session_rotations_reason CHECK (reason IN ('periodic', 'privilege_change', 'manual_refresh', 'concurrent_limit', 'reuse_detected', 'inactivity_refresh'));
ALTER TABLE session_rotations ADD CONSTRAINT uq_session_rotations_session_number UNIQUE (session_id, rotation_number);
DROP INDEX IF EXISTS idx_session_rotations_session;
CREATE INDEX IF NOT EXISTS idx_session_rotations_session_id ON session_rotations(session_id);

-- 3.10 OIDC Transactions
ALTER TABLE oidc_transactions RENAME COLUMN id TO oidc_transaction_id;
ALTER TABLE oidc_transactions DROP COLUMN IF EXISTS state_token;
ALTER TABLE oidc_transactions DROP COLUMN IF EXISTS nonce;
ALTER TABLE oidc_transactions DROP COLUMN IF EXISTS pkce_verifier;
ALTER TABLE oidc_transactions DROP COLUMN IF EXISTS redirect_uri;
ALTER TABLE oidc_transactions ADD COLUMN IF NOT EXISTS state_hash BYTEA NOT NULL DEFAULT '\x00'::bytea;
ALTER TABLE oidc_transactions ADD COLUMN IF NOT EXISTS nonce_hash BYTEA NOT NULL DEFAULT '\x00'::bytea;
ALTER TABLE oidc_transactions ADD COLUMN IF NOT EXISTS pkce_verifier_ciphertext BYTEA NULL;
ALTER TABLE oidc_transactions ADD COLUMN IF NOT EXISTS return_path TEXT NOT NULL DEFAULT '/';
ALTER TABLE oidc_transactions ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ NULL;
ALTER TABLE oidc_transactions ALTER COLUMN state_hash DROP DEFAULT;
ALTER TABLE oidc_transactions ALTER COLUMN nonce_hash DROP DEFAULT;
ALTER TABLE oidc_transactions ALTER COLUMN return_path DROP DEFAULT;
ALTER TABLE oidc_transactions DROP CONSTRAINT IF EXISTS chk_oidc_transactions_state_non_empty;
ALTER TABLE oidc_transactions DROP CONSTRAINT IF EXISTS chk_oidc_transactions_nonce_non_empty;
ALTER TABLE oidc_transactions ADD CONSTRAINT chk_oidc_transactions_expiry CHECK (expires_at > created_at);
ALTER TABLE oidc_transactions ADD CONSTRAINT chk_oidc_transactions_consumed CHECK (consumed_at IS NULL OR consumed_at >= created_at);
ALTER TABLE oidc_transactions ADD CONSTRAINT uq_oidc_transactions_state_hash UNIQUE (state_hash);
DROP INDEX IF EXISTS idx_oidc_transactions_state;
CREATE INDEX IF NOT EXISTS idx_oidc_transactions_expires_at ON oidc_transactions(expires_at);

-- ============================================================================
-- 4. Transform Audit Chain & Idempotency Tables
-- ============================================================================

-- 4.1 Audit Chain Heads
ALTER TABLE audit_chain_heads DROP COLUMN IF EXISTS head_sequence_num;
ALTER TABLE audit_chain_heads DROP COLUMN IF EXISTS head_event_hash;
ALTER TABLE audit_chain_heads DROP COLUMN IF EXISTS genesis_hash;
ALTER TABLE audit_chain_heads DROP COLUMN IF EXISTS last_appended_at;
ALTER TABLE audit_chain_heads ADD COLUMN IF NOT EXISTS last_sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE audit_chain_heads ADD COLUMN IF NOT EXISTS last_event_hash BYTEA NULL;
ALTER TABLE audit_chain_heads DROP CONSTRAINT IF EXISTS chk_audit_chain_heads_seq_non_negative;
ALTER TABLE audit_chain_heads DROP CONSTRAINT IF EXISTS chk_audit_chain_heads_hash_len;
ALTER TABLE audit_chain_heads DROP CONSTRAINT IF EXISTS chk_audit_chain_heads_genesis_len;
ALTER TABLE audit_chain_heads ADD CONSTRAINT chk_audit_chain_heads_last_seq_non_negative CHECK (last_sequence >= 0);
ALTER TABLE audit_chain_heads ADD CONSTRAINT chk_audit_chain_heads_last_hash_len CHECK (last_event_hash IS NULL OR octet_length(last_event_hash) = 32);
ALTER TABLE audit_chain_heads ADD CONSTRAINT fk_audit_chain_heads_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE RESTRICT;

-- 4.2 Audit Events (Fixed Canonical Envelope)
ALTER TABLE audit_events DROP COLUMN IF EXISTS id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS sequence_num;
ALTER TABLE audit_events DROP COLUMN IF EXISTS previous_event_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS event_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS event_type;
ALTER TABLE audit_events DROP COLUMN IF EXISTS actor_principal_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS action;
ALTER TABLE audit_events DROP COLUMN IF EXISTS resource_type;
ALTER TABLE audit_events DROP COLUMN IF EXISTS resource_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS payload;
ALTER TABLE audit_events DROP COLUMN IF EXISTS recorded_at;

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS audit_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid();
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS sequence BIGINT NOT NULL DEFAULT 1;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT 'system';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_id UUID NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS authority_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS action_code TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS entity_type TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS entity_id TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS entity_version INT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS request_id TEXT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS source_state_hash BYTEA NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS before_ref JSONB NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS after_ref JSONB NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS previous_event_hash BYTEA NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_hash BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea;

ALTER TABLE audit_events ALTER COLUMN sequence DROP DEFAULT;
ALTER TABLE audit_events ALTER COLUMN actor_type DROP DEFAULT;
ALTER TABLE audit_events ALTER COLUMN action_code DROP DEFAULT;
ALTER TABLE audit_events ALTER COLUMN entity_type DROP DEFAULT;
ALTER TABLE audit_events ALTER COLUMN entity_id DROP DEFAULT;
ALTER TABLE audit_events ALTER COLUMN event_hash DROP DEFAULT;

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_seq_positive;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_prev_hash_len;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_hash_len;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_type_non_empty;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_action_non_empty;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_res_type_non_empty;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS chk_audit_events_res_id_non_empty;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS uq_audit_events_workspace_seq;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS uq_audit_events_workspace_hash;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS uq_audit_events_id_workspace;

ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_sequence_positive CHECK (sequence > 0);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_action_code_non_empty CHECK (length(trim(action_code)) > 0);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_entity_type_non_empty CHECK (length(trim(entity_type)) > 0);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_entity_id_non_empty CHECK (length(trim(entity_id)) > 0);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_actor_type_non_empty CHECK (length(trim(actor_type)) > 0);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_prev_hash_len CHECK (previous_event_hash IS NULL OR octet_length(previous_event_hash) = 32);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_hash_len CHECK (octet_length(event_hash) = 32);
ALTER TABLE audit_events ADD CONSTRAINT chk_audit_events_src_state_hash_len CHECK (source_state_hash IS NULL OR octet_length(source_state_hash) = 32);

ALTER TABLE audit_events ADD CONSTRAINT fk_audit_events_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE RESTRICT;
ALTER TABLE audit_events ADD CONSTRAINT uq_audit_events_workspace_sequence UNIQUE (workspace_id, sequence);
ALTER TABLE audit_events ADD CONSTRAINT uq_audit_events_workspace_hash UNIQUE (workspace_id, event_hash);
ALTER TABLE audit_events ADD CONSTRAINT uq_audit_events_id_workspace UNIQUE (audit_event_id, workspace_id);

DROP INDEX IF EXISTS idx_audit_events_workspace_seq;
DROP INDEX IF EXISTS idx_audit_events_actor;
DROP INDEX IF EXISTS idx_audit_events_correlation;

CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_seq ON audit_events(workspace_id, sequence ASC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON audit_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events(occurred_at);

-- 4.3 Idempotency Records
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS id;
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS idempotency_key;
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS request_hash;
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS status;
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS response_status_code;
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS response_headers;
ALTER TABLE idempotency_records DROP COLUMN IF EXISTS completed_at;

ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS idempotency_record_id UUID PRIMARY KEY DEFAULT gen_random_uuid();
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS principal_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'::uuid;
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS route_code TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS key_hash BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea;
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS request_hash BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea;
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS response_status SMALLINT NULL;

ALTER TABLE idempotency_records ALTER COLUMN principal_id DROP DEFAULT;
ALTER TABLE idempotency_records ALTER COLUMN route_code DROP DEFAULT;
ALTER TABLE idempotency_records ALTER COLUMN key_hash DROP DEFAULT;
ALTER TABLE idempotency_records ALTER COLUMN request_hash DROP DEFAULT;

ALTER TABLE idempotency_records DROP CONSTRAINT IF EXISTS chk_idempotency_status;
ALTER TABLE idempotency_records DROP CONSTRAINT IF EXISTS chk_idempotency_key_non_empty;
ALTER TABLE idempotency_records DROP CONSTRAINT IF EXISTS chk_idempotency_req_hash_len;
ALTER TABLE idempotency_records DROP CONSTRAINT IF EXISTS uq_idempotency_id_workspace;
DROP INDEX IF EXISTS uq_idempotency_workspace_key;

ALTER TABLE idempotency_records ADD CONSTRAINT chk_idempotency_route_code_non_empty CHECK (length(trim(route_code)) > 0);
ALTER TABLE idempotency_records ADD CONSTRAINT chk_idempotency_key_hash_len CHECK (octet_length(key_hash) = 32);
ALTER TABLE idempotency_records ADD CONSTRAINT chk_idempotency_req_hash_len CHECK (octet_length(request_hash) = 32);
ALTER TABLE idempotency_records ADD CONSTRAINT chk_idempotency_expiry CHECK (expires_at > created_at);
ALTER TABLE idempotency_records ADD CONSTRAINT chk_idempotency_status_valid CHECK (response_status IS NULL OR (response_status >= 100 AND response_status <= 599));

ALTER TABLE idempotency_records ADD CONSTRAINT fk_idempotency_records_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE;
ALTER TABLE idempotency_records ADD CONSTRAINT fk_idempotency_records_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE;
ALTER TABLE idempotency_records ADD CONSTRAINT uq_idempotency_records_identity UNIQUE NULLS NOT DISTINCT (workspace_id, principal_id, route_code, key_hash);
ALTER TABLE idempotency_records ADD CONSTRAINT uq_idempotency_records_id_workspace UNIQUE (idempotency_record_id, workspace_id);

-- ============================================================================
-- 5. Immutability Triggers for Authoritative Audit History
-- ============================================================================

CREATE OR REPLACE FUNCTION fn_prevent_audit_events_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE and DELETE operations are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_audit_events_mutation
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION fn_prevent_audit_events_mutation();

CREATE OR REPLACE FUNCTION fn_prevent_audit_chain_heads_deletion()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain_heads is protected: DELETE operations are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_audit_chain_heads_deletion
BEFORE DELETE ON audit_chain_heads
FOR EACH ROW EXECUTE FUNCTION fn_prevent_audit_chain_heads_deletion();

CREATE OR REPLACE FUNCTION fn_enforce_audit_chain_heads_progression()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.last_sequence < OLD.last_sequence THEN
        RAISE EXCEPTION 'audit_chain_heads sequence cannot decrease: % < %', NEW.last_sequence, OLD.last_sequence;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_audit_chain_heads_progression
BEFORE UPDATE ON audit_chain_heads
FOR EACH ROW EXECUTE FUNCTION fn_enforce_audit_chain_heads_progression();

-- ============================================================================
-- 6. Row Level Security (RLS) Mechanics & Tenant Isolation
-- ============================================================================

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;

ALTER TABLE capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE capability_grants FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_workspaces_isolation ON workspaces
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

CREATE POLICY rls_memberships_isolation ON memberships
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

CREATE POLICY rls_capability_grants_isolation ON capability_grants
    FOR ALL
    USING (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

CREATE POLICY rls_audit_chain_heads_isolation ON audit_chain_heads
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

CREATE POLICY rls_audit_events_isolation ON audit_events
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

CREATE POLICY rls_idempotency_records_isolation ON idempotency_records
    FOR ALL
    USING (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id IS NULL OR workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- ============================================================================
-- 7. Database Roles & Grants (Password-Free Migration Delivery)
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'w014_app') THEN
        BEGIN
            CREATE ROLE w014_app WITH LOGIN;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'w014_worker') THEN
        BEGIN
            CREATE ROLE w014_worker WITH LOGIN;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_append') THEN
        BEGIN
            CREATE ROLE audit_append;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ops_readonly') THEN
        BEGIN
            CREATE ROLE ops_readonly WITH LOGIN;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migration_owner') THEN
        BEGIN
            CREATE ROLE migration_owner;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'break_glass') THEN
        BEGIN
            CREATE ROLE break_glass;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
END $$;

-- Revoke legacy w014_readonly permissions if present
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'w014_readonly') THEN
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM w014_readonly;
        REVOKE ALL ON SCHEMA public FROM w014_readonly;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO w014_app, w014_worker, ops_readonly, audit_append;

-- Application Role CRUD (Prompt-12 / Prompt-13 permissions)
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
GRANT SELECT, INSERT, UPDATE ON idempotency_records TO w014_app;
GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO w014_app;
GRANT SELECT, INSERT ON audit_events TO w014_app;

-- Worker Role Permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, principals, programs, workspaces, memberships, capability_grants, oidc_identities, sessions, session_rotations, oidc_transactions TO w014_worker;
GRANT SELECT, INSERT, UPDATE ON idempotency_records TO w014_worker;
GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO w014_worker;
GRANT SELECT, INSERT ON audit_events TO w014_worker;

-- Audit Append Role: Narrow authority
GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO audit_append;
GRANT SELECT, INSERT ON audit_events TO audit_append;

-- Ops Readonly Role: Bounded diagnostics
GRANT SELECT ON organizations, principals, programs, workspaces, memberships, capability_grants, oidc_identities, sessions, session_rotations, oidc_transactions, audit_chain_heads, audit_events, idempotency_records TO ops_readonly;
