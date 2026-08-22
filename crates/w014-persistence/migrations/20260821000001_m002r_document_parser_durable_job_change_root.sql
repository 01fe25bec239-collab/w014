-- M002R: Physical Migration for W2 Document Pipeline, Object Storage, Parser Hierarchy,
-- Durable Job Substrate, and Change Evidence Ledger.
-- Conforming to exact frozen Prompt-12 specifications and Staged-FK controls.

-- ============================================================================
-- 1. Document & Object Domain Tables (1-6)
-- ============================================================================

-- 1.1 Documents Table
CREATE TABLE IF NOT EXISTS documents (
    document_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    document_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_by UUID NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version INT NOT NULL DEFAULT 1,
    CONSTRAINT chk_documents_title_non_empty CHECK (length(trim(title)) > 0),
    CONSTRAINT chk_documents_type_non_empty CHECK (length(trim(document_type)) > 0),
    CONSTRAINT chk_documents_status CHECK (status IN ('active', 'archived', 'deleted')),
    CONSTRAINT chk_documents_row_version_positive CHECK (row_version > 0),
    CONSTRAINT uq_documents_id_workspace UNIQUE (document_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_documents_workspace_id ON documents(workspace_id);
CREATE INDEX IF NOT EXISTS idx_documents_created_by ON documents(created_by);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);

-- 1.2 Document Versions Table
CREATE TABLE IF NOT EXISTS document_versions (
    document_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    version_number INT NOT NULL,
    byte_size BIGINT NOT NULL,
    sha256_hash BYTEA NOT NULL,
    content_type TEXT NOT NULL,
    trust_state TEXT NOT NULL DEFAULT 'pending',
    created_by UUID NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_document_versions_version_positive CHECK (version_number > 0),
    CONSTRAINT chk_document_versions_byte_size_non_negative CHECK (byte_size >= 0),
    CONSTRAINT chk_document_versions_sha256_len CHECK (octet_length(sha256_hash) = 32),
    CONSTRAINT chk_document_versions_content_type_non_empty CHECK (length(trim(content_type)) > 0),
    CONSTRAINT chk_document_versions_trust_state CHECK (trust_state IN ('pending', 'scanning', 'trusted', 'quarantined', 'rejected')),
    CONSTRAINT uq_document_versions_document_version UNIQUE (document_id, version_number),
    CONSTRAINT uq_document_versions_id_workspace UNIQUE (document_version_id, workspace_id),
    CONSTRAINT fk_document_versions_document_workspace FOREIGN KEY (document_id, workspace_id) REFERENCES documents(document_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT fk_document_versions_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_document_versions_document_id ON document_versions(document_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_workspace_id ON document_versions(workspace_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_trust_state ON document_versions(trust_state);
CREATE INDEX IF NOT EXISTS idx_document_versions_sha256_hash ON document_versions(sha256_hash);

-- 1.3 Document Version Metadata Table
CREATE TABLE IF NOT EXISTS document_version_metadata (
    document_version_metadata_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    custom_fields JSONB NOT NULL DEFAULT '{}'::jsonb,
    extracted_author TEXT NULL,
    extracted_title TEXT NULL,
    page_count INT NULL,
    word_count INT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_doc_ver_metadata_page_count CHECK (page_count IS NULL OR page_count >= 0),
    CONSTRAINT chk_doc_ver_metadata_word_count CHECK (word_count IS NULL OR word_count >= 0),
    CONSTRAINT uq_doc_ver_metadata_version UNIQUE (document_version_id),
    CONSTRAINT uq_doc_ver_metadata_id_workspace UNIQUE (document_version_metadata_id, workspace_id),
    CONSTRAINT fk_doc_ver_metadata_ver_workspace FOREIGN KEY (document_version_id, workspace_id) REFERENCES document_versions(document_version_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT fk_doc_ver_metadata_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_doc_ver_metadata_version_id ON document_version_metadata(document_version_id);
CREATE INDEX IF NOT EXISTS idx_doc_ver_metadata_workspace_id ON document_version_metadata(workspace_id);

-- 1.4 Upload Intents Table
CREATE TABLE IF NOT EXISTS upload_intents (
    upload_intent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    document_id UUID NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    expected_size_bytes BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'initiated',
    storage_key TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_upload_intents_filename_non_empty CHECK (length(trim(filename)) > 0),
    CONSTRAINT chk_upload_intents_content_type_non_empty CHECK (length(trim(content_type)) > 0),
    CONSTRAINT chk_upload_intents_size_positive CHECK (expected_size_bytes > 0),
    CONSTRAINT chk_upload_intents_status CHECK (status IN ('initiated', 'uploaded', 'verified', 'expired', 'aborted')),
    CONSTRAINT chk_upload_intents_expiry CHECK (expires_at > created_at),
    CONSTRAINT chk_upload_intents_completed CHECK (completed_at IS NULL OR completed_at >= created_at),
    CONSTRAINT uq_upload_intents_id_workspace UNIQUE (upload_intent_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_upload_intents_workspace_id ON upload_intents(workspace_id);
CREATE INDEX IF NOT EXISTS idx_upload_intents_principal_id ON upload_intents(principal_id);
CREATE INDEX IF NOT EXISTS idx_upload_intents_status ON upload_intents(status);
CREATE INDEX IF NOT EXISTS idx_upload_intents_expires_at ON upload_intents(expires_at);

-- 1.5 Object Artifacts Table
CREATE TABLE IF NOT EXISTS object_artifacts (
    object_artifact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    storage_bucket TEXT NOT NULL,
    storage_key TEXT NOT NULL UNIQUE,
    byte_size BIGINT NOT NULL,
    sha256_hash BYTEA NOT NULL,
    content_type TEXT NOT NULL,
    storage_tier TEXT NOT NULL DEFAULT 'hot',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_object_artifacts_bucket_non_empty CHECK (length(trim(storage_bucket)) > 0),
    CONSTRAINT chk_object_artifacts_key_non_empty CHECK (length(trim(storage_key)) > 0),
    CONSTRAINT chk_object_artifacts_byte_size_non_negative CHECK (byte_size >= 0),
    CONSTRAINT chk_object_artifacts_sha256_len CHECK (octet_length(sha256_hash) = 32),
    CONSTRAINT chk_object_artifacts_content_type_non_empty CHECK (length(trim(content_type)) > 0),
    CONSTRAINT chk_object_artifacts_tier CHECK (storage_tier IN ('hot', 'warm', 'cold', 'archive')),
    CONSTRAINT uq_object_artifacts_id_workspace UNIQUE (object_artifact_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_object_artifacts_workspace_id ON object_artifacts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_object_artifacts_sha256_hash ON object_artifacts(sha256_hash);

-- 1.6 Quarantine Records Table
CREATE TABLE IF NOT EXISTS quarantine_records (
    quarantine_record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    document_version_id UUID NULL REFERENCES document_versions(document_version_id) ON DELETE CASCADE,
    object_artifact_id UUID NULL REFERENCES object_artifacts(object_artifact_id) ON DELETE SET NULL,
    quarantine_reason TEXT NOT NULL,
    scanner_name TEXT NOT NULL,
    scanner_version TEXT NULL,
    threat_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'quarantined',
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMPTZ NULL,
    reviewed_by UUID NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
    review_decision TEXT NULL,
    CONSTRAINT chk_quarantine_records_reason_non_empty CHECK (length(trim(quarantine_reason)) > 0),
    CONSTRAINT chk_quarantine_records_scanner_non_empty CHECK (length(trim(scanner_name)) > 0),
    CONSTRAINT chk_quarantine_records_status CHECK (status IN ('quarantined', 'released', 'purged')),
    CONSTRAINT chk_quarantine_records_decision CHECK (review_decision IS NULL OR review_decision IN ('false_positive', 'confirmed_threat', 'overridden')),
    CONSTRAINT chk_quarantine_records_review_time CHECK (reviewed_at IS NULL OR reviewed_at >= quarantined_at),
    CONSTRAINT uq_quarantine_records_id_workspace UNIQUE (quarantine_record_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_quarantine_records_workspace_id ON quarantine_records(workspace_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_records_doc_ver ON quarantine_records(document_version_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_records_object ON quarantine_records(object_artifact_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_records_status ON quarantine_records(status);

-- ============================================================================
-- 2. Durable Job Substrate Tables (7-11)
-- ============================================================================

-- 2.1 Jobs Table
-- Frozen Prompt-12 status domain: requested -> queued -> running ->
--   retryable (re-claimable) / succeeded / failed / cancelled / dead_letter.
-- Queue claim support: status IN ('queued','retryable'), not_before <= clock_timestamp(),
--   cancellation_requested = false, lease absent or expired, FOR UPDATE SKIP LOCKED.
-- Canonical Jobs-AI semantic identity: UNIQUE(idempotency_key).
CREATE TABLE IF NOT EXISTS jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    queue_name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested',
    priority INT NOT NULL DEFAULT 0,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NULL,
    error_details JSONB NULL,
    idempotency_key TEXT NULL,
    correlation_id TEXT NULL,
    cancellation_requested BOOLEAN NOT NULL DEFAULT false,
    lease_holder TEXT NULL,
    lease_token UUID NULL,
    lease_generation BIGINT NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ NULL,
    last_heartbeat_at TIMESTAMPTZ NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    backoff_base_secs INT NOT NULL DEFAULT 2,
    backoff_max_secs INT NOT NULL DEFAULT 300,
    not_before TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    row_version INT NOT NULL DEFAULT 1,
    CONSTRAINT chk_jobs_queue_name_non_empty CHECK (length(trim(queue_name)) > 0),
    CONSTRAINT chk_jobs_job_type_non_empty CHECK (length(trim(job_type)) > 0),
    CONSTRAINT chk_jobs_status CHECK (status IN ('requested', 'queued', 'running', 'retryable', 'succeeded', 'failed', 'cancelled', 'dead_letter')),
    CONSTRAINT chk_jobs_attempts CHECK (attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts),
    CONSTRAINT chk_jobs_lease_generation CHECK (lease_generation >= 0),
    CONSTRAINT chk_jobs_row_version_positive CHECK (row_version > 0),
    CONSTRAINT uq_jobs_id_workspace UNIQUE (job_id, workspace_id),
    CONSTRAINT uq_jobs_idempotency_key UNIQUE (idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_jobs_workspace_id ON jobs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_jobs_queue_claim ON jobs(queue_name, priority DESC, not_before ASC) WHERE status IN ('queued', 'retryable') AND cancellation_requested = false;
CREATE INDEX IF NOT EXISTS idx_jobs_lease_expires ON jobs(lease_expires_at) WHERE status = 'running' AND lease_expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_jobs_correlation_id ON jobs(correlation_id);

-- 2.2 Job Attempts Table
-- Frozen Prompt-12 physical contract: append-only attempt history.
-- Exact columns: job_attempt_id, job_id, attempt_number, worker_id, started_at,
--   completed_at, outcome, error_code, error_detail_redacted.
-- Only the frozen terminal-completion fields (outcome, completed_at, error_code,
--   error_detail_redacted) may transition exactly once from 'running'.
CREATE TABLE IF NOT EXISTS job_attempts (
    job_attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    attempt_number INT NOT NULL,
    worker_id TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ NULL,
    outcome TEXT NOT NULL DEFAULT 'running',
    error_code TEXT NULL,
    error_detail_redacted TEXT NULL,
    CONSTRAINT chk_job_attempts_attempt_number_positive CHECK (attempt_number >= 1),
    CONSTRAINT chk_job_attempts_worker_id_non_empty CHECK (length(trim(worker_id)) > 0),
    CONSTRAINT chk_job_attempts_outcome CHECK (outcome IN ('running', 'succeeded', 'retryable_failed', 'terminal_failed', 'cancelled', 'lease_expired')),
    CONSTRAINT chk_job_attempts_terminal_completion CHECK ((outcome = 'running') = (completed_at IS NULL)),
    CONSTRAINT uq_job_attempts_job_attempt UNIQUE (job_id, attempt_number)
);
CREATE INDEX IF NOT EXISTS idx_job_attempts_worker_id ON job_attempts(worker_id);

CREATE OR REPLACE FUNCTION fn_enforce_job_attempts_append_only()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Referential-integrity cascades from parent jobs/workspaces rows are the
        -- only permitted deletion path; direct DELETE mutations are prohibited.
        IF pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'job_attempts is append-only: DELETE operations are prohibited';
    END IF;
    IF NEW.job_attempt_id IS DISTINCT FROM OLD.job_attempt_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_number IS DISTINCT FROM OLD.attempt_number
       OR NEW.worker_id IS DISTINCT FROM OLD.worker_id
       OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'job_attempts identity fields are immutable: %', TG_OP;
    END IF;
    IF OLD.outcome <> 'running' THEN
        RAISE EXCEPTION 'job_attempts row is finalized: terminal-completion fields may transition only once';
    END IF;
    IF NEW.outcome = 'running' THEN
        RAISE EXCEPTION 'job_attempts UPDATE must transition outcome to a terminal value';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_job_attempts_append_only
BEFORE UPDATE OR DELETE ON job_attempts
FOR EACH ROW EXECUTE FUNCTION fn_enforce_job_attempts_append_only();

-- 2.3 Job Dependencies Table
-- Frozen Prompt-12 physical contract: dependency edges between jobs in the same
-- family; tenant scoping flows through the parent jobs row. The predecessor
-- success predicate is status = 'succeeded' on depends_on_job_id.
CREATE TABLE IF NOT EXISTS job_dependencies (
    job_dependency_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    depends_on_job_id UUID NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_job_dependencies_not_self CHECK (job_id <> depends_on_job_id),
    CONSTRAINT uq_job_dependencies_pair UNIQUE (job_id, depends_on_job_id)
);
CREATE INDEX IF NOT EXISTS idx_job_dependencies_depends_on ON job_dependencies(depends_on_job_id);

-- 2.4 Job Progress Table
-- Frozen Prompt-12 physical contract: DURABLE STAGE-LEVEL PROGRESS EVENTS.
-- Exact columns: job_progress_id, job_id, sequence, stage_code, current, total,
--   message_code, created_at. INSERT ONLY: multiple sequential events per job are
--   permitted; duplicate (job_id, sequence) is rejected. No UPSERT / mutable row.
CREATE TABLE IF NOT EXISTS job_progress (
    job_progress_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    sequence INT NOT NULL,
    stage_code TEXT NOT NULL,
    current BIGINT NOT NULL,
    total BIGINT NULL,
    message_code TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_job_progress_sequence_non_negative CHECK (sequence >= 0),
    CONSTRAINT chk_job_progress_stage_code_non_empty CHECK (length(trim(stage_code)) > 0),
    CONSTRAINT chk_job_progress_current_non_negative CHECK (current >= 0),
    CONSTRAINT chk_job_progress_total_gte_current CHECK (total IS NULL OR total >= current),
    CONSTRAINT chk_job_progress_message_code_non_empty CHECK (message_code IS NULL OR length(trim(message_code)) > 0),
    CONSTRAINT uq_job_progress_job_sequence UNIQUE (job_id, sequence)
);

CREATE OR REPLACE FUNCTION fn_enforce_job_progress_insert_only()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Referential-integrity cascades from parent jobs/workspaces rows are the
        -- only permitted deletion path; direct DELETE mutations are prohibited.
        IF pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'job_progress is insert-only: % operations are prohibited', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_job_progress_insert_only
BEFORE UPDATE OR DELETE ON job_progress
FOR EACH ROW EXECUTE FUNCTION fn_enforce_job_progress_insert_only();

-- 2.5 Dead Letter Entries Table
-- Frozen Prompt-12 physical contract: one durable dead-letter record per poisoned
-- job; tenant scoping flows through the parent jobs row.
CREATE TABLE IF NOT EXISTS dead_letter_entries (
    dead_letter_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    queue_name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempt_count INT NOT NULL,
    failure_reason TEXT NOT NULL,
    error_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    resolved_at TIMESTAMPTZ NULL,
    resolved_by UUID NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
    resolution_notes TEXT NULL,
    CONSTRAINT chk_dead_letter_failure_reason_non_empty CHECK (length(trim(failure_reason)) > 0),
    CONSTRAINT chk_dead_letter_queue_name_non_empty CHECK (length(trim(queue_name)) > 0),
    CONSTRAINT chk_dead_letter_job_type_non_empty CHECK (length(trim(job_type)) > 0),
    CONSTRAINT chk_dead_letter_attempt_count_positive CHECK (attempt_count > 0),
    CONSTRAINT chk_dead_letter_resolved CHECK (resolved_at IS NULL OR resolved_at >= failed_at),
    CONSTRAINT uq_dead_letter_job UNIQUE (job_id)
);
CREATE INDEX IF NOT EXISTS idx_dead_letter_queue_name ON dead_letter_entries(queue_name);

-- ============================================================================
-- 3. Parser Artifacts & Document Span Hierarchy Tables (12-15)
-- ============================================================================

-- 3.1 Parser Artifacts Table
CREATE TABLE IF NOT EXISTS parser_artifacts (
    parser_artifact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    job_id UUID NULL REFERENCES jobs(job_id) ON DELETE SET NULL,
    parser_name TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'processing',
    page_count INT NOT NULL DEFAULT 0,
    block_count INT NOT NULL DEFAULT 0,
    span_count INT NOT NULL DEFAULT 0,
    execution_duration_ms BIGINT NULL,
    error_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_parser_artifacts_name_non_empty CHECK (length(trim(parser_name)) > 0),
    CONSTRAINT chk_parser_artifacts_version_non_empty CHECK (length(trim(parser_version)) > 0),
    CONSTRAINT chk_parser_artifacts_status CHECK (status IN ('processing', 'completed', 'failed')),
    CONSTRAINT chk_parser_artifacts_page_count_non_negative CHECK (page_count >= 0),
    CONSTRAINT chk_parser_artifacts_block_count_non_negative CHECK (block_count >= 0),
    CONSTRAINT chk_parser_artifacts_span_count_non_negative CHECK (span_count >= 0),
    CONSTRAINT chk_parser_artifacts_duration_non_negative CHECK (execution_duration_ms IS NULL OR execution_duration_ms >= 0),
    CONSTRAINT chk_parser_artifacts_completed CHECK (completed_at IS NULL OR completed_at >= created_at),
    CONSTRAINT uq_parser_artifacts_id_workspace UNIQUE (parser_artifact_id, workspace_id),
    CONSTRAINT fk_parser_artifacts_doc_version_ws FOREIGN KEY (document_version_id, workspace_id) REFERENCES document_versions(document_version_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT fk_parser_artifacts_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_parser_artifacts_workspace_id ON parser_artifacts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_parser_artifacts_doc_version ON parser_artifacts(document_version_id);
CREATE INDEX IF NOT EXISTS idx_parser_artifacts_job_id ON parser_artifacts(job_id);
CREATE INDEX IF NOT EXISTS idx_parser_artifacts_status ON parser_artifacts(status);

-- 3.2 Parser Pages Table
CREATE TABLE IF NOT EXISTS parser_pages (
    parser_page_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parser_artifact_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    page_number INT NOT NULL,
    width DOUBLE PRECISION NULL,
    height DOUBLE PRECISION NULL,
    rotation INT NOT NULL DEFAULT 0,
    text_content TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_parser_pages_page_num_positive CHECK (page_number > 0),
    CONSTRAINT chk_parser_pages_rotation CHECK (rotation IN (0, 90, 180, 270)),
    CONSTRAINT chk_parser_pages_dimensions CHECK ((width IS NULL AND height IS NULL) OR (width > 0 AND height > 0)),
    CONSTRAINT uq_parser_pages_artifact_page UNIQUE (parser_artifact_id, page_number),
    CONSTRAINT uq_parser_pages_id_workspace UNIQUE (parser_page_id, workspace_id),
    CONSTRAINT fk_parser_pages_artifact_workspace FOREIGN KEY (parser_artifact_id, workspace_id) REFERENCES parser_artifacts(parser_artifact_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT fk_parser_pages_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_parser_pages_artifact_id ON parser_pages(parser_artifact_id);
CREATE INDEX IF NOT EXISTS idx_parser_pages_workspace_id ON parser_pages(workspace_id);

-- 3.3 Parser Blocks Table
CREATE TABLE IF NOT EXISTS parser_blocks (
    parser_block_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parser_page_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    block_sequence INT NOT NULL,
    block_type TEXT NOT NULL,
    bounding_box JSONB NULL,
    text_content TEXT NOT NULL DEFAULT '',
    confidence DOUBLE PRECISION NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_parser_blocks_sequence_non_negative CHECK (block_sequence >= 0),
    CONSTRAINT chk_parser_blocks_type_non_empty CHECK (length(trim(block_type)) > 0),
    CONSTRAINT chk_parser_blocks_confidence CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    CONSTRAINT uq_parser_blocks_page_sequence UNIQUE (parser_page_id, block_sequence),
    CONSTRAINT uq_parser_blocks_id_workspace UNIQUE (parser_block_id, workspace_id),
    CONSTRAINT fk_parser_blocks_page_workspace FOREIGN KEY (parser_page_id, workspace_id) REFERENCES parser_pages(parser_page_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT fk_parser_blocks_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_parser_blocks_page_id ON parser_blocks(parser_page_id);
CREATE INDEX IF NOT EXISTS idx_parser_blocks_workspace_id ON parser_blocks(workspace_id);
CREATE INDEX IF NOT EXISTS idx_parser_blocks_type ON parser_blocks(block_type);

-- 3.4 Source Spans Table
CREATE TABLE IF NOT EXISTS source_spans (
    source_span_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parser_block_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    span_sequence INT NOT NULL,
    start_char INT NOT NULL,
    end_char INT NOT NULL,
    text_content TEXT NOT NULL,
    bounding_box JSONB NULL,
    confidence DOUBLE PRECISION NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_source_spans_sequence_non_negative CHECK (span_sequence >= 0),
    CONSTRAINT chk_source_spans_char_interval CHECK (start_char >= 0 AND end_char >= start_char),
    CONSTRAINT chk_source_spans_confidence CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    CONSTRAINT uq_source_spans_block_sequence UNIQUE (parser_block_id, span_sequence),
    CONSTRAINT uq_source_spans_id_workspace UNIQUE (source_span_id, workspace_id),
    CONSTRAINT fk_source_spans_block_workspace FOREIGN KEY (parser_block_id, workspace_id) REFERENCES parser_blocks(parser_block_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT fk_source_spans_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_source_spans_block_id ON source_spans(parser_block_id);
CREATE INDEX IF NOT EXISTS idx_source_spans_workspace_id ON source_spans(workspace_id);

-- ============================================================================
-- 4. Source & Change Evidence Ledger Tables (16-17)
-- ============================================================================

-- 4.1 Dependency Keys Table (Precedes Change Events)
CREATE TABLE IF NOT EXISTS dependency_keys (
    dependency_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    key_type TEXT NOT NULL,
    key_value TEXT NOT NULL,
    key_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_dependency_keys_type_non_empty CHECK (length(trim(key_type)) > 0),
    CONSTRAINT chk_dependency_keys_val_non_empty CHECK (length(trim(key_value)) > 0),
    CONSTRAINT chk_dependency_keys_hash_len CHECK (octet_length(key_hash) = 32),
    CONSTRAINT uq_dependency_keys_workspace_hash UNIQUE (workspace_id, key_hash),
    CONSTRAINT uq_dependency_keys_id_workspace UNIQUE (dependency_key_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_dependency_keys_workspace_id ON dependency_keys(workspace_id);
CREATE INDEX IF NOT EXISTS idx_dependency_keys_type ON dependency_keys(key_type);
CREATE INDEX IF NOT EXISTS idx_dependency_keys_hash ON dependency_keys(key_hash);

-- 4.2 Change Events Table
CREATE TABLE IF NOT EXISTS change_events (
    change_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    dependency_key_id UUID NULL REFERENCES dependency_keys(dependency_key_id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    change_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_change_events_type_non_empty CHECK (length(trim(event_type)) > 0),
    CONSTRAINT chk_change_events_entity_type_non_empty CHECK (length(trim(entity_type)) > 0),
    CONSTRAINT chk_change_events_entity_id_non_empty CHECK (length(trim(entity_id)) > 0),
    CONSTRAINT uq_change_events_id_workspace UNIQUE (change_event_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_change_events_workspace_id ON change_events(workspace_id);
CREATE INDEX IF NOT EXISTS idx_change_events_dep_key ON change_events(dependency_key_id);
CREATE INDEX IF NOT EXISTS idx_change_events_entity ON change_events(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_change_events_detected_at ON change_events(detected_at);

-- ============================================================================
-- 5. Staged Foreign Key Closures (audit_events.job_id -> jobs)
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_audit_events_job'
          AND table_name = 'audit_events'
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT fk_audit_events_job
            FOREIGN KEY (job_id)
            REFERENCES jobs(job_id)
            ON DELETE SET NULL;
    END IF;
END $$;

-- ============================================================================
-- 6. Row Level Security (RLS) & Tenant Isolation Policies
-- ============================================================================

-- Documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_documents_isolation ON documents
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Document Versions
ALTER TABLE document_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_document_versions_isolation ON document_versions
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Document Version Metadata
ALTER TABLE document_version_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_version_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_document_version_metadata_isolation ON document_version_metadata
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Upload Intents
ALTER TABLE upload_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_upload_intents_isolation ON upload_intents
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Object Artifacts
ALTER TABLE object_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_object_artifacts_isolation ON object_artifacts
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Quarantine Records
ALTER TABLE quarantine_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine_records FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_quarantine_records_isolation ON quarantine_records
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Jobs
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_jobs_isolation ON jobs
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Job Attempts (tenant scoping flows through the parent jobs row)
ALTER TABLE job_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_job_attempts_isolation ON job_attempts
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = job_attempts.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = job_attempts.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    );

-- Job Dependencies (tenant scoping flows through the parent jobs row)
ALTER TABLE job_dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_dependencies FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_job_dependencies_isolation ON job_dependencies
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = job_dependencies.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = job_dependencies.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    );

-- Job Progress (tenant scoping flows through the parent jobs row)
ALTER TABLE job_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_progress FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_job_progress_isolation ON job_progress
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = job_progress.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = job_progress.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    );

-- Dead Letter Entries (tenant scoping flows through the parent jobs row)
ALTER TABLE dead_letter_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE dead_letter_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_dead_letter_entries_isolation ON dead_letter_entries
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = dead_letter_entries.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM jobs j
            WHERE j.job_id = dead_letter_entries.job_id
              AND j.workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
        )
    );

-- Parser Artifacts
ALTER TABLE parser_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE parser_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_parser_artifacts_isolation ON parser_artifacts
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Parser Pages
ALTER TABLE parser_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE parser_pages FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_parser_pages_isolation ON parser_pages
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Parser Blocks
ALTER TABLE parser_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE parser_blocks FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_parser_blocks_isolation ON parser_blocks
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Source Spans
ALTER TABLE source_spans ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_spans FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_source_spans_isolation ON source_spans
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Dependency Keys
ALTER TABLE dependency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE dependency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_dependency_keys_isolation ON dependency_keys
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- Change Events
ALTER TABLE change_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_events FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_change_events_isolation ON change_events
    FOR ALL
    USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

-- ============================================================================
-- 7. Database Roles & Grants for Application, Worker & Ops Access
-- ============================================================================

GRANT USAGE ON SCHEMA public TO w014_app, w014_worker, ops_readonly;

-- Application Role CRUD Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON document_versions TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON document_version_metadata TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON upload_intents TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON object_artifacts TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON quarantine_records TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO w014_app;
-- job_attempts: append-only attempt history (no DELETE; single terminal transition via UPDATE)
GRANT SELECT, INSERT, UPDATE ON job_attempts TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON job_dependencies TO w014_app;
-- job_progress: insert-only durable progress events (no UPDATE, no DELETE)
GRANT SELECT, INSERT ON job_progress TO w014_app;
-- dead_letter_entries: durable evidence with bounded resolution updates (no DELETE)
GRANT SELECT, INSERT, UPDATE ON dead_letter_entries TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON parser_artifacts TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON parser_pages TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON parser_blocks TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON source_spans TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON dependency_keys TO w014_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON change_events TO w014_app;

-- Worker Role CRUD Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON document_versions TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON document_version_metadata TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON upload_intents TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON object_artifacts TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON quarantine_records TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO w014_worker;
-- job_attempts: append-only attempt history (no DELETE; single terminal transition via UPDATE)
GRANT SELECT, INSERT, UPDATE ON job_attempts TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON job_dependencies TO w014_worker;
-- job_progress: insert-only durable progress events (no UPDATE, no DELETE)
GRANT SELECT, INSERT ON job_progress TO w014_worker;
-- dead_letter_entries: durable evidence with bounded resolution updates (no DELETE)
GRANT SELECT, INSERT, UPDATE ON dead_letter_entries TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON parser_artifacts TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON parser_pages TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON parser_blocks TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON source_spans TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON dependency_keys TO w014_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON change_events TO w014_worker;

-- Ops Readonly Role Grants
GRANT SELECT ON documents, document_versions, document_version_metadata, upload_intents,
    object_artifacts, quarantine_records, jobs, job_attempts, job_dependencies,
    job_progress, dead_letter_entries, parser_artifacts, parser_pages, parser_blocks,
    source_spans, dependency_keys, change_events TO ops_readonly;
