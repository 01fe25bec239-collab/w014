//! Shared real-PostgreSQL test provisioning for the W2 durable job runtime tests.
#![allow(dead_code)]

use sqlx::PgPool;
use uuid::Uuid;

use w014_jobs::{EnqueueParams, JobKind, PgJobQueue, QUEUE_DOCUMENT_PARSE, QUEUE_MALWARE_SCAN};
use w014_persistence::{MIGRATOR, MigrationRunner, TestDatabase};

/// An isolated migrated database with two distinct workspaces.
pub struct Ctx {
    pub db: TestDatabase,
    pub ws_a: Uuid,
    pub ws_b: Uuid,
}

impl Ctx {
    pub fn pool(&self) -> &PgPool {
        self.db.pool()
    }

    pub fn queue(&self) -> PgJobQueue {
        PgJobQueue::new(self.db.pool().clone())
    }

    /// Queue backed by a connection pool that runs every statement under the
    /// restricted `w014_app` application role, so Row-Level Security is fully
    /// enforced (the superuser pool bypasses RLS).
    pub async fn rls_queue(&self) -> PgJobQueue {
        let opts = self
            .db
            .url()
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("valid url");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("SET ROLE w014_app").execute(conn).await?;
                    Ok(())
                })
            })
            .connect_with(opts)
            .await
            .expect("worker-role pool must connect");
        PgJobQueue::new(pool)
    }

    pub async fn close(self) {
        self.db.close().await.expect("Failed to drop test database");
    }
}

/// Provisions an isolated migrated database (M001R + repair + M002R) with two
/// workspaces in distinct organizations, mirroring the accepted persistence
/// contract-test harness.
pub async fn provision() -> Ctx {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R + M001R-F1 + M002R migrations");

    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let prog_a = Uuid::new_v4();
    let prog_b = Uuid::new_v4();
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO organizations (organization_id, display_name, slug) \
         VALUES ($1, 'Org A', $2), ($3, 'Org B', $4)",
    )
    .bind(org_a)
    .bind(format!("jobs-runtime-org-a-{org_a}"))
    .bind(org_b)
    .bind(format!("jobs-runtime-org-b-{org_b}"))
    .execute(test_db.pool())
    .await
    .expect("Failed to insert organizations");

    sqlx::query(
        "INSERT INTO programs (program_id, organization_id, name, program_code) \
         VALUES ($1, $2, 'Prog A', $3), ($4, $5, 'Prog B', $6)",
    )
    .bind(prog_a)
    .bind(org_a)
    .bind(format!("jobs-runtime-prog-a-{prog_a}"))
    .bind(prog_b)
    .bind(org_b)
    .bind(format!("jobs-runtime-prog-b-{prog_b}"))
    .execute(test_db.pool())
    .await
    .expect("Failed to insert programs");

    sqlx::query(
        "INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) \
         VALUES ($1, $2, $3, 'WS A', $4), ($5, $6, $7, 'WS B', $8)",
    )
    .bind(ws_a)
    .bind(prog_a)
    .bind(org_a)
    .bind(format!("jobs-runtime-ws-a-{ws_a}"))
    .bind(ws_b)
    .bind(prog_b)
    .bind(org_b)
    .bind(format!("jobs-runtime-ws-b-{ws_b}"))
    .execute(test_db.pool())
    .await
    .expect("Failed to insert workspaces");

    Ctx {
        db: test_db,
        ws_a,
        ws_b,
    }
}

/// Builds bounded, valid enqueue parameters for a kind/workspace/target set.
pub fn params_for(workspace_id: Uuid, kind: JobKind, targets: &[&str]) -> EnqueueParams {
    let mut params = EnqueueParams::new(
        workspace_id,
        kind,
        targets.iter().map(|s| (*s).to_string()).collect(),
    );
    params.producer_version = "w014-jobs-tests".to_string();
    params
}

/// Raw status read for authoritative-state assertions (superuser connection).
pub async fn raw_status(pool: &PgPool, job_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("job row must exist")
}

#[derive(Debug, sqlx::FromRow)]
pub struct LeaseState {
    pub status: String,
    pub lease_holder: Option<String>,
    pub lease_token: Option<Uuid>,
    pub lease_generation: i64,
    pub attempt_count: i32,
    pub not_before: chrono::DateTime<chrono::Utc>,
}

/// Full lease/authority state read for fencing assertions.
pub async fn lease_state(pool: &PgPool, job_id: Uuid) -> LeaseState {
    sqlx::query_as::<_, LeaseState>(
        "SELECT status, lease_holder, lease_token, lease_generation, attempt_count, not_before \
         FROM jobs WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .expect("job row must exist")
}

/// Deterministically expires a running lease via direct database manipulation
/// (no sleeps as primary correctness proof).
pub async fn force_expire_lease(pool: &PgPool, job_id: Uuid) {
    sqlx::query("UPDATE jobs SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = $1")
        .bind(job_id)
        .execute(pool)
        .await
        .expect("force-expire update must succeed");
}

/// Makes a deferred job immediately claimable.
pub async fn make_due_now(pool: &PgPool, job_id: Uuid) {
    sqlx::query(
        "UPDATE jobs SET not_before = clock_timestamp() - INTERVAL '1 second' WHERE job_id = $1",
    )
    .bind(job_id)
    .execute(pool)
    .await
    .expect("not_before update must succeed");
}

/// Canonical claim criteria for one queue in workspace scope.
pub fn single_ws_criteria(queue: &str, workspace_id: Uuid) -> w014_jobs::ClaimCriteria {
    w014_jobs::ClaimCriteria {
        queues: vec![queue.to_string()],
        kinds: Vec::new(),
        workspace: w014_jobs::WorkspaceScope::Single(workspace_id),
        lease_duration: std::time::Duration::from_secs(60),
    }
}

pub const PARSE_QUEUE: &str = QUEUE_DOCUMENT_PARSE;
pub const SCAN_QUEUE: &str = QUEUE_MALWARE_SCAN;
