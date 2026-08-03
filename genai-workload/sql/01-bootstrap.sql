-- Database bootstrap for layer 04.
--
-- CloudFormation creates the cluster; it cannot create schema. Run this once
-- against the cluster writer endpoint as the master user, from a host inside the
-- VPC, before the adapter is deployed.
--
--   psql "host=<cluster-endpoint> dbname=genai_workload_db user=genai_workload_master sslmode=verify-full"
--
-- The IAM policy in layer 03 grants rds-db:connect on
-- dbuser:*/genai_workload_app. That ARN names the Postgres role below. If the
-- name here and the name in the policy diverge, IAM auth fails with a generic
-- authentication error that reads like a networking problem.

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Roles
--
-- rds_iam is what makes a Postgres role accept an IAM auth token instead of a
-- password. Granting it is the other half of EnableIAMDatabaseAuthentication:
-- the cluster flag permits IAM auth, this grant enables it for one role.
--
-- NOLOGIN is absent deliberately - these roles do log in, they just never hold
-- a password. Setting a password on an rds_iam role creates a second credential
-- path that bypasses IAM entirely.
-- ---------------------------------------------------------------------------

CREATE ROLE genai_workload_app WITH LOGIN;
GRANT rds_iam TO genai_workload_app;

CREATE ROLE genai_workload_lifecycle WITH LOGIN;
GRANT rds_iam TO genai_workload_lifecycle;

-- ---------------------------------------------------------------------------
-- Schema
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS safeguard;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA safeguard TO genai_workload_app, genai_workload_lifecycle;

-- ---------------------------------------------------------------------------
-- Fingerprints
--
-- Partitioned by ingest month for retention (spec 12.3). That is a lifecycle
-- mechanism and NOT a tenant boundary - tenant_id in the primary key and in
-- every query predicate is what isolates tenants. Row-level security below is
-- the backstop for a query that forgets the predicate.
--
-- The partition key must include the partitioning column, so the primary key is
-- composite across (tenant_id, fingerprint_id, ingest_month).
-- ---------------------------------------------------------------------------
CREATE TABLE safeguard.fingerprints (
    tenant_id       text        NOT NULL,
    fingerprint_id  uuid        NOT NULL DEFAULT gen_random_uuid(),
    ingest_month    date        NOT NULL,
    label           text        NOT NULL,
    prompt_sha256   bytea       NOT NULL,
    simhash         bigint      NOT NULL,
    embedding       vector(1024) NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, fingerprint_id, ingest_month)
) PARTITION BY RANGE (ingest_month);

-- Row-level security. The adapter sets app.tenant_id per connection from the
-- authorizer context; a query without the predicate returns nothing rather than
-- returning another tenant's rows.
ALTER TABLE safeguard.fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE safeguard.fingerprints FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON safeguard.fingerprints
    USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON safeguard.fingerprints TO genai_workload_app;

-- Seed partitions. pg_cron adds and drops the rolling window below.
CREATE TABLE safeguard.fingerprints_2026_08 PARTITION OF safeguard.fingerprints
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE safeguard.fingerprints_2026_09 PARTITION OF safeguard.fingerprints
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

-- ---------------------------------------------------------------------------
-- Indexes
--
-- HNSW over cosine distance. Built per partition, not on the parent: Postgres
-- routes an index on a partitioned table down to each partition, but building
-- explicitly keeps the parameters visible and lets a large partition be
-- reindexed without touching the others.
--
-- vector_cosine_ops matches the <=> operator used in data.mjs. Using an L2
-- index with a cosine query silently falls back to a sequential scan.
-- ---------------------------------------------------------------------------
CREATE INDEX ON safeguard.fingerprints_2026_08
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
CREATE INDEX ON safeguard.fingerprints_2026_09
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);

CREATE INDEX ON safeguard.fingerprints (tenant_id, simhash);
CREATE INDEX ON safeguard.fingerprints (tenant_id, prompt_sha256);

-- ---------------------------------------------------------------------------
-- Partition rotation
--
-- DROP on a partition is instantaneous and reclaims storage. A bulk DELETE on a
-- vector table leaves index bloat and forces a VACUUM window that Serverless v2
-- absorbs poorly at low ACU.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION safeguard.rotate_partitions(retain_months int DEFAULT 12)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = safeguard, pg_temp
AS $$
DECLARE
    next_month date := date_trunc('month', now())::date + interval '1 month';
    cutoff     date := date_trunc('month', now())::date - (retain_months || ' months')::interval;
    part_name  text;
BEGIN
    part_name := 'fingerprints_' || to_char(next_month, 'YYYY_MM');
    IF to_regclass('safeguard.' || part_name) IS NULL THEN
        EXECUTE format(
            'CREATE TABLE safeguard.%I PARTITION OF safeguard.fingerprints
             FOR VALUES FROM (%L) TO (%L)',
            part_name, next_month, next_month + interval '1 month');
        EXECUTE format(
            'CREATE INDEX ON safeguard.%I
             USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)',
            part_name);
    END IF;

    FOR part_name IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_inherits i ON i.inhrelid = c.oid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname = 'fingerprints'
           AND c.relname < 'fingerprints_' || to_char(cutoff, 'YYYY_MM')
    LOOP
        EXECUTE format('DROP TABLE safeguard.%I', part_name);
    END LOOP;
END;
$$;

SELECT cron.schedule('rotate-fingerprint-partitions', '0 3 1 * *',
                     'SELECT safeguard.rotate_partitions(12)');

-- ---------------------------------------------------------------------------
-- Least privilege
--
-- The app role reads and writes rows. It cannot alter the schema, drop
-- partitions, or read the catalog beyond what its own queries need. Schema
-- changes come through the pipeline as reviewed migrations, not from runtime.
-- ---------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA safeguard FROM PUBLIC;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA safeguard TO genai_workload_app;
GRANT EXECUTE ON FUNCTION safeguard.rotate_partitions TO genai_workload_lifecycle;

ALTER DEFAULT PRIVILEGES IN SCHEMA safeguard
    GRANT SELECT, INSERT ON TABLES TO genai_workload_app;

-- Bound a runaway query at the role level. data.mjs also sets statement_timeout
-- on the pool; this is the version a compromised client cannot raise.
ALTER ROLE genai_workload_app SET statement_timeout = '5s';
ALTER ROLE genai_workload_app SET idle_in_transaction_session_timeout = '10s';

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
-- \du+ genai_workload_app          -- expect rds_iam in "Member of"
-- SHOW rds.force_ssl;              -- expect on
-- SELECT * FROM pg_extension;      -- expect vector, pg_cron, pgcrypto
-- SELECT cron.schedule FROM cron.job;
