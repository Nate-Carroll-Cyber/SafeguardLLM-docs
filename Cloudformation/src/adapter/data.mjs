/**
 * Data access.
 *
 * Every query is parameterized. Every write is schema-validated before it leaves
 * the process. Every read and write carries the tenant from the authorizer
 * context, not from the request body.
 *
 * The IAM policy conditions in the specification (dynamodb:LeadingKeys, enumerated
 * resource ARNs, pinned SSE key) enforce the boundary at the service. This module
 * enforces it at the caller, so a policy regression is caught by tests rather than
 * discovered in an audit.
 */

import crypto from "node:crypto";
import pg from "pg";
import { Signer } from "@aws-sdk/rds-signer";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { z } from "zod";

const required = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
};

const PROXY_HOST = required("RDS_PROXY_HOST");
const PROXY_PORT = Number(process.env.RDS_PROXY_PORT ?? 5432);
const DB_NAME = required("DB_NAME");
const DB_USER = required("DB_USER");
const LEDGER_TABLE = required("LEDGER_TABLE");
const BUDGET_TABLE = required("BUDGET_TABLE");
const AWS_REGION = required("AWS_REGION");

const CONTENT_TTL_DAYS = Number(process.env.CONTENT_TTL_DAYS ?? 30);
const METADATA_TTL_DAYS = Number(process.env.METADATA_TTL_DAYS ?? 400);
const TOKEN_BUDGET = Number(process.env.TENANT_TOKEN_BUDGET ?? 1_000_000);

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: { removeUndefinedValues: true },
});

// ---------------------------------------------------------------------------
// Aurora PostgreSQL via RDS Proxy, IAM authentication
// ---------------------------------------------------------------------------

/**
 * No password anywhere — not in the environment, not in Secrets Manager for this
 * path, not in a connection string. The signer mints a short-lived token per
 * connection against the caller's execution role.
 *
 * ssl.rejectUnauthorized stays true. Disabling certificate verification is the
 * single most common way an otherwise-correct IAM auth setup becomes a
 * man-in-the-middle target inside the VPC.
 */
const signer = new Signer({
  hostname: PROXY_HOST,
  port: PROXY_PORT,
  username: DB_USER,
  region: AWS_REGION,
});

const pool = new pg.Pool({
  host: PROXY_HOST,
  port: PROXY_PORT,
  database: DB_NAME,
  user: DB_USER,
  password: () => signer.getAuthToken(),
  ssl: { rejectUnauthorized: true, ca: process.env.RDS_CA_BUNDLE },
  max: Number(process.env.PG_POOL_MAX ?? 2),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  // Bounds a query that would otherwise hold a proxy connection until the
  // Lambda timeout. Resource exhaustion is a denial-of-service vector here.
  statement_timeout: 5_000,
});

/**
 * Similarity search over the adversarial fingerprint store.
 *
 * Tenant is a bound parameter in the WHERE clause, not a string interpolation and
 * not a caller-supplied filter. The vector literal is bound as well — pgvector
 * accepts a string cast, which is exactly the shape that invites concatenation.
 *
 * The specification partitions this table by ingest month. That is a retention
 * mechanism; it is not a tenant boundary. This predicate is.
 */
export async function findSimilarFingerprints({ tenantId, embedding, threshold = 0.78, limit = 10 }) {
  if (!tenantId) throw new Error("fingerprint query without tenant");
  if (!Array.isArray(embedding)) throw new Error("embedding must be an array");

  const sql = `
    SELECT fingerprint_id,
           label,
           1 - (embedding <=> $2::vector) AS similarity
      FROM fingerprints
     WHERE tenant_id = $1
       AND 1 - (embedding <=> $2::vector) >= $3
     ORDER BY embedding <=> $2::vector
     LIMIT $4
  `;

  const { rows } = await pool.query(sql, [
    tenantId,
    `[${embedding.join(",")}]`,
    threshold,
    Math.min(limit, 50),
  ]);

  return rows;
}

// ---------------------------------------------------------------------------
// Ledger writes
// ---------------------------------------------------------------------------

/**
 * Schema-constrained ledger record.
 *
 * Model-derived values are confined to designated fields and length-capped. The
 * specification's IAM conditions prevent a compromised adapter writing to the
 * wrong table; they do not prevent it writing attacker-chosen structure into the
 * right one. Validation is what closes that.
 */
const LedgerRecord = z
  .object({
    tenantId: z.string().min(1).max(64),
    correlationId: z.string().uuid(),
    sub: z.string().min(1).max(128),
    clientId: z.string().min(1).max(128),
    delegated: z.boolean(),
    // Async: every ledger entry now belongs to a job. Without this the audit
    // record and the job record cannot be joined, which is the first thing an
    // investigation needs.
    jobId: z.string().uuid(),
    // Binding evidence. Records whether the request was audience-bound (RFC
    // 8707) and certificate-bound (viewer mTLS) at the time it was authorized,
    // so an audit can separate sender-constrained calls from bearer-only ones
    // during and after the mTLS rollout.
    audience: z.string().max(512).nullable(),
    certBound: z.boolean(),
    promptHash: z.string().regex(/^[a-f0-9]{64}$/),
    responseHash: z.string().regex(/^[a-f0-9]{64}$/),
    // Guardrail verdict recorded alongside the hash. Without it, a guarded call
    // and an unguarded one are indistinguishable in the ledger after the fact.
    guardrailAction: z.enum(["NONE", "GUARDRAIL_INTERVENED", "INTERVENED"]),
    modelId: z.string().min(1).max(256),
    inputTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    // Aligned with the job state machine: a ledger verdict now corresponds to
    // the terminal state written to the job table, so the two records agree.
    verdict: z.enum(["COMPLETED", "BLOCKED", "FAILED"]),
    // The only free-text field, and it is bounded and never rendered as markup.
    reason: z.string().max(512).optional(),
  })
  .strict();

export async function writeLedgerEntry(record) {
  const parsed = LedgerRecord.parse(record);
  const now = Math.floor(Date.now() / 1000);

  await ddb.send(
    new PutCommand({
      TableName: LEDGER_TABLE,
      Item: {
        // Tenant is the partition key, which is what dynamodb:LeadingKeys binds
        // against. Changing this key shape silently disables that condition.
        pk: `TENANT#${parsed.tenantId}`,
        sk: `EVENT#${now}#${parsed.correlationId}`,
        ...parsed,
        createdAt: now,
        contentTtl: now + CONTENT_TTL_DAYS * 86_400,
        metadataTtl: now + METADATA_TTL_DAYS * 86_400,
      },
      // Idempotent: a retry must not double-write an audit record.
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
    }),
  );
}

// ---------------------------------------------------------------------------
// Token budget — MOVED
//
// consumeBudget() lived here and charged the budget immediately, before a call
// that was about to happen. The async split makes that model wrong: submit is
// cheap and returns in milliseconds, so a caller could enqueue far more work
// than their budget permits before any of it completed and reported its cost.
//
// It is now two phases in jobs.mjs — reserveBudget() on the submit path charges
// an upper bound, reconcileBudget() on the worker refunds the unspent portion.
//
// Deleted rather than deprecated. Leaving it importable meant a plausible-
// looking call site could double-charge: once here, once through the two-phase
// path, with no error to notice.
// ---------------------------------------------------------------------------

export const hash = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

export async function shutdown() {
  await pool.end();
}
