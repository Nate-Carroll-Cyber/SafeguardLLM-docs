/**
 * Async job lifecycle.
 *
 * Shared by the submit path (adapter) and the worker. The two call different
 * functions here and hold different IAM permissions, so a bug in one cannot
 * reach the other's operations: the adapter has PutItem and GetItem and no
 * UpdateItem, so it cannot advance a job's state or forge a payload; the worker
 * has UpdateItem and no PutItem, so it cannot create work for itself.
 *
 * State machine — five states, and the client handles states rather than HTTP
 * codes. `BLOCKED` and `FAILED` are both terminal and mean different things:
 * one is a policy decision the caller should see as a policy decision, the
 * other is a system fault.
 *
 *   QUEUED     ──▶ PROCESSING ──▶ COMPLETED   payload available
 *                             ├─▶ BLOCKED     guardrail, PII, or judge denial
 *                             └─▶ FAILED      timeout, upstream 5xx, crash
 *
 * Node.js 20+, ESM. Dependencies: @aws-sdk/client-dynamodb, @aws-sdk/lib-dynamodb.
 */

import crypto from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

const required = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
};

const JOB_TABLE = required("JOB_TABLE");
const BUDGET_TABLE = required("BUDGET_TABLE");
const TOKEN_BUDGET = Number(process.env.TENANT_TOKEN_BUDGET ?? 1_000_000);
const MAX_COMPLETION_TOKENS = Number(process.env.MAX_COMPLETION_TOKENS ?? 2048);
const JOB_TTL_HOURS = Number(process.env.JOB_TTL_HOURS ?? 2);

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: { removeUndefinedValues: true },
});

export const JobStatus = Object.freeze({
  QUEUED: "QUEUED",
  PROCESSING: "PROCESSING",
  COMPLETED: "COMPLETED",
  BLOCKED: "BLOCKED",
  FAILED: "FAILED",
});

const key = (tenantId, jobId) => ({ pk: `TENANT#${tenantId}`, sk: `JOB#${jobId}` });
const ttl = () => Math.floor(Date.now() / 1000) + JOB_TTL_HOURS * 3600;

// ---------------------------------------------------------------------------
// Budget — two-phase
//
// Async inverts the risk the synchronous design managed. There, the budget was
// charged immediately before a call that was about to happen. Here, submit is
// cheap and fast, so a caller could enqueue far more work than their budget
// permits before any of it completed and reported its cost.
//
// So: reserve an upper bound at submit, reconcile at completion. A caller who
// abandons the poll still pays actuals — the tokens were spent regardless of
// whether anyone collected the result.
// ---------------------------------------------------------------------------

/**
 * Phase 1. Charges prompt tokens plus the maximum possible completion, so the
 * reservation is never an underestimate.
 *
 * Atomic conditional UpdateItem, not read-then-write: concurrent submissions
 * must not both pass against a stale value. Two counters for the same reason as
 * the synchronous design — a caller entitled to several tenants would otherwise
 * multiply its budget by rotating the tenant it asserts.
 */
export async function reserveBudget({ tenantId, clientId, promptTokens }) {
  const estimate = promptTokens + MAX_COMPLETION_TOKENS;
  const window = new Date().toISOString().slice(0, 10);
  const now = Math.floor(Date.now() / 1000);

  const charge = async (pk) => {
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: BUDGET_TABLE,
          Key: { pk, sk: window },
          UpdateExpression:
            "ADD consumed :t SET expiresAt = if_not_exists(expiresAt, :e)",
          ConditionExpression: "attribute_not_exists(consumed) OR consumed < :limit",
          ExpressionAttributeValues: {
            ":t": estimate,
            ":limit": TOKEN_BUDGET,
            ":e": now + 3 * 86_400,
          },
        }),
      );
    } catch (err) {
      if (err.name === "ConditionalCheckFailedException") {
        throw Object.assign(new Error("token budget exceeded"), {
          status: 429,
          code: "TokenBudgetExceeded",
          publicMessage: "rate_limited",
        });
      }
      throw err;
    }
  };

  await charge(`TENANT#${tenantId}`);
  await charge(`CLIENT#${clientId}`);
  return estimate;
}

/**
 * Phase 2. Refunds the unspent portion.
 *
 * Never refunds more than was reserved — a negative `actual`, or an `actual`
 * above the estimate, would otherwise let a worker credit budget it never held.
 * Failures here are swallowed deliberately: a job that produced a result must
 * not be marked FAILED because the accounting write did not land. The cost of
 * that is an over-charge, which is the safe direction to be wrong in.
 */
export async function reconcileBudget({ tenantId, clientId, reserved, actual }) {
  const spent = Math.max(0, Math.min(actual, reserved));
  const refund = reserved - spent;
  if (refund <= 0) return;

  const window = new Date().toISOString().slice(0, 10);
  const credit = async (pk) => {
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: BUDGET_TABLE,
          Key: { pk, sk: window },
          UpdateExpression: "ADD consumed :r",
          ExpressionAttributeValues: { ":r": -refund },
        }),
      );
    } catch {
      // See above. Over-charging is recoverable; failing a completed job is not.
    }
  };

  await credit(`TENANT#${tenantId}`);
  await credit(`CLIENT#${clientId}`);
}

// ---------------------------------------------------------------------------
// Submit path
// ---------------------------------------------------------------------------

/**
 * Creates a QUEUED job. Written before the worker is invoked, so a job always
 * exists for any invocation the worker receives — never the reverse.
 *
 * The prompt is stored here because the worker needs it and an async invoke
 * payload is capped at 256 KB. That makes this table a prompt store as well as
 * a response store, which is why it has its own CMK and a two-hour TTL.
 */
export async function createJob({ tenantId, clientId, sub, correlationId, prompt, reserved }) {
  const jobId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  await ddb.send(
    new PutCommand({
      TableName: JOB_TABLE,
      Item: {
        ...key(tenantId, jobId),
        jobId,
        status: JobStatus.QUEUED,
        tenantId,
        clientId,
        sub,
        correlationId,
        prompt,
        reservedTokens: reserved,
        createdAt: now,
        expiresAt: ttl(),
      },
      // A UUID collision is not a real concern; this guards against a replayed
      // write rather than a duplicate identifier.
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
    }),
  );

  return jobId;
}

/**
 * Poll. Returns null when the job does not exist OR has expired — the caller
 * cannot distinguish the two, and should not: "no job under your tenant with
 * that id" is the whole answer either way.
 *
 * IAM has already constrained this before the code runs. dynamodb:LeadingKeys
 * on the submit role limits the caller to keys under their own TENANT# prefix,
 * so another tenant's job ID is denied at the service. The tenantId argument
 * comes from the authorizer context, never from the request.
 */
export async function getJob({ tenantId, jobId }) {
  const { Item } = await ddb.send(
    new GetCommand({
      TableName: JOB_TABLE,
      Key: key(tenantId, jobId),
      ConsistentRead: true,
    }),
  );
  if (!Item) return null;

  // TTL deletion lags expiry by up to 48 hours, so filter at read time: a job
  // past its expiry is gone as far as the caller is concerned, whether or not
  // DynamoDB has removed the item yet.
  if (Item.expiresAt && Item.expiresAt < Math.floor(Date.now() / 1000)) return null;

  return {
    jobId: Item.jobId,
    status: Item.status,
    createdAt: Item.createdAt,
    completedAt: Item.completedAt ?? null,
    // Present only on COMPLETED.
    response: Item.status === JobStatus.COMPLETED ? Item.response : undefined,
    // Present only on BLOCKED — a policy reason the client can render as a
    // policy decision. Deliberately coarse: which detector fired is a detection
    // oracle and stays in the ledger.
    reason: Item.status === JobStatus.BLOCKED ? Item.reason : undefined,
    correlationId: Item.correlationId,
  };
}

// ---------------------------------------------------------------------------
// Worker path
// ---------------------------------------------------------------------------

/**
 * The idempotency lock. The worker's first action, before anything else.
 *
 * Lambda async invoke is at-least-once: a network blip causes the service to
 * deliver the same event twice. Without this, a duplicate double-writes the
 * ledger and double-charges the budget — and the ledger is an audit record, so
 * a duplicate there is worse than a duplicate charge.
 *
 * Conditional on status = QUEUED. If the condition fails, another worker
 * already has the job or it has already finished. The duplicate returns false
 * and must then exit having done nothing at all — not log the prompt, not read
 * the corpus, not touch the budget.
 */
export async function claimJob({ tenantId, jobId }) {
  try {
    const { Attributes } = await ddb.send(
      new UpdateCommand({
        TableName: JOB_TABLE,
        Key: key(tenantId, jobId),
        UpdateExpression: "SET #s = :processing, startedAt = :now",
        ConditionExpression: "#s = :queued",
        ExpressionAttributeNames: { "#s": "status" },
        ExpressionAttributeValues: {
          ":processing": JobStatus.PROCESSING,
          ":queued": JobStatus.QUEUED,
          ":now": Math.floor(Date.now() / 1000),
        },
        ReturnValues: "ALL_NEW",
      }),
    );
    return Attributes;
  } catch (err) {
    if (err.name === "ConditionalCheckFailedException") return null;
    throw err;
  }
}

/**
 * Terminal transition. Only from PROCESSING, so a completion cannot overwrite
 * a job this worker never claimed.
 *
 * `response` is written only for COMPLETED. `reason` only for BLOCKED, and it
 * is a coarse category rather than a detector name — telling a caller which
 * check rejected them turns the response into a detection oracle.
 */
export async function finishJob({ tenantId, jobId, status, response, reason }) {
  if (![JobStatus.COMPLETED, JobStatus.BLOCKED, JobStatus.FAILED].includes(status)) {
    throw new Error(`not a terminal status: ${status}`);
  }

  const values = {
    ":status": status,
    ":processing": JobStatus.PROCESSING,
    ":now": Math.floor(Date.now() / 1000),
    ":ttl": ttl(),
  };
  let expr = "SET #s = :status, completedAt = :now, expiresAt = :ttl";

  if (status === JobStatus.COMPLETED && response !== undefined) {
    expr += ", #r = :response";
    values[":response"] = response;
  }
  if (status === JobStatus.BLOCKED && reason !== undefined) {
    expr += ", #reason = :reason";
    values[":reason"] = reason;
  }

  // The prompt is removed on every terminal transition. It has served its
  // purpose, and leaving it doubles this table's content footprint for the
  // remainder of the TTL.
  expr += " REMOVE prompt";

  await ddb.send(
    new UpdateCommand({
      TableName: JOB_TABLE,
      Key: key(tenantId, jobId),
      UpdateExpression: expr,
      ConditionExpression: "#s = :processing",
      ExpressionAttributeNames: {
        "#s": "status",
        ...(status === JobStatus.COMPLETED ? { "#r": "response" } : {}),
        ...(status === JobStatus.BLOCKED ? { "#reason": "reason" } : {}),
      },
      ExpressionAttributeValues: values,
    }),
  );
}
