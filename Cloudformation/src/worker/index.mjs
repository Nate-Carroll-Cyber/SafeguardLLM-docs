/**
 * Async worker.
 *
 * Everything that used to run inside the 29-second API Gateway ceiling:
 * similarity check, retrieval, pre-egress guardrail, judge, inference, ledger.
 * Invoked by the submit adapter with `InvocationType: Event`, so the ceiling is
 * Lambda's 15 minutes and the function's own 5-minute timeout.
 *
 * TWO INVARIANTS, and everything else follows from them:
 *
 *   1. A duplicate delivery must do nothing at all. Lambda async invoke is
 *      at-least-once. Without the claim lock, a retry double-writes the ledger
 *      — an audit record — and double-charges the budget.
 *
 *   2. Every path must reach a terminal state. A job left in PROCESSING is
 *      indistinguishable from a job still running, and the caller polls forever
 *      against a budget they have already been charged for.
 *
 * Deployed as worker.zip. Handler: index.handler.
 */

import {
  JobStatus,
  claimJob,
  finishJob,
  reconcileBudget,
} from "./jobs.mjs";
import { retrieve, assembleContext, infer, guardEgress } from "./inference.mjs";
import { findSimilarFingerprints, writeLedgerEntry, hash } from "./data.mjs";

const required = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
};

const EGRESS_PROXY_FUNCTION = required("EGRESS_PROXY_FUNCTION");
const EMBEDDING_MODEL_ID = required("EMBEDDING_MODEL_ID");
const SIMILARITY_THRESHOLD = Number(process.env.SIMILARITY_THRESHOLD ?? 0.78);

// Coarse categories. A caller learns that a policy stopped them and not which
// check fired — naming the detector turns the response into a detection oracle,
// which is the same reason the synchronous design returned only a verdict.
// The specific reason goes to the ledger.
const BlockReason = Object.freeze({
  POLICY: "policy_violation",
  SIMILARITY: "policy_violation",
  GUARDRAIL: "policy_violation",
  JUDGE: "policy_violation",
});

/**
 * Embeds the prompt for the adversarial-fingerprint comparison.
 *
 * The similarity check needs a vector and nothing upstream produces one - the
 * submit path deliberately holds no Bedrock permission, so this is the first
 * point in the flow where an embedding can be computed.
 *
 * Returns null on failure rather than throwing. A failed embedding degrades the
 * check to "no match found", which is the same outcome as a genuine miss. That
 * is a deliberate fail-OPEN on one detector inside a chain that is fail-closed
 * overall: the guardrail and the judge still run, and blocking every request
 * because an embedding endpoint hiccuped trades a detection layer for an
 * outage. The degradation is logged so it is visible rather than silent.
 */
async function embedPrompt(text) {
  try {
    const { BedrockRuntimeClient, InvokeModelCommand } = await import(
      "@aws-sdk/client-bedrock-runtime"
    );
    const client = new BedrockRuntimeClient({});
    const res = await client.send(
      new InvokeModelCommand({
        modelId: EMBEDDING_MODEL_ID,
        contentType: "application/json",
        accept: "application/json",
        body: JSON.stringify({ inputText: text }),
      }),
    );
    const parsed = JSON.parse(Buffer.from(res.body).toString("utf8"));
    return Array.isArray(parsed.embedding) ? parsed.embedding : null;
  } catch {
    return null;
  }
}

const log = (fields) =>
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...fields }) + "\n");

/**
 * Calls the judge through the egress proxy.
 *
 * The proxy is invoked as a function, not reached over the network — the worker
 * has no route to the egress subnet. That is what makes "the worker cannot
 * reach the internet" structurally true rather than a firewall rule.
 *
 * FAILS CLOSED on every abnormal outcome. A judge that errors, times out, or
 * returns an unrecognised verdict blocks the request. Without this branch,
 * inducing latency against a third-party endpoint we do not control would
 * bypass the shield entirely.
 */
async function callJudge({ text, correlationId }) {
  const { LambdaClient, InvokeCommand } = await import("@aws-sdk/client-lambda");
  const lambda = new LambdaClient({});

  let payload;
  try {
    const res = await lambda.send(
      new InvokeCommand({
        FunctionName: EGRESS_PROXY_FUNCTION,
        InvocationType: "RequestResponse",
        Payload: Buffer.from(JSON.stringify({ text, correlationId })),
      }),
    );
    // FunctionError is set when the proxy threw. A thrown egress proxy is a
    // guardrail that did not run, not a judge that said yes.
    if (res.FunctionError) return { verdict: "UNAVAILABLE" };
    payload = JSON.parse(Buffer.from(res.Payload).toString("utf8"));
  } catch {
    return { verdict: "UNAVAILABLE" };
  }

  const verdict = payload?.verdict;
  if (!["CLEAN", "SUSPICIOUS", "ADVERSARIAL"].includes(verdict)) {
    // Unrecognised is not clean.
    return { verdict: "UNAVAILABLE" };
  }
  return { verdict, reasoning: payload.reasoning };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export const handler = async (event) => {
  const { tenantId, jobId } = event ?? {};
  if (!tenantId || !jobId) {
    // Malformed invocation. Nothing to fail — there is no job to mark.
    log({ event: "worker_bad_invocation" });
    return { ok: false };
  }

  // ---- Invariant 1: claim before anything else.
  //
  // Conditional UpdateItem, QUEUED -> PROCESSING. A duplicate delivery loses
  // the race, returns null, and exits having read no prompt, touched no corpus,
  // and written no ledger entry. Returning ok:true satisfies the Lambda event
  // queue so the duplicate is not retried again.
  const job = await claimJob({ tenantId, jobId });
  if (!job) {
    log({ event: "worker_duplicate_ignored", jobId, tenantId });
    return { ok: true, duplicate: true };
  }

  const { prompt, clientId, sub, correlationId, reservedTokens } = job;
  const auth = {
    tenantId,
    clientId,
    sub,
    delegated: job.delegated === true,
    audience: job.audience ?? null,
    certBound: job.certBound === true,
  };

  let terminal = JobStatus.FAILED;
  let response;
  let reason;
  let guardrailAction = "NONE";
  let inputTokens = 0;
  let outputTokens = 0;
  let responseHash = hash("");

  try {
    // ---- Similarity check against the adversarial fingerprint store.
    const embedding = await embedPrompt(prompt);
    if (!embedding) {
      log({ event: "embedding_unavailable", jobId, correlationId });
    }

    const similar = embedding
      ? await findSimilarFingerprints({
          tenantId,
          embedding,
          threshold: SIMILARITY_THRESHOLD,
        }).catch(() => [])
      : [];

    if (similar.some((r) => r.similarity >= SIMILARITY_THRESHOLD)) {
      terminal = JobStatus.BLOCKED;
      reason = BlockReason.SIMILARITY;
      throw { handled: true };
    }

    // ---- Retrieval. Tenant filter comes from the job record, which took it
    //      from the authorizer context — never from anything the caller sent.
    const chunks = await retrieve({ query: prompt, tenantId, correlationId });
    const { text: groundingSource, dropped } = assembleContext(chunks);
    if (dropped > 0) log({ event: "context_truncated", jobId, dropped });

    // ---- Pre-egress guardrail. Runs BEFORE the judge because the judge is a
    //      third party: redaction has to happen on this side of the boundary.
    //      Throws on error, throttle, or missing verdict — fail-closed.
    const guarded = await guardEgress({ text: prompt, source: "INPUT" });
    if (guarded.action === "GUARDRAIL_INTERVENED") guardrailAction = guarded.action;

    // ---- Judge.
    const judged = await callJudge({ text: guarded.text, correlationId });

    if (judged.verdict === "UNAVAILABLE") {
      // The third branch. Not a policy decision — a system fault — so it is
      // FAILED rather than BLOCKED, and the caller sees a generic error rather
      // than a policy message they cannot act on.
      log({ event: "judge_unavailable", jobId, correlationId });
      terminal = JobStatus.FAILED;
      throw { handled: true };
    }

    if (judged.verdict !== "CLEAN") {
      terminal = JobStatus.BLOCKED;
      reason = BlockReason.JUDGE;
      throw { handled: true };
    }

    // ---- Inference. Only reachable on CLEAN.
    const result = await infer({
      userQuery: prompt,
      groundingSource,
      auth,
      correlationId,
      jobId,
    });

    inputTokens = result.usage?.inputTokens ?? 0;
    outputTokens = result.usage?.outputTokens ?? 0;

    if (result.intervened) {
      // Output-side guardrail. The model produced something the guardrail
      // stopped — a policy outcome, not a fault.
      guardrailAction = "GUARDRAIL_INTERVENED";
      terminal = JobStatus.BLOCKED;
      reason = BlockReason.GUARDRAIL;
      throw { handled: true };
    }

    response = result.text;
    responseHash = hash(response);
    terminal = JobStatus.COMPLETED;
  } catch (err) {
    if (!err?.handled) {
      // Genuine fault. err.code carries a class; err.message carries values
      // like table names and ARNs and does not belong in a log the workload
      // account can read.
      log({
        event: "worker_error",
        jobId,
        correlationId,
        errorCode: err?.code ?? err?.name ?? "UnknownError",
      });
      terminal = JobStatus.FAILED;
    }
  } finally {
    // ---- Invariant 2: always reach a terminal state.
    //
    // In `finally` so that an exception anywhere above still resolves the job.
    // The order matters: the job record first, because that is what unblocks
    // the caller; then the ledger; then the budget refund. Each is wrapped so a
    // failure in one does not prevent the others.

    try {
      await finishJob({
        tenantId,
        jobId,
        status: terminal,
        response: terminal === JobStatus.COMPLETED ? response : undefined,
        reason: terminal === JobStatus.BLOCKED ? reason : undefined,
      });
    } catch (err) {
      // The job stays PROCESSING and the caller polls a job that will never
      // resolve. Logged loudly because the async failure destination catches a
      // thrown handler, not a swallowed write.
      log({
        event: "terminal_write_failed",
        jobId,
        correlationId,
        errorCode: err?.name ?? "Unknown",
      });
    }

    // Ledger. Written for every terminal state including FAILED — an audit
    // trail with only successes is not an audit trail.
    try {
      await writeLedgerEntry({
        tenantId,
        correlationId,
        sub,
        clientId,
        delegated: auth.delegated,
        jobId,
        audience: auth.audience,
        certBound: auth.certBound,
        promptHash: hash(prompt ?? ""),
        responseHash,
        guardrailAction,
        modelId: process.env.INFERENCE_PROFILE_ARN ?? "unknown",
        inputTokens,
        outputTokens,
        verdict: terminal,
        reason,
      });
    } catch (err) {
      log({ event: "ledger_write_failed", jobId, errorCode: err?.name ?? "Unknown" });
    }

    // Budget reconciliation. Runs on every terminal state, including FAILED and
    // BLOCKED — a blocked request consumed the judge call and possibly the
    // guardrail call, but not the completion tokens that were reserved.
    //
    // Refunding on FAILED is deliberate: the caller should not pay a full
    // completion for a system fault. What they already spent is not refunded,
    // because reconcile never credits more than was reserved.
    try {
      await reconcileBudget({
        tenantId,
        clientId,
        reserved: reservedTokens ?? 0,
        actual: inputTokens + outputTokens,
      });
    } catch (err) {
      log({ event: "budget_reconcile_failed", jobId, errorCode: err?.name ?? "Unknown" });
    }

    log({
      event: "job_finished",
      jobId,
      tenantId,
      correlationId,
      status: terminal,
      guardrailAction,
      inputTokens,
      outputTokens,
    });
  }

  // Always resolves. Throwing here would trigger Lambda's async retry against a
  // job already in a terminal state — the claim lock would reject the retry, so
  // it would be harmless, but it would also be noise in the failure destination.
  return { ok: true, jobId, status: terminal };
};
