/**
 * Express security middleware for the adapter running behind API Gateway.
 *
 * The architecture terminates TLS at CloudFront and validates identity at the
 * authorizer, so this layer is not the perimeter. It exists because the adapter
 * has write permissions and calls a model: everything below assumes the request
 * already passed the perimeter and asks what damage it could still do.
 */

import crypto from "node:crypto";
import helmet from "helmet";
import cors from "cors";
import express from "express";

const required = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
};

// Exact origins. A wildcard here would undo the origin cloaking that CloudFront
// and the regional WAF enforce upstream.
const ALLOWED_ORIGINS = required("ALLOWED_ORIGINS").split(",");

// Bounds the request before the model sees it. The WAF enforces a ceiling too;
// this is the second one, because a WAF rule change should not silently widen
// what the application accepts.
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES ?? 32_768);

export function applySecurity(app) {
  app.disable("x-powered-by");
  app.set("trust proxy", true);

  app.use(
    helmet({
      contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: "no-referrer" },
      crossOriginResourcePolicy: { policy: "same-origin" },
    }),
  );

  app.use(
    cors({
      origin(origin, cb) {
        // Server-to-server callers send no Origin. Browser callers must match exactly.
        if (!origin) return cb(null, true);
        return cb(null, ALLOWED_ORIGINS.includes(origin));
      },
      // GET is required for the async poll route, GET /v1/jobs/{jobId}.
      // Without it the browser preflight for that route fails and the SPA can
      // submit work it can never collect.
      methods: ["GET", "POST"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Request-ID"],
      credentials: false,
      maxAge: 600,
    }),
  );

  app.use(express.json({ limit: MAX_BODY_BYTES, strict: true }));
  app.use(requestContext);
  return app;
}

/**
 * Lifts authorizer output into req.auth.
 *
 * This is the only sanctioned source of identity in the adapter. Handlers must
 * never read a tenant, subject, or client from a request header — those are
 * caller-controlled, the authorizer context is not.
 */
export function requestContext(req, _res, next) {
  const authz = req.apiGateway?.event?.requestContext?.authorizer ?? {};

  if (!authz.tenantId || !authz.sub) {
    return next(Object.assign(new Error("missing authorizer context"), { status: 401 }));
  }

  req.auth = Object.freeze({
    sub: authz.sub,
    clientId: authz.clientId,
    tenantId: authz.tenantId,
    callerClass: authz.callerClass,
    scopes: (authz.scopes ?? "").split(" ").filter(Boolean),
    delegated: authz.delegated === "true",
    // Emitted by the authorizer since resource binding and mTLS landed. Lifted
    // here so the ledger can record whether a request was audience-bound and
    // certificate-bound - otherwise those checks happen and leave no trace
    // downstream of the authorizer's own access log.
    audience: authz.audience || null,
    certBound: authz.certBound === "true",
    originJti: authz.originJti || null,
  });

  req.correlationId = req.get("X-Request-ID") ?? crypto.randomUUID();
  next();
}

/**
 * Hash, never content.
 *
 * Prompt and completion bodies belong in Bedrock model invocation logging, which
 * lands in the Log Archive account under a separate key with restricted access.
 * Anything this process writes to CloudWatch is readable by anyone with workload
 * log access, so it carries hashes and metadata only.
 */
export const promptHash = (text) =>
  crypto.createHash("sha256").update(text, "utf8").digest("hex");

export function auditLog(req, fields) {
  process.stdout.write(
    JSON.stringify({
      ts: new Date().toISOString(),
      correlationId: req.correlationId,
      sub: req.auth?.sub,
      clientId: req.auth?.clientId,
      tenantId: req.auth?.tenantId,
      delegated: req.auth?.delegated,
      ...fields,
    }) + "\n",
  );
}

/**
 * Terminal error handler.
 *
 * Masks internals unconditionally. Stack traces, SQL fragments, AWS error codes,
 * and model responses all leak architecture; the correlation ID is what lets
 * support reconnect a user report to the full record in the audit stream.
 *
 * Registered last, after all routes.
 */
export function errorHandler(err, req, res, _next) {
  const status = err.status && err.status < 500 ? err.status : 500;

  auditLog(req, {
    event: "request_error",
    status,
    // err.code, not err.message — messages carry values, codes carry classes.
    errorCode: err.code ?? err.name ?? "UnknownError",
  });

  res.status(status).json({
    error: status === 500 ? "internal_error" : (err.publicMessage ?? "request_rejected"),
    correlationId: req.correlationId,
  });
}

/**
 * Fail closed on unhandled rejection.
 *
 * A Lambda container that survives an unhandled rejection serves subsequent
 * requests from indeterminate state. Exiting forces a cold start, which is the
 * cheaper failure.
 */
process.on("unhandledRejection", (reason) => {
  process.stderr.write(
    JSON.stringify({ event: "unhandled_rejection", errorCode: reason?.name ?? "Unknown" }) + "\n",
  );
  process.exit(1);
});
