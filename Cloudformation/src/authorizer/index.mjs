/**
 * API Gateway REQUEST Lambda authorizer.
 *
 * Validation profile, stated explicitly rather than inherited from library
 * defaults (RFC 8725 §3.1 — the caller must specify supported algorithms):
 *
 *   alg     RS256 only. `none` and all HMAC variants rejected.
 *   iss     Derived from userPoolId, never read from the presented token.
 *   kid     Resolved only from the JWKS at that issuer. jku/x5u/jwk ignored.
 *   typ     Not checked — Cognito does not emit RFC 9068 `at+jwt`. Token-type
 *           separation is enforced by tokenUse instead, which is stronger here
 *           because Cognito signs it into the payload.
 *   aud     Human path: REQUIRED and must equal the API resource identifier.
 *           Cognito sets it from the RFC 8707 `resource` parameter sent at
 *           /oauth2/authorize, and a refresh carries it forward.
 *           Machine path: ABSENT and cannot be requested — Cognito does not
 *           permit a resource indicator on client_credentials. Binding is
 *           client_id there. The two paths therefore have genuinely different
 *           validation rules, which is the correct outcome rather than a
 *           workaround: RFC 8725 §3.10 wants token-type validation rules to be
 *           mutually exclusive.
 *   exp/nbf Enforced. graceSeconds bounds clock skew.
 *   scope   Required per method. Deny-by-default on unmapped routes.
 *   jti     Checked against a revocation denylist (origin_jti).
 *
 * Two structural choices:
 *
 *  1. Cache key is per-method. Identity sources are Authorization + httpMethod
 *     + resourcePath, and the returned policy names ONLY the requested method
 *     ARN. A wildcard resource would cache an over-broad policy against a
 *     scope-limited token and silently disable the scope check thereafter.
 *
 *  2. Tenant is resolved server-side. The token's tenant claim is a REQUEST,
 *     not an assertion — under client_credentials it originates in
 *     caller-supplied metadata at the token endpoint. Membership in a known
 *     tenant set is not authorization; entitlement is.
 *
 * Node.js 20+, ESM. Dependencies: aws-jwt-verify, @aws-sdk/client-dynamodb,
 * @aws-sdk/lib-dynamodb.
 */

import { CognitoJwtVerifier } from "aws-jwt-verify";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";

const required = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
};

const USER_POOL_ID = required("COGNITO_USER_POOL_ID");
const HUMAN_CLIENT_IDS = required("COGNITO_HUMAN_CLIENT_IDS").split(",");
const MACHINE_CLIENT_IDS = required("COGNITO_MACHINE_CLIENT_IDS").split(",");
const ENTITLEMENT_TABLE = required("CLIENT_TENANT_ENTITLEMENT_TABLE");
const REVOCATION_TABLE = required("TOKEN_REVOCATION_TABLE");

// RFC 8707 resource indicator. Human-path access tokens must carry this as
// their aud claim; a token without it was issued without the `resource`
// parameter and is not bound to this API.
const API_RESOURCE = required("API_RESOURCE_IDENTIFIER");

// RFC 8725 §3.7 — allow a small skew, not an open window. Cognito and Lambda
// are both NTP-synced, so this is generous.
const CLOCK_SKEW_SECONDS = Number(process.env.CLOCK_SKEW_SECONDS ?? 30);

// Deny-by-default: a route absent from this map is unauthorized regardless of
// how valid the token is.
//
// Two accepted forms per route. A resource-bound human token carries scopes
// prefixed with the resource identifier; a machine token carries the bare
// `llm/*` form. The route requires one of them, not a specific one — the
// binding is enforced by the aud check, not by the scope string.
const SCOPE_BY_ROUTE = Object.freeze({
  "POST /v1/inference": ["llm/invoke", `${API_RESOURCE}/invoke`],
  "POST /v1/retrieve": ["llm/retrieve", `${API_RESOURCE}/retrieve`],
});

// ---------------------------------------------------------------------------
// Verifiers
//
// Access tokens only. There is deliberately no ID-token verifier: every route
// in SCOPE_BY_ROUTE requires a scope, ID tokens carry none, so an ID-token path
// could never succeed. A fallback that cannot succeed is worse than absent — it
// reads as though ID tokens are accepted somewhere.
//
// RFC 8725 §3.10 and RFC 9700 §2.5: validation rules for different token types
// must be mutually exclusive. tokenUse: "access" is that rule. Cognito signs
// token_use into the payload, so it cannot be forged the way a typ header could.
//
// aws-jwt-verify resolves the JWKS from the issuer it derives from userPoolId —
// it never reads iss from the presented token. That distinction is the
// difference between key pinning and signature forgery.
// ---------------------------------------------------------------------------

const verifierConfig = {
  userPoolId: USER_POOL_ID,
  tokenUse: "access",
  graceSeconds: CLOCK_SKEW_SECONDS,
};

const humanVerifier = CognitoJwtVerifier.create({
  ...verifierConfig,
  clientId: HUMAN_CLIENT_IDS,
  // Human tokens are resource-bound, so aud is present and must match. A token
  // issued without the `resource` parameter has no aud and fails here — which
  // is the intent: an unbound token is not evidence of intent to call THIS API,
  // and RFC 8707 exists precisely to stop a token minted for one resource
  // working at another.
  audience: API_RESOURCE,
});

const machineVerifier = CognitoJwtVerifier.create({
  ...verifierConfig,
  clientId: MACHINE_CLIENT_IDS,
  // No `audience`. Setting one here would reject every machine token, because
  // Cognito cannot issue an aud claim on a client_credentials grant. clientId
  // is the binding on this path and it is checked above.
});

await Promise.all([humanVerifier.hydrate(), machineVerifier.hydrate()]).catch(() => {
  // Not fatal — the first verify() will fetch. Do not log the error object; it
  // can contain the JWKS URL and response body.
});

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

// ---------------------------------------------------------------------------
// Revocation
//
// JWTs are stateless, so a valid signature says nothing about whether the token
// has been revoked since issuance. Cognito's RevokeToken invalidates every token
// sharing an origin_jti, and offline verification has no visibility into that.
//
// The denylist closes it: RevokeToken and the containment runbook both write the
// origin_jti here with a TTL matching the token's own expiry, so the row expires
// exactly when checking it stops mattering.
//
// Fails CLOSED. A revocation store that is unreachable is a store whose answer
// is unknown, and "unknown" for "is this credential revoked" is not a yes.
// ---------------------------------------------------------------------------

async function isRevoked(originJti, sub) {
  if (!originJti) {
    // Cognito emits origin_jti on all current access tokens. Absence means an
    // unexpected token shape, which is a reason to stop rather than continue.
    return true;
  }

  const { Item } = await ddb.send(
    new GetCommand({
      TableName: REVOCATION_TABLE,
      Key: { pk: `JTI#${originJti}` },
      ProjectionExpression: "revokedAt",
      // Strongly consistent. An eventually-consistent read can return a stale
      // miss for a token revoked seconds ago — precisely the window that matters.
      ConsistentRead: true,
    }),
  );

  if (Item) return true;

  // Subject-wide revocation, for "disable this caller now" containment. One
  // extra read rather than a second round trip, on the same call path.
  const { Item: subjectItem } = await ddb.send(
    new GetCommand({
      TableName: REVOCATION_TABLE,
      Key: { pk: `SUB#${sub}` },
      ProjectionExpression: "revokedAt",
      ConsistentRead: true,
    }),
  );

  return Boolean(subjectItem);
}

// ---------------------------------------------------------------------------
// Tenant entitlement
// ---------------------------------------------------------------------------

async function resolveTenant(clientId, requestedTenant) {
  const { Item } = await ddb.send(
    new GetCommand({
      TableName: ENTITLEMENT_TABLE,
      Key: { clientId },
      ProjectionExpression: "defaultTenant, allowedTenants",
      ConsistentRead: true,
    }),
  );

  if (!Item?.defaultTenant) return { tenantId: null, delegated: false };

  if (!requestedTenant) return { tenantId: Item.defaultTenant, delegated: false };

  if (requestedTenant === Item.defaultTenant) {
    return { tenantId: Item.defaultTenant, delegated: false };
  }

  // Acting for another tenant is a delegation, permitted only if provisioned.
  const allowed = new Set(Item.allowedTenants ?? []);
  if (!allowed.has(requestedTenant)) return { tenantId: null, delegated: true };

  return { tenantId: requestedTenant, delegated: true };
}

// ---------------------------------------------------------------------------
// Policy generation. Single method ARN, never a wildcard.
// ---------------------------------------------------------------------------

function policy(effect, methodArn, principalId, context) {
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [{ Action: "execute-api:Invoke", Effect: effect, Resource: methodArn }],
    },
    context,
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export const handler = async (event) => {
  const methodArn = event.methodArn;
  const route = `${event.httpMethod} ${event.resource}`;
  const acceptedScopes = SCOPE_BY_ROUTE[route];

  if (!acceptedScopes) throw new Error("Unauthorized");

  const header = event.headers?.authorization ?? event.headers?.Authorization;
  if (!header?.startsWith("Bearer ")) throw new Error("Unauthorized");
  const token = header.slice(7);

  // Machine first — the higher-volume path and the narrower client set. Each
  // verifier enforces signature, iss, exp, nbf, token_use, and client binding.
  // Failure reasons are not surfaced to the caller; distinguishing "expired"
  // from "wrong client" from "bad signature" is an oracle.
  let claims;
  let callerClass;
  try {
    claims = await machineVerifier.verify(token);
    callerClass = "machine";
  } catch {
    try {
      claims = await humanVerifier.verify(token);
      callerClass = "human";
    } catch {
      throw new Error("Unauthorized");
    }
  }

  // Revocation before authorization. A revoked token should not reach a scope
  // check, an entitlement lookup, or a log line describing what it asked for.
  let revoked;
  try {
    revoked = await isRevoked(claims.origin_jti, claims.sub);
  } catch {
    // Fail closed. See isRevoked.
    revoked = true;
  }
  if (revoked) {
    return policy("Deny", methodArn, claims.sub, {});
  }

  // Audience, asserted per path rather than left to the verifier alone. The
  // verifier already enforces this for the human path; repeating it here makes
  // the asymmetry explicit and catches a future change that moves a client
  // between paths without moving its validation rule.
  if (callerClass === "human" && claims.aud !== API_RESOURCE) {
    return policy("Deny", methodArn, claims.sub, {});
  }
  if (callerClass === "machine" && claims.aud) {
    // A machine token should have no aud. One that does was not issued by the
    // client_credentials grant this path expects.
    return policy("Deny", methodArn, claims.sub, {});
  }

  // Scope. Either the resource-bound or the bare form satisfies the route.
  const granted = typeof claims.scope === "string" ? claims.scope.split(" ") : [];
  if (!acceptedScopes.some((s) => granted.includes(s))) {
    return policy("Deny", methodArn, claims.sub, {});
  }

  // Access tokens: client_id. Already validated by the verifier against the
  // permitted client list — read here only to key the entitlement lookup.
  const clientId = claims.client_id;
  if (!clientId) {
    return policy("Deny", methodArn, claims.sub, {});
  }

  const { tenantId, delegated } = await resolveTenant(clientId, claims["custom:tenant"]);
  if (!tenantId) {
    return policy("Deny", methodArn, claims.sub, {});
  }

  // API Gateway populates this context; a caller cannot influence it. Downstream
  // reads these values, never raw request headers. All values must be strings —
  // API Gateway silently drops non-string context entries.
  return policy("Allow", methodArn, claims.sub, {
    sub: String(claims.sub),
    clientId: String(clientId),
    tenantId: String(tenantId),
    callerClass,
    scopes: granted.join(" "),
    // Lets the adapter emit a distinct audit event when a caller acts for a
    // tenant other than its own.
    delegated: String(delegated),
    // Carried through so a containment runbook can revoke the exact token that
    // was seen misbehaving, not just the subject.
    originJti: String(claims.origin_jti),
    // Empty on the machine path by construction. Present in the access log so
    // an audit can distinguish a resource-bound token from an unbound one.
    audience: String(claims.aud ?? ""),
  });
};
