package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import foundation.aep.core.Aep;
import foundation.aep.core.AepJson;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.core.PlatformVerificationRequest;
import foundation.aep.platform.AepPlatform;
import foundation.aep.platform.PlatformDidVerificationMethod;
import foundation.aep.platform.PlatformIdentityListQuery;
import foundation.aep.platform.PlatformIdentityRecord;
import foundation.aep.platform.PlatformKeyStore;
import foundation.aep.platform.PlatformReplayStore;
import foundation.aep.platform.PlatformRequestContext;
import foundation.aep.platform.PlatformResponse;
import foundation.aep.platform.PlatformSignHandler;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

final class PlatformConformance {
    private static final String LIFETIME_SECONDS = "300";
    private static final String STATUS_FIELD = "status";
    private static final String CLIENT_ASSERTION = "client_assertion";
    private static final String LIFECYCLE_RESPONSE = "lifecycle-response";
    private static final String PROVISION_KEY = "provision";
    private static final String SERVICE_DID_FIELD = "service_did";
    private static final String VERIFY = "verify";
    private static final String SIGN_OPERATION = "sign";
    private static final String ASSERTION_ID = "01J0AEPASSERTION0000000001";
    private static final String IDEMPOTENCY_KEY_HEADER = "idempotency_key_header";
    private static final Instant NOW = Instant.parse("2026-07-06T12:00:00Z");
    private static final String PRINCIPAL = "stable-principal-123";
    private static final String SERVICE_DID = "did:web:api.service.example";

    private PlatformConformance() {}

    static boolean evaluate(AdapterRequest request) {
        return switch (request.vector().id()) {
            case "authorization-required" -> authorization(request);
            case "discovery" -> discovery(request);
            case "idempotency-replay-conflict" -> idempotency(request);
            case "lifecycle-request", "lifecycle-response" -> lifecycle(request);
            case "list-response" -> list(request);
            case "provision-request", "provision-response" -> provision(request);
            case "provision-response-distinct-services" -> distinctServices(request);
            case "sign-request", "sign-response" -> sign(request);
            case "sign-response-pending" -> pendingSign(request);
            case "verification-authenticate-missing-resource" -> missingResource(request);
            case "verification-request" -> verificationRequest(request);
            case "verification-response-recognized" -> recognizedVerification(request);
            case "verification-response-unrecognized" -> unrecognizedVerification(request);
            default -> throw ConformanceSupport.unmapped(request);
        };
    }

    private static boolean authorization(AdapterRequest vector) {
        if (!missingAuthorizerRejected()) return false;
        JsonNode expected = vector.testCase().expected();
        Fixture fixture = fixture(true, true, null);
        var identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        var sign = new PlatformSignRequest(
                ASSERTION_ID, LIFETIME_SECONDS, AssertionOperation.ENROLL, null, null, SERVICE_DID);
        var signed = fixture.platform()
                .sign(identity.agentIdentityId(), sign, fixture.context("signed"))
                .toCompletableFuture()
                .join()
                .body();
        if (!(signed instanceof PlatformSignResponses.Completed completed)) return false;
        var verification = new PlatformVerificationRequest(
                completed.clientAssertion(), AssertionOperation.ENROLL, null, SERVICE_DID);
        fixture.authorized().set(false);
        int effects = fixture.keys().effects.get();
        for (String operation : ConformanceSupport.strings(vector.testCase().input(), "private_operations")) {
            int decisions = fixture.decisions().get();
            PlatformResponse<?> denied =
                    switch (operation) {
                        case "get-identity" ->
                            fixture.platform()
                                    .getIdentity(identity.agentIdentityId(), fixture.context("get"))
                                    .toCompletableFuture()
                                    .join();
                        case "list-identities" ->
                            fixture.platform()
                                    .list(PlatformIdentityListQuery.defaults(), fixture.context("list"))
                                    .toCompletableFuture()
                                    .join();
                        case "provision-identity" ->
                            fixture.platform()
                                    .provision(
                                            new PlatformProvisionRequest(SERVICE_DID), fixture.context(PROVISION_KEY))
                                    .toCompletableFuture()
                                    .join();
                        case SIGN_OPERATION ->
                            fixture.platform()
                                    .sign(identity.agentIdentityId(), sign, fixture.context("signed"))
                                    .toCompletableFuture()
                                    .join();
                        case "update-identity" ->
                            fixture.platform()
                                    .updateIdentity(
                                            identity.agentIdentityId(),
                                            new PlatformLifecycleRequest(ManagedAgentStatus.SUSPENDED),
                                            fixture.context("update"))
                                    .toCompletableFuture()
                                    .join();
                        case "verify" ->
                            fixture.platform()
                                    .verify(verification, fixture.context(VERIFY))
                                    .toCompletableFuture()
                                    .join();
                        default -> throw new IllegalArgumentException("Unknown private operation: " + operation);
                    };
            if (fixture.decisions().get() <= decisions) return false;
            if (VERIFY.equals(operation)) {
                JsonNode body = ConformanceSupport.json(AepJson.write(denied.body()));
                if (denied.status() != 200
                        || body.path("verified").asBoolean()
                                != expected.path("verification_denied")
                                        .path("verified")
                                        .asBoolean()
                        || !body.path("reason")
                                .equals(expected.path("verification_denied").path("reason"))) return false;
            } else if (denied.status()
                            != expected.path("management_denied_status").asInt()
                    || denied.problem() == null
                    || !denied.problem().code().equals(ConformanceSupport.text(expected, "management_denied_code")))
                return false;
        }
        var publicDid = fixture.platform()
                .getDidDocument("4Yf7p2xQd9", new PlatformRequestContext(null, null))
                .toCompletableFuture()
                .join();
        fixture.authorized().set(true);
        var unchanged = fixture.platform()
                .getIdentity(identity.agentIdentityId(), fixture.context("read"))
                .toCompletableFuture()
                .join();
        return publicDid.status() == 200
                && expected.path("did_document_public").asBoolean()
                && !expected.path("side_effects").asBoolean()
                && fixture.keys().effects.get() == effects
                && ConformanceSupport.jsonEquals(unchanged.body(), ConformanceSupport.json(AepJson.write(identity)))
                && "construction-error".equals(ConformanceSupport.text(expected, "missing_authorizer"));
    }

    private static boolean discovery(AdapterRequest request) {
        PlatformResponse<PlatformDiscoveryDocument> response =
                fixture(true, true, null).platform().discovery();
        return response.status() == 200
                && ConformanceSupport.jsonEquals(
                        response.body(), request.testCase().expected());
    }

    // Each operation in input.operations is replayed under one key and then retried with changed
    // material, which must answer the conflict status and code expected names.
    private static boolean idempotency(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        JsonNode expected = request.testCase().expected();
        int conflictStatus = ConformanceSupport.required(expected, "changed_input_or_operation_status")
                .asInt();
        String conflictCode = ConformanceSupport.text(expected, "changed_input_or_operation_code");
        String signKey = ConformanceSupport.text(input, "initial_sign_key");
        for (JsonNode operation : ConformanceSupport.required(input, "operations")) {
            if (!replays(operation.asText(), signKey, conflictStatus, conflictCode)) return false;
        }
        return "stored_http_result".equals(ConformanceSupport.text(expected, "exact_replay"))
                && retains(Long.parseLong(ConformanceSupport.text(expected, "retention_seconds_minimum")));
    }

    /**
     * expected.retention_seconds_minimum is how long a recorded result must stay replayable. A store
     * that forgot the key earlier would provision a second identity under it instead of returning
     * the first, which is exactly the duplicate the key exists to prevent.
     */
    private static boolean retains(long seconds) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest signRequest = new PlatformSignRequest(
                ASSERTION_ID, LIFETIME_SECONDS, AssertionOperation.ENROLL, null, null, SERVICE_DID);
        // Signing is used rather than provisioning because a second provision for the same principal
        // and Service returns the same identity whether or not the key was remembered, so it could
        // not tell a retained result from a fresh one. A forgotten sign key mints a new assertion.
        PlatformResponse<?> recorded = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context("retained"))
                .toCompletableFuture()
                .join();
        fixture.advanceSeconds(seconds - 1);
        PlatformResponse<?> replay = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context("retained"))
                .toCompletableFuture()
                .join();
        return recorded.status() == replay.status()
                && ConformanceSupport.json(AepJson.write(recorded.body()))
                        .equals(ConformanceSupport.json(AepJson.write(replay.body())));
    }

    /** Runs one replayable operation twice with one key, then once more with changed material. */
    private static boolean replays(String operation, String signKey, int conflictStatus, String conflictCode) {
        Fixture fixture = fixture(true, true, null);
        PlatformResponse<?> first;
        PlatformResponse<?> replay;
        PlatformResponse<?> conflict;
        switch (operation) {
            case "provision" -> {
                PlatformRequestContext context = fixture.context("shared");
                first = fixture.platform()
                        .provision(new PlatformProvisionRequest(SERVICE_DID), context)
                        .toCompletableFuture()
                        .join();
                replay = fixture.platform()
                        .provision(new PlatformProvisionRequest(SERVICE_DID), context)
                        .toCompletableFuture()
                        .join();
                conflict = fixture.platform()
                        .provision(new PlatformProvisionRequest("did:web:other.example"), context)
                        .toCompletableFuture()
                        .join();
            }
            case SIGN_OPERATION -> {
                PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
                PlatformRequestContext context = fixture.context(signKey);
                PlatformSignRequest signRequest = new PlatformSignRequest(
                        ASSERTION_ID, LIFETIME_SECONDS, AssertionOperation.ENROLL, null, null, SERVICE_DID);
                first = fixture.platform()
                        .sign(identity.agentIdentityId(), signRequest, context)
                        .toCompletableFuture()
                        .join();
                replay = fixture.platform()
                        .sign(identity.agentIdentityId(), signRequest, context)
                        .toCompletableFuture()
                        .join();
                conflict = fixture.platform()
                        .sign(
                                identity.agentIdentityId(),
                                new PlatformSignRequest(
                                        "01J0AEPASSERTION0000000002",
                                        LIFETIME_SECONDS,
                                        AssertionOperation.ENROLL,
                                        null,
                                        null,
                                        SERVICE_DID),
                                context)
                        .toCompletableFuture()
                        .join();
            }
            case "hosted_verification" -> {
                PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
                var response = fixture.platform()
                        .sign(
                                identity.agentIdentityId(),
                                new PlatformSignRequest(
                                        ASSERTION_ID,
                                        LIFETIME_SECONDS,
                                        AssertionOperation.ENROLL,
                                        null,
                                        null,
                                        SERVICE_DID),
                                fixture.context(signKey))
                        .toCompletableFuture()
                        .join();
                if (!(response.body() instanceof PlatformSignResponses.Completed signed)) return false;
                PlatformRequestContext context = fixture.context(VERIFY);
                PlatformVerificationRequest verification = new PlatformVerificationRequest(
                        signed.clientAssertion(), AssertionOperation.ENROLL, null, SERVICE_DID);
                first = fixture.platform()
                        .verify(verification, context)
                        .toCompletableFuture()
                        .join();
                replay = fixture.platform()
                        .verify(verification, context)
                        .toCompletableFuture()
                        .join();
                conflict = fixture.platform()
                        .verify(
                                new PlatformVerificationRequest(
                                        signed.clientAssertion(), AssertionOperation.STATUS, null, SERVICE_DID),
                                context)
                        .toCompletableFuture()
                        .join();
            }
            default -> throw new IllegalArgumentException("Unknown replayable operation: " + operation);
        }
        return ConformanceSupport.jsonEquals(first.body(), ConformanceSupport.json(AepJson.write(replay.body())))
                && conflict.status() == conflictStatus
                && conflictCode.equals(conflict.problem().code());
    }

    private static boolean lifecycle(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        ManagedAgentStatus status = request.testCase().input().has(STATUS_FIELD)
                ? ManagedAgentStatus.fromValue(
                        ConformanceSupport.text(request.testCase().input(), STATUS_FIELD))
                : ManagedAgentStatus.SUSPENDED;
        if (LIFECYCLE_RESPONSE.equals(request.vector().id())) fixture.advanceSeconds(600);
        PlatformResponse<PlatformAgentIdentity> response = fixture.platform()
                .updateIdentity(identity.agentIdentityId(), new PlatformLifecycleRequest(status), fixture.context(null))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && ("lifecycle-request".equals(request.vector().id())
                        ? response.body().status() == status
                        : ConformanceSupport.jsonEquals(
                                response.body(), request.testCase().expected()));
    }

    private static boolean list(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        provision(fixture, SERVICE_DID, PROVISION_KEY);
        var queryNode = ConformanceSupport.required(request.testCase().input(), "query");
        PlatformIdentityListQuery query = new PlatformIdentityListQuery(
                ConformanceSupport.required(queryNode, "descending").asBoolean(),
                ConformanceSupport.required(queryNode, "limit").asInt(),
                ConformanceSupport.required(queryNode, "offset").asInt(),
                ConformanceSupport.text(queryNode, SERVICE_DID_FIELD),
                ManagedAgentStatus.fromValue(ConformanceSupport.text(queryNode, STATUS_FIELD)));
        var response = fixture.platform()
                .list(query, fixture.context(null))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && ConformanceSupport.jsonEquals(
                        response.body(), request.testCase().expected());
    }

    private static boolean provision(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        String serviceDid = request.testCase().input().has(SERVICE_DID_FIELD)
                ? ConformanceSupport.text(request.testCase().input(), SERVICE_DID_FIELD)
                : SERVICE_DID;
        PlatformAgentIdentity identity = provision(fixture, serviceDid, "01J0AEPPLATFORM000000000001");
        return "provision-request".equals(request.vector().id())
                ? identity.serviceDid().equals(serviceDid)
                : ConformanceSupport.jsonEquals(identity, request.testCase().expected());
    }

    private static boolean distinctServices(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        String firstDid = ConformanceSupport.text(
                ConformanceSupport.required(request.testCase().input(), "first_request"), SERVICE_DID_FIELD);
        String secondDid = ConformanceSupport.text(
                ConformanceSupport.required(request.testCase().input(), "second_request"), SERVICE_DID_FIELD);
        PlatformAgentIdentity first = provision(fixture, firstDid, "first");
        fixture.advanceMinute();
        PlatformAgentIdentity second = provision(fixture, secondDid, "second");
        return !first.agentDid().equals(second.agentDid())
                && ConformanceSupport.jsonEquals(
                        first, request.testCase().expected().get("first_response"))
                && ConformanceSupport.jsonEquals(
                        second, request.testCase().expected().get("second_response"));
    }

    /**
     * sign-request is about the request contract: PLT-SIGN_OPERATION-002 makes the Idempotency-Key header
     * mandatory and PLT-IDP-005 makes an exact retry replay the stored result. sign-response is
     * about the body, which is compared member by member against the one the vector publishes.
     */
    private static boolean sign(AdapterRequest request) {
        boolean requestVector = "sign-request".equals(request.vector().id());
        PlatformSignRequest signRequest = requestVector
                ? AepJson.parsePlatformSignRequest(request.testCase().input().toString())
                : signRequestFor(request.testCase().expected());
        if (requestVector) {
            String key = ConformanceSupport.text(request.testCase().expected(), IDEMPOTENCY_KEY_HEADER);
            return signRequiresAKey(signRequest) && signReplays(signRequest, key);
        }
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformResponse<PlatformSignResponses.Response> response = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context(SIGN_OPERATION))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && response.body() instanceof PlatformSignResponses.Completed completed
                && matchesExpectedAssertion(completed, request.testCase().expected());
    }

    /** Rebuilds the request that produces the response the vector publishes. */
    private static PlatformSignRequest signRequestFor(JsonNode expected) {
        JsonNode context = expected.get("platform_context");
        return new PlatformSignRequest(
                ConformanceSupport.text(expected, "jti"),
                LIFETIME_SECONDS,
                AssertionOperation.ENROLL,
                context == null ? null : AepJson.parseObject(context.toString(), "platform_context"),
                null,
                ConformanceSupport.text(expected, SERVICE_DID_FIELD));
    }

    /**
     * Every member of the expected body is compared except client_assertion.
     *
     * That one is excluded because the token the vector publishes is illustrative and does not agree
     * with the response it sits in: its `aud` is did:web:s.example where the body's service_did is
     * did:web:api.service.example, and its iat/exp fall on 2026-07-07 where the body's issued_at and
     * expires_at are 2026-07-06. PLT-SIGN_OPERATION-020 and PLT-SIGN_OPERATION-021 require the minted assertion to agree
     * with the response carrying it, which is what {@link #boundToItsResponse} checks instead.
     */
    private static boolean matchesExpectedAssertion(PlatformSignResponses.Completed completed, JsonNode expected) {
        com.fasterxml.jackson.databind.node.ObjectNode actual = (com.fasterxml.jackson.databind.node.ObjectNode)
                ConformanceSupport.json(AepJson.write(completed)).deepCopy();
        com.fasterxml.jackson.databind.node.ObjectNode published =
                (com.fasterxml.jackson.databind.node.ObjectNode) expected.deepCopy();
        String minted = ConformanceSupport.text(actual, CLIENT_ASSERTION);
        actual.remove(CLIENT_ASSERTION);
        published.remove(CLIENT_ASSERTION);
        return actual.equals(published) && boundToItsResponse(minted, completed);
    }

    /** PLT-SIGN_OPERATION-021: iss and sub are the Agent DID, aud is the Service DID the response names. */
    private static boolean boundToItsResponse(String minted, PlatformSignResponses.Completed completed) {
        ClientAssertionClaims claims = ClientAssertions.decodeUnverified(minted);
        return claims.issuer().equals(completed.agentDid())
                && claims.subject().equals(completed.agentDid())
                && claims.audience().equals(completed.serviceDid())
                && claims.jwtId().equals(completed.jwtId())
                && Instant.ofEpochSecond(claims.issuedAt()).equals(Instant.parse(completed.issuedAt()))
                && Instant.ofEpochSecond(claims.expiresAt()).equals(Instant.parse(completed.expiresAt()));
    }

    private static boolean signRequiresAKey(PlatformSignRequest signRequest) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        var refused = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, new PlatformRequestContext(PRINCIPAL, null))
                .toCompletableFuture()
                .join();
        return refused.status() == 400;
    }

    private static boolean signReplays(PlatformSignRequest signRequest, String key) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformRequestContext context = fixture.context(key);
        var first = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, context)
                .toCompletableFuture()
                .join();
        var replay = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, context)
                .toCompletableFuture()
                .join();
        return first.status() == 200
                && ConformanceSupport.jsonEquals(first.body(), ConformanceSupport.json(AepJson.write(replay.body())));
    }

    private static boolean pendingSign(AdapterRequest request) {
        PlatformSignHandler handler = (identity, signRequest, context) -> completed(Optional.of(new PlatformResponse<>(
                202,
                Aep.MEDIA_TYPE,
                new PlatformSignResponses.Pending("pending", Map.of("authorization_handle", "opaque-value"), "5"),
                null,
                Map.of())));
        Fixture fixture = fixture(true, true, handler);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest signRequest =
                new PlatformSignRequest("pending", null, AssertionOperation.ENROLL, null, null, SERVICE_DID);
        var response = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context("pending"))
                .toCompletableFuture()
                .join();
        return response.status() == 202
                && ConformanceSupport.jsonEquals(
                        response.body(), request.testCase().expected());
    }

    private static boolean missingResource(AdapterRequest request) {
        JsonNode input = ConformanceSupport.required(request.testCase().input(), "request");
        PlatformVerificationRequest verification = new PlatformVerificationRequest(
                ConformanceSupport.text(input, CLIENT_ASSERTION),
                AssertionOperation.fromValue(ConformanceSupport.text(input, "op")),
                null,
                ConformanceSupport.text(input, "service_did"));
        var response = fixture(true, true, null)
                .platform()
                .verify(verification, new PlatformRequestContext(PRINCIPAL, VERIFY))
                .toCompletableFuture()
                .join();
        // The status the Platform answers must track expected.valid, whichever polarity the vector
        // publishes.
        return !ConformanceSupport.valid(request) == (response.status() == 400);
    }

    /**
     * PLT-VER-002 makes the Idempotency-Key header mandatory on hosted verification. The request is
     * round-tripped, refused without a key, accepted with the key the vector names, and an exact
     * retry must replay the stored result.
     */
    private static boolean verificationRequest(AdapterRequest request) {
        PlatformVerificationRequest input = AepJson.parsePlatformVerificationRequest(
                request.testCase().input().toString());
        if (!ConformanceSupport.jsonEquals(input, request.testCase().input())) return false;
        String key = ConformanceSupport.text(request.testCase().expected(), IDEMPOTENCY_KEY_HEADER);
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, input.serviceDid(), PROVISION_KEY);
        var signed = fixture.platform()
                .sign(
                        identity.agentIdentityId(),
                        new PlatformSignRequest(
                                ASSERTION_ID,
                                LIFETIME_SECONDS,
                                input.operation(),
                                null,
                                input.resource(),
                                input.serviceDid()),
                        fixture.context("sign-for-verification"))
                .toCompletableFuture()
                .join()
                .body();
        if (!(signed instanceof PlatformSignResponses.Completed completed)) return false;
        input = new PlatformVerificationRequest(
                completed.clientAssertion(), input.operation(), input.resource(), input.serviceDid());
        var withoutKey = fixture.platform()
                .verify(input, new PlatformRequestContext(PRINCIPAL, null))
                .toCompletableFuture()
                .join();
        PlatformRequestContext context = fixture.context(key);
        var first =
                fixture.platform().verify(input, context).toCompletableFuture().join();
        var replay =
                fixture.platform().verify(input, context).toCompletableFuture().join();
        return withoutKey.status() == 400
                && first.status() == 200
                && first.body().verified()
                && replay.body().verified()
                && ConformanceSupport.jsonEquals(first.body(), ConformanceSupport.json(AepJson.write(replay.body())));
    }

    private static boolean recognizedVerification(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest signRequest =
                new PlatformSignRequest("verification", null, AssertionOperation.ENROLL, null, null, SERVICE_DID);
        var body = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context(SIGN_OPERATION))
                .toCompletableFuture()
                .join()
                .body();
        // A Pending body here raised a ClassCastException and was reported as an opaque failure
        // rather than as the wrong kind of response.
        if (!(body instanceof PlatformSignResponses.Completed signed)) return false;
        var verified = fixture.platform()
                .verify(
                        new PlatformVerificationRequest(
                                signed.clientAssertion(), AssertionOperation.ENROLL, null, SERVICE_DID),
                        fixture.context(VERIFY))
                .toCompletableFuture()
                .join();
        JsonNode expected = request.testCase().expected();
        return verified.status() == 200 && ConformanceSupport.jsonEquals(verified.body(), expected);
    }

    private static boolean unrecognizedVerification(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        var response = fixture.platform()
                .verify(
                        new PlatformVerificationRequest("invalid", AssertionOperation.ENROLL, null, SERVICE_DID),
                        fixture.context(VERIFY))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && ConformanceSupport.jsonEquals(
                        response.body(), request.testCase().expected());
    }

    private static PlatformAgentIdentity provision(Fixture fixture, String serviceDid, String key) {
        PlatformResponse<PlatformAgentIdentity> response = fixture.platform()
                .provision(new PlatformProvisionRequest(serviceDid), fixture.context(key))
                .toCompletableFuture()
                .join();
        if (response.status() != 200 || response.body() == null) {
            throw new IllegalArgumentException("Provisioning the conformance fixture returned " + response.status());
        }
        return response.body();
    }

    static Fixture fixture(boolean authorized, boolean hostedVerification, PlatformSignHandler handler) {
        try {
            ConformanceKeyStore keys = new ConformanceKeyStore();
            AtomicInteger identity = new AtomicInteger();
            AtomicInteger did = new AtomicInteger();
            AtomicBoolean permission = new AtomicBoolean(authorized);
            AtomicInteger decisions = new AtomicInteger();
            MutableClock clock = new MutableClock(NOW);
            AepPlatform.Builder builder = AepPlatform.builder(
                            discovery(hostedVerification),
                            "p.example",
                            (request, context) -> {
                                decisions.incrementAndGet();
                                return completed(permission.get());
                            },
                            keys,
                            (serviceDid, context) -> completed(true))
                    .clock(clock)
                    .didPathPrefix("a")
                    .identityIdSupplier(() -> List.of("01J0AEPPLATFORM000000000001", "01J0AEPPLATFORM000000000002")
                            .get(identity.getAndIncrement()))
                    .agentDidIdSupplier(
                            () -> List.of("4Yf7p2xQd9", "9Lm2r8VnQ4").get(did.getAndIncrement()));
            if (hostedVerification) builder.replayStore(PlatformReplayStore.inMemory());
            if (handler != null) builder.signHandler(handler);
            return new Fixture(builder.build(), clock, permission, decisions, keys);
        } catch (JOSEException exception) {
            throw new IllegalArgumentException("Unable to create Platform conformance key", exception);
        }
    }

    private static boolean missingAuthorizerRejected() {
        try {
            AepPlatform.builder(
                            discovery(true),
                            "p.example",
                            null,
                            new ConformanceKeyStore(),
                            (serviceDid, context) -> completed(true))
                    .replayStore(PlatformReplayStore.inMemory())
                    .build();
            return false;
        } catch (NullPointerException expected) { // NOPMD - Construction must reject a missing authorizer.
            return true;
        } catch (JOSEException exception) {
            throw new IllegalArgumentException("Unable to create Platform conformance key", exception);
        }
    }

    private static PlatformDiscoveryDocument discovery(boolean hostedVerification) {
        return new PlatformDiscoveryDocument(
                Aep.VERSION,
                new PlatformDiscoveryDocument.Endpoints(
                        hostedVerification ? "/v1/aep/verifications" : null,
                        "/v1/aep/agent-identities/{agent_identity_id}",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep"),
                new PlatformDiscoveryDocument.Identity(
                        List.of(Aep.IDENTITY_METHOD_DID_WEB), "https://p.example/a/{agent_did_id}/did.json"),
                new PlatformDiscoveryDocument.Platform("did:web:p.example", hostedVerification, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), LIFETIME_SECONDS));
    }

    private static <T> CompletableFuture<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    record Fixture(
            AepPlatform platform,
            MutableClock clock,
            AtomicBoolean authorized,
            AtomicInteger decisions,
            ConformanceKeyStore keys) {
        PlatformRequestContext context(String key) {
            return new PlatformRequestContext(PRINCIPAL, key, clock.instant(), Map.of());
        }

        void advanceMinute() {
            advanceSeconds(60);
        }

        void advanceSeconds(long seconds) {
            clock.set(clock.instant().plusSeconds(seconds));
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant value) {
            now = value;
        }

        void set(Instant value) {
            now = value;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("Only UTC is supported");
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static final class ConformanceKeyStore implements PlatformKeyStore {
        private final ECKey key;
        private final AtomicInteger effects = new AtomicInteger();

        ConformanceKeyStore() throws JOSEException {
            key = new ECKeyGenerator(Curve.P_256).keyID("platform-key").generate();
        }

        @Override
        public CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context) {
            effects.incrementAndGet();
            return completed(null);
        }

        @Override
        public CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
                PlatformIdentityRecord identity, PlatformRequestContext context) {
            return completed(new PlatformDidVerificationMethod(
                    identity.agentDid(), identity.agentDid(), key.toPublicJWK().toJSONObject(), "JsonWebKey2020"));
        }

        @Override
        public CompletionStage<String> sign(
                PlatformIdentityRecord identity, ClientAssertionClaims claims, PlatformRequestContext context) {
            effects.incrementAndGet();
            return completed(ClientAssertions.sign(claims, key, identity.keyId()));
        }

        @Override
        public CompletionStage<JWK> verificationKey(PlatformIdentityRecord identity, PlatformRequestContext context) {
            return completed(key.toPublicJWK());
        }
    }
}
