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
import java.util.concurrent.atomic.AtomicInteger;

final class PlatformConformance {
    private static final String LIFECYCLE_RESPONSE = "lifecycle-response";
    private static final String PROVISION_KEY = "provision";
    private static final String SERVICE_DID_FIELD = "service_did";
    private static final String VERIFY = "verify";
    private static final Instant NOW = Instant.parse("2026-07-06T12:00:00Z");
    private static final String PRINCIPAL = "stable-principal-123";
    private static final String SERVICE_DID = "did:web:api.service.example";

    private PlatformConformance() {}

    static boolean evaluate(AdapterRequest request) {
        return switch (request.vector().id()) {
            case "authorization-required" -> authorization();
            case "discovery" -> discovery(request);
            case "idempotency-replay-conflict" -> idempotency();
            case "lifecycle-request", "lifecycle-response" -> lifecycle(request);
            case "list-response" -> list(request);
            case "provision-request", "provision-response" -> provision(request);
            case "provision-response-distinct-services" -> distinctServices(request);
            case "sign-request", "sign-response" -> sign(request);
            case "sign-response-pending" -> pendingSign(request);
            case "verification-authenticate-missing-resource" -> missingResource(request);
            case "verification-request" -> verificationRequest(request);
            case "verification-response-recognized" -> recognizedVerification();
            case "verification-response-unrecognized" -> unrecognizedVerification();
            default -> throw ConformanceSupport.unmapped(request);
        };
    }

    private static boolean authorization() {
        if (!missingAuthorizerRejected()) return false;
        Fixture denied = fixture(false, true, null);
        PlatformResponse<?> result = denied.platform()
                .provision(new PlatformProvisionRequest(SERVICE_DID), denied.context(PROVISION_KEY))
                .toCompletableFuture()
                .join();
        return result.status() == 404
                && "not_recognized".equals(result.problem().code());
    }

    private static boolean discovery(AdapterRequest request) {
        PlatformResponse<PlatformDiscoveryDocument> response =
                fixture(true, true, null).platform().discovery();
        return response.status() == 200
                && ConformanceSupport.jsonEquals(
                        response.body(), request.testCase().expected());
    }

    private static boolean idempotency() {
        Fixture fixture = fixture(true, true, null);
        PlatformRequestContext context = fixture.context("shared");
        PlatformResponse<?> first = fixture.platform()
                .provision(new PlatformProvisionRequest(SERVICE_DID), context)
                .toCompletableFuture()
                .join();
        PlatformResponse<?> replay = fixture.platform()
                .provision(new PlatformProvisionRequest(SERVICE_DID), context)
                .toCompletableFuture()
                .join();
        PlatformResponse<?> conflict = fixture.platform()
                .provision(new PlatformProvisionRequest("did:web:other.example"), context)
                .toCompletableFuture()
                .join();
        return ConformanceSupport.jsonEquals(first.body(), ConformanceSupport.json(AepJson.write(replay.body())))
                && conflict.status() == 409
                && "idempotency_conflict".equals(conflict.problem().code());
    }

    private static boolean lifecycle(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        ManagedAgentStatus status = request.testCase().input().has("status")
                ? ManagedAgentStatus.fromValue(
                        ConformanceSupport.text(request.testCase().input(), "status"))
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
                ManagedAgentStatus.fromValue(ConformanceSupport.text(queryNode, "status")));
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
        String firstDid = request.testCase()
                .input()
                .get("first_request")
                .get(SERVICE_DID_FIELD)
                .asText();
        String secondDid = request.testCase()
                .input()
                .get("second_request")
                .get(SERVICE_DID_FIELD)
                .asText();
        PlatformAgentIdentity first = provision(fixture, firstDid, "first");
        fixture.advanceMinute();
        PlatformAgentIdentity second = provision(fixture, secondDid, "second");
        return !first.agentDid().equals(second.agentDid())
                && ConformanceSupport.jsonEquals(
                        first, request.testCase().expected().get("first_response"))
                && ConformanceSupport.jsonEquals(
                        second, request.testCase().expected().get("second_response"));
    }

    private static boolean sign(AdapterRequest request) {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest signRequest = "sign-request".equals(request.vector().id())
                ? AepJson.parsePlatformSignRequest(request.testCase().input().toString())
                : new PlatformSignRequest(
                        "01J0AEPASSERTION0000000001", "300", AssertionOperation.ENROLL, null, null, SERVICE_DID);
        PlatformResponse<PlatformSignResponses.Response> response = fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context("sign"))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && response.body() instanceof PlatformSignResponses.Completed completed
                && !completed.clientAssertion().isBlank()
                && signRequest.jwtId().equals(completed.jwtId());
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
                ConformanceSupport.text(input, "client_assertion"),
                AssertionOperation.fromValue(ConformanceSupport.text(input, "op")),
                null,
                ConformanceSupport.text(input, "service_did"));
        var response = fixture(true, true, null)
                .platform()
                .verify(verification, new PlatformRequestContext(PRINCIPAL, VERIFY))
                .toCompletableFuture()
                .join();
        return response.status() == 400;
    }

    private static boolean verificationRequest(AdapterRequest request) {
        PlatformVerificationRequest input = AepJson.parsePlatformVerificationRequest(
                request.testCase().input().toString());
        Fixture fixture = fixture(true, true, null);
        var response = fixture.platform()
                .verify(input, fixture.context(VERIFY))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && !response.body().verified()
                && "not_recognized".equals(response.body().reason());
    }

    private static boolean recognizedVerification() {
        Fixture fixture = fixture(true, true, null);
        PlatformAgentIdentity identity = provision(fixture, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest signRequest =
                new PlatformSignRequest("verification", null, AssertionOperation.ENROLL, null, null, SERVICE_DID);
        var signed = (PlatformSignResponses.Completed) fixture.platform()
                .sign(identity.agentIdentityId(), signRequest, fixture.context("sign"))
                .toCompletableFuture()
                .join()
                .body();
        var verified = fixture.platform()
                .verify(
                        new PlatformVerificationRequest(
                                signed.clientAssertion(), AssertionOperation.ENROLL, null, SERVICE_DID),
                        fixture.context(VERIFY))
                .toCompletableFuture()
                .join();
        return verified.status() == 200
                && verified.body().verified()
                && identity.agentIdentityId().equals(verified.body().agentIdentityId());
    }

    private static boolean unrecognizedVerification() {
        Fixture fixture = fixture(true, true, null);
        var response = fixture.platform()
                .verify(
                        new PlatformVerificationRequest("invalid", AssertionOperation.ENROLL, null, SERVICE_DID),
                        fixture.context(VERIFY))
                .toCompletableFuture()
                .join();
        return response.status() == 200
                && !response.body().verified()
                && "not_recognized".equals(response.body().reason());
    }

    private static PlatformAgentIdentity provision(Fixture fixture, String serviceDid, String key) {
        return fixture.platform()
                .provision(new PlatformProvisionRequest(serviceDid), fixture.context(key))
                .toCompletableFuture()
                .join()
                .body();
    }

    private static Fixture fixture(boolean authorized, boolean hostedVerification, PlatformSignHandler handler) {
        try {
            ConformanceKeyStore keys = new ConformanceKeyStore();
            AtomicInteger identity = new AtomicInteger();
            AtomicInteger did = new AtomicInteger();
            MutableClock clock = new MutableClock(NOW);
            AepPlatform.Builder builder = AepPlatform.builder(
                            discovery(hostedVerification),
                            "p.example",
                            (request, context) -> completed(authorized),
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
            return new Fixture(builder.build(), clock);
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
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));
    }

    private static <T> CompletableFuture<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private record Fixture(AepPlatform platform, MutableClock clock) {
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

        ConformanceKeyStore() throws JOSEException {
            key = new ECKeyGenerator(Curve.P_256).keyID("platform-key").generate();
        }

        @Override
        public CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context) {
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
            return completed(ClientAssertions.sign(claims, key, identity.keyId()));
        }

        @Override
        public CompletionStage<JWK> verificationKey(PlatformIdentityRecord identity, PlatformRequestContext context) {
            return completed(key.toPublicJWK());
        }
    }
}
