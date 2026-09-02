package foundation.aep.platform;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertionVerification;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.core.PlatformVerificationRequest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class AepPlatformTest {
    private static final Instant NOW = Instant.parse("2026-07-06T12:00:00Z");
    private static final String SERVICE_DID = "did:web:api.service.example";

    @Test
    void provisionsDistinctServiceScopedIdentitiesWithSafeReplay() throws JOSEException {
        TestKeyStore keys = new TestKeyStore();
        AepPlatform platform = platform(allow(), keys, false);

        PlatformResponse<?> first = provision(platform, SERVICE_DID, "provision-1");
        PlatformResponse<?> replay = provision(platform, SERVICE_DID, "provision-1");
        PlatformResponse<?> repeated = provision(platform, SERVICE_DID, "provision-2");
        PlatformResponse<?> distinct = provision(platform, "did:web:billing.service.example", "provision-3");

        var firstIdentity = (foundation.aep.core.PlatformAgentIdentity) first.body();
        var distinctIdentity = (foundation.aep.core.PlatformAgentIdentity) distinct.body();
        assertEquals(first, replay);
        assertEquals(
                firstIdentity.agentDid(), ((foundation.aep.core.PlatformAgentIdentity) repeated.body()).agentDid());
        assertNotEquals(firstIdentity.agentDid(), distinctIdentity.agentDid());
        assertEquals(2, keys.created.get());
    }

    @Test
    void listsOnlyTheAuthorizedPrincipalInDeterministicOrder() throws JOSEException {
        AepPlatform platform = platform(allow(), new TestKeyStore(), false);
        provision(platform, SERVICE_DID, "first");
        provision(platform, "did:web:billing.service.example", "second");

        var page = platform.list(
                        new PlatformIdentityListQuery(true, 1, 0, null, ManagedAgentStatus.ACTIVE), context(null))
                .toCompletableFuture()
                .join()
                .body();

        assertEquals("1", page.count());
        assertEquals("2", page.total());
        assertEquals(1, page.data().size());
        assertEquals(
                400,
                platform.list(new PlatformIdentityListQuery(false, 101, 0, null, null), context(null))
                        .toCompletableFuture()
                        .join()
                        .status());
    }

    @Test
    void authorizesPrivateOperationsAndPublishesActiveDidDocuments() throws JOSEException {
        AtomicBoolean authorized = new AtomicBoolean(true);
        PlatformAuthorizer authorizer = (request, context) -> completed(authorized.get());
        AepPlatform platform = platform(authorizer, new TestKeyStore(), false);
        var identity = (foundation.aep.core.PlatformAgentIdentity)
                provision(platform, SERVICE_DID, "provision").body();

        assertEquals(
                200,
                platform.getDidDocument(agentDidId(identity.agentDid()), context(null))
                        .toCompletableFuture()
                        .join()
                        .status());
        authorized.set(false);
        assertEquals(
                404,
                platform.getIdentity(identity.agentIdentityId(), context(null))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                404,
                platform.list(PlatformIdentityListQuery.defaults(), context(null))
                        .toCompletableFuture()
                        .join()
                        .status());
    }

    @Test
    void signsAssertionsAndEnforcesLifecycleState() throws JOSEException {
        TestKeyStore keys = new TestKeyStore();
        AepPlatform platform = platform(allow(), keys, false);
        var identity = (foundation.aep.core.PlatformAgentIdentity)
                provision(platform, SERVICE_DID, "provision").body();
        PlatformSignRequest request = new PlatformSignRequest(
                "assertion-1", "300", AssertionOperation.ENROLL, Map.of("approval", "opaque"), null, SERVICE_DID);

        var signed =
                (PlatformSignResponses.Completed) platform.sign(identity.agentIdentityId(), request, context("sign-1"))
                        .toCompletableFuture()
                        .join()
                        .body();
        ClientAssertionClaims claims = ClientAssertions.verify(
                signed.clientAssertion(),
                keys.key.toPublicJWK(),
                ClientAssertionVerification.builder(SERVICE_DID, identity.agentDid(), AssertionOperation.ENROLL)
                        .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                        .build());
        assertEquals("assertion-1", claims.jwtId());
        assertEquals("opaque", signed.platformContext().get("approval"));

        platform.updateIdentity(
                        identity.agentIdentityId(),
                        new PlatformLifecycleRequest(ManagedAgentStatus.SUSPENDED),
                        context(null))
                .toCompletableFuture()
                .join();
        assertEquals(
                403,
                platform.sign(identity.agentIdentityId(), request, context("sign-2"))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                404,
                platform.getDidDocument(agentDidId(identity.agentDid()), context(null))
                        .toCompletableFuture()
                        .join()
                        .status());
    }

    @Test
    void returnsAndReplaysPendingSigningResponses() throws JOSEException {
        PlatformSignHandler handler = (identity, request, context) -> completed(Optional.of(new PlatformResponse<>(
                202,
                foundation.aep.core.Aep.MEDIA_TYPE,
                new PlatformSignResponses.Pending("pending", Map.of("handle", "opaque"), "5"),
                null,
                Map.of())));
        AepPlatform platform = platformBuilder(allow(), new TestKeyStore(), false)
                .signHandler(handler)
                .build();
        var identity = (foundation.aep.core.PlatformAgentIdentity)
                provision(platform, SERVICE_DID, "provision").body();
        PlatformSignRequest request =
                new PlatformSignRequest("assertion-1", null, AssertionOperation.ENROLL, null, null, SERVICE_DID);

        PlatformResponse<?> first = platform.sign(identity.agentIdentityId(), request, context("pending"))
                .toCompletableFuture()
                .join();
        PlatformResponse<?> replay = platform.sign(identity.agentIdentityId(), request, context("pending"))
                .toCompletableFuture()
                .join();

        assertEquals(202, first.status());
        assertEquals(first, replay);
    }

    @Test
    void verifiesHostedAssertionsOnceWithoutDisclosure() throws JOSEException {
        TestKeyStore keys = new TestKeyStore();
        AepPlatform platform = platform(allow(), keys, true);
        var identity = (foundation.aep.core.PlatformAgentIdentity)
                provision(platform, SERVICE_DID, "provision").body();
        PlatformSignRequest signRequest =
                new PlatformSignRequest("assertion-1", null, AssertionOperation.ENROLL, null, null, SERVICE_DID);
        var signed = (PlatformSignResponses.Completed)
                platform.sign(identity.agentIdentityId(), signRequest, context("sign"))
                        .toCompletableFuture()
                        .join()
                        .body();
        PlatformVerificationRequest request =
                new PlatformVerificationRequest(signed.clientAssertion(), AssertionOperation.ENROLL, null, SERVICE_DID);

        var verified = platform.verify(request, context("verify-1"))
                .toCompletableFuture()
                .join()
                .body();
        var replayed = platform.verify(request, context("verify-2"))
                .toCompletableFuture()
                .join()
                .body();

        assertTrue(verified.verified());
        assertFalse(replayed.verified());
        assertEquals("not_recognized", replayed.reason());
        assertEquals(null, replayed.agentDid());
    }

    @Test
    void returnsIdempotencyConflictForChangedMaterial() throws JOSEException {
        AepPlatform platform = platform(allow(), new TestKeyStore(), false);
        provision(platform, SERVICE_DID, "same");

        assertEquals(409, provision(platform, "did:web:other.example", "same").status());
    }

    @Test
    void rejectsUnauthorizedProvisioningBeforeCreatingKeyMaterial() throws JOSEException {
        TestKeyStore keys = new TestKeyStore();
        AepPlatform platform = platform((request, context) -> completed(false), keys, false);

        assertEquals(404, provision(platform, SERVICE_DID, "denied").status());
        assertEquals(0, keys.created.get());
    }

    @Test
    void validatesCustomSigningResponses() throws JOSEException {
        TestKeyStore keys = new TestKeyStore();
        AepPlatform problemPlatform = platformBuilder(allow(), keys, false)
                .signHandler((identity, request, context) -> completed(Optional.of(new PlatformResponse<>(
                        503,
                        foundation.aep.core.Aep.PROBLEM_MEDIA_TYPE,
                        null,
                        foundation.aep.core.ProblemDetails.of("temporarily_unavailable", "Try later.", 503),
                        Map.of()))))
                .build();
        var identity = (foundation.aep.core.PlatformAgentIdentity)
                provision(problemPlatform, SERVICE_DID, "provision").body();
        PlatformSignRequest request =
                new PlatformSignRequest("assertion-1", null, AssertionOperation.ENROLL, null, null, SERVICE_DID);

        assertEquals(
                503,
                problemPlatform
                        .sign(identity.agentIdentityId(), request, context("sign"))
                        .toCompletableFuture()
                        .join()
                        .status());

        AepPlatform invalidPlatform = platformBuilder(allow(), new TestKeyStore(), false)
                .signHandler((record, signRequest, requestContext) -> completed(Optional.of(new PlatformResponse<>(
                        200,
                        foundation.aep.core.Aep.MEDIA_TYPE,
                        new PlatformSignResponses.Completed(
                                "completed",
                                "did:web:wrong.example",
                                "assertion",
                                "2026-07-06T12:05:00Z",
                                "2026-07-06T12:00:00Z",
                                signRequest.jwtId(),
                                null,
                                signRequest.serviceDid()),
                        null,
                        Map.of()))))
                .build();
        var invalidIdentity = (foundation.aep.core.PlatformAgentIdentity)
                provision(invalidPlatform, SERVICE_DID, "provision-invalid").body();

        assertThrows(
                CompletionException.class,
                () -> invalidPlatform
                        .sign(invalidIdentity.agentIdentityId(), request, context("sign-invalid"))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void isolatesCallerOwnedContextAndRedactsCredentials() {
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("value", "original");
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("nested", nested);

        PlatformRequestContext context = new PlatformRequestContext("secret-principal", "secret-key", NOW, values);
        nested.put("value", "changed");
        values.put("other", true);

        assertEquals("original", ((Map<?, ?>) context.values().get("nested")).get("value"));
        assertFalse(context.values().containsKey("other"));
        assertFalse(context.toString().contains("secret-principal"));
        assertFalse(context.toString().contains("secret-key"));
    }

    @Test
    void coalescesConcurrentIdentityCreationWithoutPropagatingCallerCancellation() {
        PlatformIdentityStore store = PlatformIdentityStore.inMemory();
        CompletableFuture<PlatformIdentityRecord> creation = new CompletableFuture<>();
        AtomicInteger calls = new AtomicInteger();
        PlatformIdentityRecord identity = identityRecord();

        CompletableFuture<PlatformIdentitySelection> cancelled = store.findOrCreate("principal", SERVICE_DID, () -> {
                    calls.incrementAndGet();
                    return creation;
                })
                .toCompletableFuture();
        CompletableFuture<PlatformIdentitySelection> waiting = store.findOrCreate("principal", SERVICE_DID, () -> {
                    calls.incrementAndGet();
                    return creation;
                })
                .toCompletableFuture();

        cancelled.cancel(true);
        creation.complete(identity);

        assertEquals(1, calls.get());
        assertEquals(identity, waiting.join().identity());
        assertEquals(
                0,
                store.list("principal", new PlatformIdentityListQuery(false, 1, Integer.MAX_VALUE, null, null))
                        .toCompletableFuture()
                        .join()
                        .identities()
                        .size());
    }

    private static PlatformResponse<?> provision(AepPlatform platform, String serviceDid, String key) {
        return platform.provision(new PlatformProvisionRequest(serviceDid), context(key))
                .toCompletableFuture()
                .join();
    }

    private static AepPlatform platform(
            PlatformAuthorizer authorizer, TestKeyStore keyStore, boolean hostedVerification) {
        return platformBuilder(authorizer, keyStore, hostedVerification).build();
    }

    private static AepPlatform.Builder platformBuilder(
            PlatformAuthorizer authorizer, TestKeyStore keyStore, boolean hostedVerification) {
        AtomicInteger identity = new AtomicInteger();
        AtomicInteger did = new AtomicInteger();
        return AepPlatform.builder(discovery(hostedVerification), "p.example", authorizer, keyStore, resolve())
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identityIdSupplier(() -> Integer.toString(identity.incrementAndGet()))
                .agentDidIdSupplier(() -> "opaque" + did.incrementAndGet())
                .replayStore(PlatformReplayStore.inMemory());
    }

    private static PlatformDiscoveryDocument discovery(boolean hostedVerification) {
        return new PlatformDiscoveryDocument(
                "1.0",
                new PlatformDiscoveryDocument.Endpoints(
                        hostedVerification ? "/v1/aep/verifications" : null,
                        "/v1/aep/agent-identities/{agent_identity_id}",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep"),
                new PlatformDiscoveryDocument.Identity(
                        List.of("did:web"), "https://p.example/a/{agent_did_id}/did.json"),
                new PlatformDiscoveryDocument.Platform("did:web:p.example", hostedVerification, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));
    }

    private static PlatformAuthorizer allow() {
        return (request, context) -> completed(true);
    }

    private static PlatformServiceDidResolver resolve() {
        return (serviceDid, context) -> completed(true);
    }

    private static PlatformRequestContext context(String key) {
        return new PlatformRequestContext("principal-1", key, NOW, Map.of());
    }

    private static String agentDidId(String agentDid) {
        return agentDid.substring(agentDid.lastIndexOf(':') + 1);
    }

    private static PlatformIdentityRecord identityRecord() {
        return PlatformIdentityRecord.builder()
                .agentDid("did:web:p.example:agents:opaque")
                .agentDidId("opaque")
                .agentIdentityId("pai_identity")
                .createdAt(NOW)
                .didDocumentUrl("https://p.example/a/opaque/did.json")
                .keyId("did:web:p.example:agents:opaque")
                .principal("principal")
                .serviceDid(SERVICE_DID)
                .signingAlgorithms(List.of("ES256"))
                .status(ManagedAgentStatus.ACTIVE)
                .updatedAt(NOW)
                .build();
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private static final class TestKeyStore implements PlatformKeyStore {
        private final ECKey key;
        private final AtomicInteger created = new AtomicInteger();

        TestKeyStore() throws JOSEException {
            key = new ECKeyGenerator(Curve.P_256).keyID("platform-key").generate();
        }

        @Override
        public CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context) {
            created.incrementAndGet();
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
