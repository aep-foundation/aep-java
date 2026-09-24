package foundation.aep.platform;

import static foundation.aep.platform.PlatformFixtures.DID_HOST;
import static foundation.aep.platform.PlatformFixtures.DID_PREFIX;
import static foundation.aep.platform.PlatformFixtures.JWT_ID;
import static foundation.aep.platform.PlatformFixtures.NOW;
import static foundation.aep.platform.PlatformFixtures.PRINCIPAL;
import static foundation.aep.platform.PlatformFixtures.PROVISION_KEY;
import static foundation.aep.platform.PlatformFixtures.SERVICE_DID;
import static foundation.aep.platform.PlatformFixtures.allow;
import static foundation.aep.platform.PlatformFixtures.builder;
import static foundation.aep.platform.PlatformFixtures.completed;
import static foundation.aep.platform.PlatformFixtures.context;
import static foundation.aep.platform.PlatformFixtures.discovery;
import static foundation.aep.platform.PlatformFixtures.platform;
import static foundation.aep.platform.PlatformFixtures.provision;
import static foundation.aep.platform.PlatformFixtures.record;
import static foundation.aep.platform.PlatformFixtures.resolver;
import static foundation.aep.platform.PlatformFixtures.signRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import foundation.aep.core.Aep;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.core.PlatformVerificationRequest;
import foundation.aep.core.ProblemDetails;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Exercises the remaining refusal, accessor, and store paths of the AEP Platform module. */
final class PlatformCoverageTest {
    private static final String AGENT_DID = "did:web:p.example:a:opaque";
    private static final String SIGN_KEY = "sign";
    private static final String BLANK = " ";
    private static final String CONTROLLER = "did:web:p.example:a:other";
    private static final String HEADER = "X-Trace";
    private static final String OTHER_SERVICE = "did:web:other.example";

    @Test
    void refusesMissingOrMalformedPathParametersAndBodies() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertEquals(404, status(platform.sign(BLANK, signRequest(null), context(SIGN_KEY))));
        assertEquals(400, status(platform.sign(identity.agentIdentityId(), null, context(SIGN_KEY))));
        assertEquals(404, status(platform.updateIdentity(null, active(), context(null))));
        assertEquals(400, status(platform.updateIdentity(identity.agentIdentityId(), null, context(null))));
        assertEquals(404, status(platform.updateIdentity("pai_missing", active(), context(null))));
        assertEquals(404, status(platform.getIdentity(null, context(null))));
        assertEquals(404, status(platform.getIdentity("pai_missing", context(null))));
        assertEquals(
                400, status(platform(allow(), new PlatformFixtures.Keys(), true).verify(null, context("verify"))));
    }

    @Test
    void refusesSigningForAServiceTheIdentityIsNotScopedTo() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest crossService = new PlatformSignRequest(
                JWT_ID, null, AssertionOperation.ENROLL, null, null, "did:web:elsewhere.example");

        assertEquals(404, status(platform.sign(identity.agentIdentityId(), crossService, context(SIGN_KEY))));
    }

    @Test
    void rejectsSignHandlerResponsesThatAreNotAValidSigningResult() throws JOSEException {
        assertEquals(200, handled(null).status(), "an absent handler result falls back to the key store");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(500, Aep.MEDIA_TYPE, null, null, Map.of())),
                "a 500 with no body is neither success nor problem");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(202, "text/plain", pending(), null, Map.of())),
                "the media type has to be application/aep+json");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(200, Aep.MEDIA_TYPE, pending(), null, Map.of())),
                "a pending response has to be 202");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        400, Aep.PROBLEM_MEDIA_TYPE, null, ProblemDetails.of("invalid_request", "No.", 503), Map.of())),
                "a problem whose status disagrees with the response is not valid");
    }

    @Test
    void rejectsDidDocumentsWhoseVerificationMethodIsNotTheAgentDid() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys() {
            @Override
            public CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
                    PlatformIdentityRecord identity, PlatformRequestContext context) {
                return completed(new PlatformDidVerificationMethod(
                        CONTROLLER, CONTROLLER, key.toPublicJWK().toJSONObject(), "JsonWebKey2020"));
            }
        };
        AepPlatform platform = platform(allow(), keys, false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String agentDidId = identity.agentDid().substring(identity.agentDid().lastIndexOf(':') + 1);

        assertThrows(
                CompletionException.class,
                () -> platform.getDidDocument(agentDidId, context(null))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void rejectsUnusableConstructionInput() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();

        assertThrows(
                IllegalArgumentException.class,
                () -> AepPlatform.builder(discovery(false), BLANK, allow(), keys, resolver(true))
                        .build(),
                "didHost is required");
        assertThrows(
                IllegalArgumentException.class,
                () -> AepPlatform.builder(discovery(false), "host/path", allow(), keys, resolver(true))
                        .build(),
                "didHost is a host and a port, nothing else");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false).didPathPrefix("a/../b").build(),
                "dot segments never reach a did:web path");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false)
                        .maximumLifetime(Duration.ofMillis(1500))
                        .build(),
                "the maximum is a whole number of seconds");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(discovery(false, "https://p.example/a/did.json", "300"), allow(), keys, resolver(true))
                        .build(),
                "the template has to name the identifier");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(
                                discovery(false, "http://p.example/a/{agent_did_id}/did.json", "300"),
                                allow(),
                                keys,
                                resolver(true))
                        .build(),
                "the template renders an HTTPS URL");
        assertThrows(
                CompletionException.class,
                () -> builder(allow(), keys, false)
                        .identityIdSupplier(() -> BLANK)
                        .build()
                        .provision(new PlatformProvisionRequest(SERVICE_DID), context(PROVISION_KEY))
                        .toCompletableFuture()
                        .join()
                        .body(),
                "a generated identifier must not be blank");
    }

    @Test
    void acceptsEveryConfigurableCollaborator() throws JOSEException {
        PlatformIdentityStore identityStore = PlatformIdentityStore.inMemory();
        PlatformIdempotencyStore idempotencyStore = PlatformIdempotencyStore.inMemory(PlatformFixtures.CLOCK);
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .identityStore(identityStore)
                .idempotencyStore(idempotencyStore)
                .lifecyclePolicy(PlatformLifecyclePolicy.permissiveTransitions())
                .maximumLifetime(Duration.ofSeconds(300))
                .build();

        assertEquals(
                200, status(platform.provision(new PlatformProvisionRequest(SERVICE_DID), context(PROVISION_KEY))));
        assertThrows(
                NullPointerException.class,
                () -> builder(allow(), new PlatformFixtures.Keys(), false).identityStore(null));
        assertThrows(
                NullPointerException.class,
                () -> builder(allow(), new PlatformFixtures.Keys(), false).idempotencyStore(null));
        assertThrows(
                NullPointerException.class,
                () -> builder(allow(), new PlatformFixtures.Keys(), false).signHandler(null));
        assertThrows(
                NullPointerException.class,
                () -> builder(allow(), new PlatformFixtures.Keys(), false).replayStore(null));
    }

    @Test
    void generatesOpaqueIdentifiersWhenNoSupplierIsConfigured() throws JOSEException {
        AepPlatform platform = AepPlatform.builder(
                        discovery(false), DID_HOST, allow(), new PlatformFixtures.Keys(), resolver(true))
                .clock(PlatformFixtures.CLOCK)
                .didPathPrefix(DID_PREFIX)
                .build();

        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertTrue(identity.agentIdentityId().startsWith("pai_"));
        assertFalse(identity.agentDid().contains("-"));
        assertEquals(
                32,
                identity.agentDid()
                        .substring(identity.agentDid().lastIndexOf(':') + 1)
                        .length());
    }

    @Test
    void foldsNumericPlatformContextIntoTheIdempotencyFingerprint() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("attempt", 1);
        first.put("nested", List.of(true, "x"));
        Map<String, Object> second = new LinkedHashMap<>();
        second.put("attempt", 2);
        second.put("nested", List.of(true, "x"));

        assertEquals(200, status(platform.sign(identity.agentIdentityId(), contextual(first), context(SIGN_KEY))));
        assertEquals(200, status(platform.sign(identity.agentIdentityId(), contextual(first), context(SIGN_KEY))));
        assertEquals(409, status(platform.sign(identity.agentIdentityId(), contextual(second), context(SIGN_KEY))));
    }

    @Test
    void reportsIdempotencyConflictsAcrossOperationsAndInFlightRequests() {
        PlatformIdempotencyStore store = PlatformIdempotencyStore.inMemory(PlatformFixtures.CLOCK);
        PlatformIdempotencyInput sign =
                new PlatformIdempotencyInput(PRINCIPAL, "k", PlatformIdempotentOperation.SIGN, "hash");
        PlatformIdempotencyInput provision =
                new PlatformIdempotencyInput(PRINCIPAL, "k", PlatformIdempotentOperation.PROVISION, "hash");
        CompletableFuture<PlatformResponse<String>> inFlight = new CompletableFuture<>();

        assertEquals(
                PlatformIdempotencyResult.State.CREATED,
                store.execute(sign, () -> completed(ok("first")))
                        .toCompletableFuture()
                        .join()
                        .state());
        assertEquals(
                PlatformIdempotencyResult.State.REPLAYED,
                store.execute(sign, () -> completed(ok("second")))
                        .toCompletableFuture()
                        .join()
                        .state());
        assertEquals(
                PlatformIdempotencyResult.State.CONFLICT,
                store.execute(provision, () -> completed(ok("third")))
                        .toCompletableFuture()
                        .join()
                        .state());

        PlatformIdempotencyStore pendingStore = PlatformIdempotencyStore.inMemory(PlatformFixtures.CLOCK);
        var started = pendingStore.execute(sign, () -> inFlight).toCompletableFuture();
        var joined = pendingStore.execute(sign, () -> completed(ok("ignored"))).toCompletableFuture();
        assertEquals(
                PlatformIdempotencyResult.State.CONFLICT,
                pendingStore
                        .execute(provision, () -> completed(ok("nope")))
                        .toCompletableFuture()
                        .join()
                        .state());
        inFlight.complete(ok("done"));

        assertEquals("done", started.join().response().body());
        assertEquals(PlatformIdempotencyResult.State.REPLAYED, joined.join().state());
    }

    @Test
    void surfacesIdempotentOperationFailuresWithoutStoringThem() {
        PlatformIdempotencyStore store = PlatformIdempotencyStore.inMemory(PlatformFixtures.CLOCK);
        PlatformIdempotencyInput input =
                new PlatformIdempotencyInput(PRINCIPAL, "k", PlatformIdempotentOperation.SIGN, "hash");

        assertThrows(
                CompletionException.class,
                () -> store.execute(input, () -> {
                            throw new IllegalStateException("boom");
                        })
                        .toCompletableFuture()
                        .join());
        assertThrows(
                CompletionException.class,
                () -> store.execute(input, () -> completed(null))
                        .toCompletableFuture()
                        .join());
        assertThrows(
                IllegalArgumentException.class,
                () -> store.execute(
                        new PlatformIdempotencyInput(BLANK, "k", PlatformIdempotentOperation.SIGN, "hash"),
                        () -> completed(ok("x"))));
        assertThrows(IllegalArgumentException.class, () -> store.execute(null, () -> completed(ok("x"))));
        assertEquals(
                PlatformIdempotencyResult.State.CREATED,
                store.execute(input, () -> completed(ok("retry")))
                        .toCompletableFuture()
                        .join()
                        .state());
    }

    @Test
    void keepsIdempotentResultsForTheFullRetentionWindow() {
        AtomicInteger executions = new AtomicInteger();
        java.time.Instant[] instant = {NOW};
        java.time.Clock moving = new java.time.Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return java.time.ZoneOffset.UTC;
            }

            @Override
            public java.time.Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public java.time.Instant instant() {
                return instant[0];
            }
        };
        PlatformIdempotencyStore store = PlatformIdempotencyStore.inMemory(moving);
        PlatformIdempotencyInput input =
                new PlatformIdempotencyInput(PRINCIPAL, "k", PlatformIdempotentOperation.SIGN, "hash");
        java.util.function.Supplier<CompletionStage<PlatformResponse<String>>> operation =
                () -> completed(ok("run-" + executions.incrementAndGet()));

        store.execute(input, operation).toCompletableFuture().join();
        instant[0] = NOW.plus(Duration.ofHours(1));
        var atTheBoundary =
                store.execute(input, operation).toCompletableFuture().join();
        instant[0] = NOW.plus(Duration.ofHours(1)).plusNanos(1);
        var afterTheBoundary =
                store.execute(input, operation).toCompletableFuture().join();

        assertEquals(PlatformIdempotencyResult.State.REPLAYED, atTheBoundary.state());
        assertEquals("run-1", atTheBoundary.response().body());
        assertEquals(PlatformIdempotencyResult.State.CREATED, afterTheBoundary.state());
        assertEquals(2, executions.get());
    }

    @Test
    void refusesIdentityRecordsThatDoNotMatchTheirRequestedScope() {
        PlatformIdentityStore store = PlatformIdentityStore.inMemory();

        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate(PRINCIPAL, SERVICE_DID, () -> {
                            throw new IllegalStateException("boom");
                        })
                        .toCompletableFuture()
                        .join(),
                "a creation failure reaches the caller");
        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate("other", SERVICE_DID, () -> completed(record(ManagedAgentStatus.ACTIVE)))
                        .toCompletableFuture()
                        .join(),
                "a record has to belong to the scope it was created for");
        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate(
                                PRINCIPAL,
                                SERVICE_DID,
                                () -> CompletableFuture.failedFuture(new IllegalStateException("boom")))
                        .toCompletableFuture()
                        .join(),
                "an asynchronous creation failure reaches the caller too");

        store.findOrCreate(PRINCIPAL, SERVICE_DID, () -> completed(record(ManagedAgentStatus.ACTIVE)))
                .toCompletableFuture()
                .join();

        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate(
                                PRINCIPAL,
                                OTHER_SERVICE,
                                () -> completed(record(ManagedAgentStatus.ACTIVE).toBuilder()
                                        .serviceDid(OTHER_SERVICE)
                                        .build()))
                        .toCompletableFuture()
                        .join(),
                "identity material stays unique across scopes");
        assertThrows(
                IllegalArgumentException.class,
                () -> store.list(PRINCIPAL, new PlatformIdentityListQuery(false, 0, 0, null, null)));
        assertThrows(IllegalArgumentException.class, () -> store.findOrCreate(BLANK, SERVICE_DID, () -> null));
        assertEquals(
                Optional.empty(),
                store.findByAgentDid("did:web:absent.example")
                        .toCompletableFuture()
                        .join());
        assertEquals(
                Optional.empty(),
                store.findByAgentDidId("absent").toCompletableFuture().join());
        assertEquals(
                Optional.empty(),
                store.update("pai_absent", ManagedAgentStatus.REVOKED, NOW)
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void refusesUnusableReplayInput() {
        PlatformReplayStore store = PlatformReplayStore.inMemory();

        assertThrows(
                CompletionException.class,
                () -> store.consume(BLANK, NOW.plusSeconds(60), NOW, null)
                        .toCompletableFuture()
                        .join());
        assertFalse(store.consume("k", NOW, NOW, null).toCompletableFuture().join(), "an expired key is never fresh");
        assertTrue(store.consume("k", NOW.plusSeconds(60), NOW, null)
                .toCompletableFuture()
                .join());
    }

    @Test
    void copiesAndValidatesResponseHeaders() {
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of("Bad Name", List.of("v"))));
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of(HEADER, List.of())));
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of(HEADER, List.of(" padded"))));
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of(HEADER, List.of("a\r\nX-Evil: 1"))));
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of(HEADER, List.of("a\u007f"))));
        assertEquals(Map.of(), new PlatformResponse<>(200, Aep.MEDIA_TYPE, "b", null, null).headers());
        assertEquals(List.of("a\tb"), headers(Map.of(HEADER, List.of("a\tb"))).get(HEADER));
    }

    @Test
    void copiesAndValidatesJsonValues() {
        Map<Object, Object> nonStringKey = new LinkedHashMap<>();
        nonStringKey.put(1, "value");
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("inner", nonStringKey);

        assertThrows(IllegalArgumentException.class, () -> PlatformCopies.jsonValue(nested));
        assertThrows(IllegalArgumentException.class, () -> PlatformCopies.jsonValue(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> PlatformCopies.jsonValue(Float.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> PlatformCopies.jsonValue(new Object()));
        assertThrows(
                IllegalArgumentException.class,
                () -> PlatformCopies.jsonObject(java.util.Collections.singletonMap(null, "v")));
        assertEquals(List.of("a", "b"), PlatformCopies.jsonValue(new ArrayList<>(List.of("a", "b"))));
        assertEquals(1.5d, PlatformCopies.jsonValue(1.5d));
        assertEquals(Map.of(), PlatformCopies.jsonObject(null));
    }

    @Test
    void exposesAuthorizationRequestSubjects() throws JOSEException {
        PlatformIdentityRecord identity = record(ManagedAgentStatus.ACTIVE);
        PlatformSignRequest sign = signRequest(null);
        PlatformProvisionRequest provision = new PlatformProvisionRequest(SERVICE_DID);
        PlatformLifecycleRequest lifecycle = active();
        PlatformVerificationRequest verification =
                new PlatformVerificationRequest("token", AssertionOperation.ENROLL, null, SERVICE_DID);
        PlatformIdentityListQuery query = PlatformIdentityListQuery.defaults();

        assertSame(identity, PlatformAuthorizationRequest.getIdentity(identity).identity());
        assertSame(query, PlatformAuthorizationRequest.list(query).listQuery());
        assertSame(provision, PlatformAuthorizationRequest.provision(provision).provisionRequest());
        assertSame(sign, PlatformAuthorizationRequest.sign(identity, sign).signRequest());
        assertSame(
                lifecycle,
                PlatformAuthorizationRequest.update(identity, lifecycle).lifecycleRequest());
        assertSame(
                verification,
                PlatformAuthorizationRequest.verify(identity, verification).verificationRequest());
        assertEquals(
                PlatformAuthorizationOperation.VERIFY,
                PlatformAuthorizationRequest.verify(identity, verification).operation());
        assertEquals(null, PlatformAuthorizationRequest.list(query).identity());
        assertThrows(NullPointerException.class, () -> new PlatformIdentityListResult(null, 0));
    }

    @Test
    void guardsRecordAndDocumentInvariants() {
        PlatformIdentityRecord identity = record(ManagedAgentStatus.ACTIVE);
        PlatformDidVerificationMethod method =
                new PlatformDidVerificationMethod(AGENT_DID, AGENT_DID, Map.of("kty", "EC"), "JsonWebKey2020");
        PlatformDidDocument document = new PlatformDidDocument(
                List.of("https://www.w3.org/ns/did/v1"), List.of(AGENT_DID), AGENT_DID, List.of(method));

        assertThrows(
                IllegalArgumentException.class,
                () -> identity.toBuilder().signingAlgorithms(List.of()).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> identity.toBuilder().agentDid(BLANK).build());
        assertThrows(
                NullPointerException.class,
                () -> identity.toBuilder().status(null).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(AGENT_DID, AGENT_DID, Map.of(), "JsonWebKey2020"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(BLANK, AGENT_DID, Map.of("kty", "EC"), "JsonWebKey2020"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(AGENT_DID, BLANK, Map.of("kty", "EC"), "JsonWebKey2020"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(AGENT_DID, AGENT_DID, Map.of("kty", "EC"), BLANK));
        assertThrows(IllegalArgumentException.class, () -> new PlatformIdentityListResult(List.of(identity), 0));
        assertEquals(List.of("https://www.w3.org/ns/did/v1"), document.context());
        assertEquals(List.of(method), document.verificationMethods());
        assertEquals(Map.of("kty", "EC"), method.publicKeyJwk());
        assertFalse(identity.toString().contains(PRINCIPAL));
        assertTrue(identity.toString().contains(AGENT_DID));
        assertEquals(
                1,
                new PlatformIdentityListResult(List.of(identity), 1)
                        .identities()
                        .size());
    }

    @Test
    void appliesRequestContextDefaults() {
        PlatformRequestContext terse = new PlatformRequestContext(PRINCIPAL, "key");

        assertEquals(null, terse.now());
        assertEquals(Map.of(), terse.values());
        assertTrue(terse.toString().contains("valueNames=[]"));
    }

    @Test
    void signsAgainstTheConfiguredClockWhenNoRequestInstantIsSupplied() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        var signed = (PlatformSignResponses.Completed) platform.sign(
                        identity.agentIdentityId(), signRequest(null), new PlatformRequestContext(PRINCIPAL, SIGN_KEY))
                .toCompletableFuture()
                .join()
                .body();

        assertEquals("2026-07-06T12:00:00Z", signed.issuedAt());
        assertEquals("2026-07-06T12:05:00Z", signed.expiresAt());
    }

    @Test
    void reportsBlankAssertionsFromAKeyStoreAsAFailure() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys() {
            @Override
            public CompletionStage<String> sign(
                    PlatformIdentityRecord identity, ClientAssertionClaims claims, PlatformRequestContext context) {
                return completed(BLANK);
            }
        };
        AepPlatform platform = platform(allow(), keys, false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertThrows(
                CompletionException.class,
                () -> platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                        .toCompletableFuture()
                        .join());
    }

    private static PlatformLifecycleRequest active() {
        return new PlatformLifecycleRequest(ManagedAgentStatus.ACTIVE);
    }

    private static PlatformSignRequest contextual(Map<String, Object> platformContext) {
        return new PlatformSignRequest(JWT_ID, null, AssertionOperation.ENROLL, platformContext, null, SERVICE_DID);
    }

    private static PlatformSignResponses.Response pending() {
        return new PlatformSignResponses.Pending("pending", null, "5");
    }

    private static PlatformResponse<String> ok(String body) {
        return new PlatformResponse<>(200, Aep.MEDIA_TYPE, body, null, Map.of());
    }

    private static Map<String, List<String>> headers(Map<String, List<String>> source) {
        return new PlatformResponse<>(200, Aep.MEDIA_TYPE, "body", null, source).headers();
    }

    private static int status(CompletionStage<? extends PlatformResponse<?>> stage) {
        return stage.toCompletableFuture().join().status();
    }

    private static PlatformResponse<?> handled(PlatformResponse<PlatformSignResponses.Response> response)
            throws JOSEException {
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .signHandler((identity, request, context) -> completed(Optional.ofNullable(response)))
                .build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        return platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                .toCompletableFuture()
                .join();
    }
}
