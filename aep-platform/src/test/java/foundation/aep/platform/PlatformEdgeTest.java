package foundation.aep.platform;

import static foundation.aep.platform.PlatformFixtures.CLOCK;
import static foundation.aep.platform.PlatformFixtures.DID_HOST;
import static foundation.aep.platform.PlatformFixtures.JWT_ID;
import static foundation.aep.platform.PlatformFixtures.NOW;
import static foundation.aep.platform.PlatformFixtures.OTHER_SERVICE_DID;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import foundation.aep.core.Aep;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.core.PlatformVerificationRequest;
import foundation.aep.core.ProblemDetails;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

/** Boundary conditions across the AEP Platform surface. */
final class PlatformEdgeTest {
    private static final String SIGN_KEY = "sign";
    private static final String BLANK = " ";
    private static final String AGENT_DID = "did:web:p.example:a:opaque1";
    private static final String NOT_RECOGNIZED = "not_recognized";
    private static final String KTY = "kty";
    private static final String EC = "EC";
    private static final String METHOD_TYPE = "JsonWebKey2020";
    private static final String ISSUED_AT = "2026-07-06T12:00:00Z";
    private static final String EXPIRES_AT = "2026-07-06T12:05:00Z";

    @Test
    void treatsAbsentAndBlankPathParametersAlike() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        provision(platform, SERVICE_DID, PROVISION_KEY);

        assertEquals(404, status(platform.getDidDocument(null, context(null))));
        assertEquals(404, status(platform.getDidDocument("absent", context(null))));
        assertEquals(404, status(platform.sign(null, signRequest(null), context(SIGN_KEY))));
        assertEquals(404, status(platform.updateIdentity(BLANK, lifecycle(), context(null))));
        assertEquals(404, status(platform.getIdentity(BLANK, context(null))));
    }

    @Test
    void appliesListDefaultsAndPrincipalScoping() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        provision(platform, SERVICE_DID, PROVISION_KEY);

        var defaults = platform.list(null, context(null)).toCompletableFuture().join();
        var anonymous = platform.list(null, new PlatformRequestContext(null, null, NOW, Map.of()))
                .toCompletableFuture()
                .join();
        var filtered = platform.list(
                        new PlatformIdentityListQuery(false, 100, 0, null, ManagedAgentStatus.REVOKED), context(null))
                .toCompletableFuture()
                .join();
        var pastTheEnd = platform.list(new PlatformIdentityListQuery(false, 100, 5, null, null), context(null))
                .toCompletableFuture()
                .join();

        assertEquals("1", defaults.body().count());
        assertEquals(404, anonymous.status());
        assertEquals("0", filtered.body().count());
        assertEquals("0", filtered.body().total(), "total counts what the whole query matches");
        assertEquals("0", pastTheEnd.body().count());
    }

    @Test
    void keepsSuppliedIdentityIdentifierPrefixes() throws JOSEException {
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .identityIdSupplier(() -> "pai_supplied")
                .build();

        assertEquals(
                "pai_supplied", provision(platform, SERVICE_DID, PROVISION_KEY).agentIdentityId());
    }

    @Test
    void rejectsEveryShapeOfInvalidSignHandlerResult() throws JOSEException {
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(200, Aep.MEDIA_TYPE, null, null, Map.of())),
                "a success needs a body");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        200,
                        Aep.MEDIA_TYPE,
                        completedBody(AGENT_DID, SERVICE_DID, JWT_ID),
                        ProblemDetails.of("invalid_request", "No.", 200),
                        Map.of())),
                "a success carries no problem");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        200, Aep.MEDIA_TYPE, completedBody("not-a-did", SERVICE_DID, JWT_ID), null, Map.of())),
                "the body still has to satisfy the schema");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        200, Aep.MEDIA_TYPE, completedBody(AGENT_DID, OTHER_SERVICE_DID, JWT_ID), null, Map.of())),
                "service_did has to echo the request");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        200, Aep.MEDIA_TYPE, completedBody(AGENT_DID, SERVICE_DID, "other"), null, Map.of())),
                "jti has to echo the request");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        202, Aep.MEDIA_TYPE, completedBody(AGENT_DID, SERVICE_DID, JWT_ID), null, Map.of())),
                "a completed response is 200");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        404,
                        Aep.PROBLEM_MEDIA_TYPE,
                        null,
                        new ProblemDetails(null, null, 404, null, null, null, null, null, null),
                        Map.of())),
                "a problem document still has to validate");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        404, Aep.MEDIA_TYPE, null, ProblemDetails.of(NOT_RECOGNIZED, "Gone.", 404), Map.of())),
                "a problem uses the problem media type");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        200, Aep.PROBLEM_MEDIA_TYPE, null, ProblemDetails.of(NOT_RECOGNIZED, "Gone.", 200), Map.of())),
                "a problem status is an error status");
    }

    @Test
    void refusesAssertionsThatDoNotBindIssuerSubjectAndIdentity() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String mismatchedSubject =
                unbound(keys, identity.agentDid(), "did:web:p.example:a:someone-else", identity.agentDid());
        String unknownIssuer = ClientAssertions.sign(
                new ClientAssertionClaims(
                        "did:web:p.example:a:unknown",
                        "did:web:p.example:a:unknown",
                        SERVICE_DID,
                        AssertionOperation.ENROLL,
                        NOW.getEpochSecond(),
                        NOW.plusSeconds(60).getEpochSecond(),
                        JWT_ID,
                        null),
                keys.key,
                "did:web:p.example:a:unknown");

        assertFalse(verified(platform, mismatchedSubject, "v1"));
        assertFalse(verified(platform, unknownIssuer, "v2"));
    }

    @Test
    void refusesHostedVerificationTheAuthorizerOrPolicyDeclines() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform denying = platform((request, context) -> completed(false), keys, true);
        AepPlatform refusing = builder(allow(), keys, true)
                .lifecyclePolicy(policy(true, false))
                .build();
        AepPlatform signing = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(signing, SERVICE_DID, PROVISION_KEY);
        String assertion = ((PlatformSignResponses.Completed)
                        signing.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                                .toCompletableFuture()
                                .join()
                                .body())
                .clientAssertion();
        provision(denying, SERVICE_DID, PROVISION_KEY);
        provision(refusing, SERVICE_DID, PROVISION_KEY);

        assertFalse(verified(denying, assertion, "v1"));
        assertFalse(verified(refusing, assertion, "v2"));
    }

    @Test
    void verifiesAgainstTheConfiguredClockWhenNoRequestInstantIsSupplied() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String assertion = ((PlatformSignResponses.Completed)
                        platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                                .toCompletableFuture()
                                .join()
                                .body())
                .clientAssertion();

        assertTrue(platform.verify(
                        new PlatformVerificationRequest(assertion, AssertionOperation.ENROLL, null, SERVICE_DID),
                        new PlatformRequestContext(PRINCIPAL, "verify"))
                .toCompletableFuture()
                .join()
                .body()
                .verified());
    }

    @Test
    void scopesAuthorizedIdentitiesToTheCallingPrincipal() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertEquals(
                404,
                status(platform.getIdentity(
                        identity.agentIdentityId(), new PlatformRequestContext("someone-else", null, NOW, Map.of()))));
        assertEquals(
                404,
                status(platform.getIdentity(
                        identity.agentIdentityId(), new PlatformRequestContext(null, null, NOW, Map.of()))));
        assertEquals(200, status(platform.getIdentity(identity.agentIdentityId(), context(null))));
    }

    @Test
    void rejectsDidDocumentsWhoseControllerIsNotTheAgentDid() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys() {
            @Override
            public CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
                    PlatformIdentityRecord identity, PlatformRequestContext context) {
                return completed(new PlatformDidVerificationMethod(
                        "did:web:p.example:a:other",
                        identity.agentDid(),
                        key.toPublicJWK().toJSONObject(),
                        METHOD_TYPE));
            }
        };
        AepPlatform platform = platform(allow(), keys, false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertThrows(
                CompletionException.class,
                () -> platform.getDidDocument("opaque1", context(null))
                        .toCompletableFuture()
                        .join());
        assertEquals(identity.agentDid(), AGENT_DID);
    }

    @Test
    void validatesEveryConstructionArgumentIndependently() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();

        assertThrows(
                IllegalArgumentException.class,
                () -> AepPlatform.builder(discovery(false), null, allow(), keys, resolver(true))
                        .build(),
                "didHost is required");
        assertThrows(
                IllegalArgumentException.class,
                () -> AepPlatform.builder(discovery(false), "user@p.example", allow(), keys, resolver(true))
                        .build(),
                "didHost carries no user information");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false).didPathPrefix("a/./b").build(),
                "a dot segment is not a path component");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false).didPathPrefix("a//b").build(),
                "an empty path component is not a path component");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false).didPathPrefix("").build(),
                "a blank prefix falls back to the default, which no longer matches the template");
        assertThrows(
                IllegalArgumentException.class,
                () -> AepPlatform.builder(discovery(false), ":8443", allow(), keys, resolver(true))
                        .build(),
                "didHost names a host, not a bare port");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false)
                        .maximumLifetime(Duration.ZERO)
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false)
                        .maximumLifetime(Duration.ofSeconds(-1))
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> builder(allow(), keys, false)
                        .maximumLifetime(Duration.ofSeconds(301))
                        .build());
        assertThrows(
                NullPointerException.class, () -> builder(allow(), keys, false).maximumLifetime(null));
        assertThrows(
                NullPointerException.class,
                () -> AepPlatform.builder(discovery(false), DID_HOST, null, keys, resolver(true))
                        .build());
        assertThrows(
                NullPointerException.class,
                () -> AepPlatform.builder(discovery(false), DID_HOST, allow(), null, resolver(true))
                        .build());
        assertThrows(
                NullPointerException.class,
                () -> AepPlatform.builder(discovery(false), DID_HOST, allow(), keys, null)
                        .build());
        assertThrows(
                CompletionException.class,
                () -> builder(allow(), keys, false)
                        .agentDidIdSupplier(() -> null)
                        .build()
                        .provision(new foundation.aep.core.PlatformProvisionRequest(SERVICE_DID), context("p"))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void appliesTheDefaultDidPathPrefixWhenNoneIsConfigured() throws JOSEException {
        AepPlatform platform = builder(
                        discovery(false, "https://p.example/agents/{agent_did_id}/did.json", "300"),
                        allow(),
                        new PlatformFixtures.Keys(),
                        resolver(true))
                .didPathPrefix(null)
                .build();

        assertEquals(
                "did:web:p.example:agents:opaque1",
                provision(platform, SERVICE_DID, PROVISION_KEY).agentDid());
    }

    @Test
    void validatesIdempotencyInputMemberByMember() {
        PlatformIdempotencyStore store = PlatformIdempotencyStore.inMemory(CLOCK);

        assertThrows(IllegalArgumentException.class, () -> execute(store, null, "k", operation(), "h"));
        assertThrows(IllegalArgumentException.class, () -> execute(store, BLANK, "k", operation(), "h"));
        assertThrows(IllegalArgumentException.class, () -> execute(store, PRINCIPAL, null, operation(), "h"));
        assertThrows(IllegalArgumentException.class, () -> execute(store, PRINCIPAL, BLANK, operation(), "h"));
        assertThrows(IllegalArgumentException.class, () -> execute(store, PRINCIPAL, "k", null, "h"));
        assertThrows(IllegalArgumentException.class, () -> execute(store, PRINCIPAL, "k", operation(), null));
        assertThrows(IllegalArgumentException.class, () -> execute(store, PRINCIPAL, "k", operation(), BLANK));
        assertThrows(
                NullPointerException.class,
                () -> store.execute(new PlatformIdempotencyInput(PRINCIPAL, "k", operation(), "h"), null));
        assertThrows(NullPointerException.class, () -> PlatformIdempotencyStore.inMemory(null));
    }

    @Test
    void validatesReplayInputMemberByMember() {
        PlatformReplayStore store = PlatformReplayStore.inMemory();

        assertThrows(
                CompletionException.class,
                () -> store.consume(null, NOW, NOW, null).toCompletableFuture().join());
        assertThrows(
                CompletionException.class,
                () -> store.consume("k", null, NOW, null).toCompletableFuture().join());
        assertThrows(
                CompletionException.class,
                () -> store.consume("k", NOW, null, null).toCompletableFuture().join());
        assertTrue(store.consume("k", NOW.plusSeconds(60), NOW, null)
                .toCompletableFuture()
                .join());
        assertFalse(store.consume("k", NOW.plusSeconds(60), NOW, null)
                .toCompletableFuture()
                .join());
        assertTrue(
                store.consume("k", NOW.plusSeconds(120), NOW.plusSeconds(61), null)
                        .toCompletableFuture()
                        .join(),
                "an expired entry stops blocking its own key");
    }

    @Test
    void validatesStoreAndRecordArgumentsMemberByMember() {
        PlatformIdentityStore store = PlatformIdentityStore.inMemory();

        assertThrows(IllegalArgumentException.class, () -> store.findOrCreate(null, SERVICE_DID, () -> null));
        assertThrows(IllegalArgumentException.class, () -> store.findOrCreate(PRINCIPAL, null, () -> null));
        assertThrows(NullPointerException.class, () -> store.findOrCreate(PRINCIPAL, SERVICE_DID, null));
        assertThrows(IllegalArgumentException.class, () -> store.list(null, PlatformIdentityListQuery.defaults()));
        assertThrows(NullPointerException.class, () -> store.list(PRINCIPAL, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> store.list(PRINCIPAL, new PlatformIdentityListQuery(false, 101, 0, null, null)));
        assertThrows(
                IllegalArgumentException.class,
                () -> store.list(PRINCIPAL, new PlatformIdentityListQuery(false, 1, -1, null, null)));
        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate(PRINCIPAL, SERVICE_DID, () -> completed(null))
                        .toCompletableFuture()
                        .join());
        assertThrows(
                NullPointerException.class,
                () -> record(ManagedAgentStatus.ACTIVE).toBuilder()
                        .createdAt(null)
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> record(ManagedAgentStatus.ACTIVE).toBuilder().keyId(null).build());
    }

    @Test
    void validatesVerificationMethodMembersIndependently() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(null, AGENT_DID, Map.of(KTY, EC), METHOD_TYPE));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(AGENT_DID, null, Map.of(KTY, EC), METHOD_TYPE));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(AGENT_DID, AGENT_DID, Map.of(KTY, EC), null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PlatformDidVerificationMethod(AGENT_DID, AGENT_DID, null, METHOD_TYPE));
    }

    @Test
    void validatesHeaderAndJsonCopiesMemberByMember() {
        assertThrows(
                IllegalArgumentException.class, () -> headers(java.util.Collections.singletonMap(null, List.of("v"))));
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of("", List.of("v"))));
        assertThrows(
                IllegalArgumentException.class, () -> headers(java.util.Collections.singletonMap("X-Trace", null)));
        assertThrows(
                IllegalArgumentException.class,
                () -> headers(Map.of("X-Trace", java.util.Collections.singletonList(null))));
        assertThrows(IllegalArgumentException.class, () -> headers(Map.of("X-Trace", List.of("padded "))));
        assertEquals(
                List.of("ok!#$%&'*+-.^_`|~"),
                headers(Map.of("X-Trace", List.of("ok!#$%&'*+-.^_`|~"))).get("X-Trace"));
        assertEquals(
                List.of("v"),
                headers(Map.of("x-trace-2!#$%&'*+.^_`|~", List.of("v"))).get("x-trace-2!#$%&'*+.^_`|~"),
                "digits, both cases, and every RFC 9110 token character are header-name material");
        assertEquals(null, PlatformCopies.jsonValue(null));
        assertEquals(true, PlatformCopies.jsonValue(true));
        assertEquals(1.5f, PlatformCopies.jsonValue(1.5f));
        assertThrows(IllegalArgumentException.class, () -> PlatformCopies.jsonValue(Float.NaN));
        assertThrows(IllegalArgumentException.class, () -> PlatformCopies.jsonValue(Double.NEGATIVE_INFINITY));
    }

    @Test
    void listsOnlyTheRecordsOwnedByTheCallingPrincipal() {
        PlatformIdentityStore store = PlatformIdentityStore.inMemory();
        store.findOrCreate(PRINCIPAL, SERVICE_DID, () -> completed(record(ManagedAgentStatus.ACTIVE)))
                .toCompletableFuture()
                .join();
        store.findOrCreate(
                        "other-principal",
                        SERVICE_DID,
                        () -> completed(record(ManagedAgentStatus.ACTIVE).toBuilder()
                                .agentDid("did:web:p.example:a:second")
                                .agentDidId("second")
                                .agentIdentityId("pai_second")
                                .keyId("did:web:p.example:a:second")
                                .principal("other-principal")
                                .build()))
                .toCompletableFuture()
                .join();

        var mine = store.list(PRINCIPAL, PlatformIdentityListQuery.defaults())
                .toCompletableFuture()
                .join();

        assertEquals(1, mine.identities().size());
        assertEquals(1, mine.total());
        assertEquals(PRINCIPAL, mine.identities().get(0).principal());
    }

    @Test
    void refusesIdentityMaterialThatCollidesOnAnyIndex() {
        assertThrows(
                CompletionException.class,
                () -> collide(builder -> builder.agentDidId("distinct").agentIdentityId("pai_distinct")),
                "the Agent DID is unique");
        assertThrows(
                CompletionException.class,
                () -> collide(builder ->
                        builder.agentDid("did:web:p.example:a:distinct").agentIdentityId("pai_distinct")),
                "the Agent DID identifier is unique");
        assertThrows(
                CompletionException.class,
                () -> collide(builder ->
                        builder.agentDid("did:web:p.example:a:distinct").agentDidId("distinct")),
                "the Agent identity identifier is unique");
    }

    @Test
    void refusesHostedVerificationForRecordsWhoseKeyIdIsNotTheAgentDid() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        PlatformIdentityStore store = PlatformIdentityStore.inMemory();
        AepPlatform platform = builder(allow(), keys, true).identityStore(store).build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String assertion = ((PlatformSignResponses.Completed)
                        platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                                .toCompletableFuture()
                                .join()
                                .body())
                .clientAssertion();
        PlatformIdentityStore rekeyed = PlatformIdentityStore.inMemory();
        rekeyed.findOrCreate(
                        PRINCIPAL,
                        SERVICE_DID,
                        () -> completed(record(ManagedAgentStatus.ACTIVE).toBuilder()
                                .agentDid(identity.agentDid())
                                .agentDidId("opaque1")
                                .keyId(identity.agentDid() + "#key-1")
                                .build()))
                .toCompletableFuture()
                .join();

        assertFalse(verified(builder(allow(), keys, true).identityStore(rekeyed).build(), assertion, "v-rekeyed"));
    }

    @Test
    void refusesHostedVerificationTheAuthorizerDeclinesForThatOperationAlone() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = builder(
                        discovery(true),
                        (request, context) -> completed(request.operation() != PlatformAuthorizationOperation.VERIFY),
                        keys,
                        resolver(true))
                .build();
        AepPlatform signing = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(signing, SERVICE_DID, PROVISION_KEY);
        provision(platform, SERVICE_DID, PROVISION_KEY);
        String assertion = ((PlatformSignResponses.Completed)
                        signing.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                                .toCompletableFuture()
                                .join()
                                .body())
                .clientAssertion();

        assertFalse(verified(platform, assertion, "v-denied"));
    }

    @Test
    void doesNotTreatAProblemBodyCarryingContentAsAValidProblem() throws JOSEException {
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(
                        400,
                        Aep.PROBLEM_MEDIA_TYPE,
                        completedBody(AGENT_DID, SERVICE_DID, JWT_ID),
                        ProblemDetails.of("invalid_request", "No.", 400),
                        Map.of())),
                "a problem response carries no success body");
        assertThrows(
                CompletionException.class,
                () -> handled(new PlatformResponse<>(400, Aep.PROBLEM_MEDIA_TYPE, null, null, Map.of())),
                "a problem response carries a problem document");
    }

    @Test
    void permissiveTransitionPolicyStillGatesOnTheActiveState() {
        PlatformLifecyclePolicy policy = PlatformLifecyclePolicy.permissiveTransitions();
        PlatformIdentityRecord suspended = record(ManagedAgentStatus.SUSPENDED);

        assertFalse(join(policy.canSign(suspended, null)));
        assertFalse(join(policy.canVerify(suspended, null)));
        assertTrue(join(policy.canTransition(suspended, ManagedAgentStatus.ACTIVE, null)));
        assertTrue(join(policy.canSign(record(ManagedAgentStatus.ACTIVE), null)));
        assertTrue(join(policy.canVerify(record(ManagedAgentStatus.ACTIVE), null)));
    }

    // AEP core refuses to mint an assertion whose subject is not its issuer, so an assertion that
    // breaks that binding has to be assembled directly to reach the Platform's own check.
    private static String unbound(PlatformFixtures.Keys keys, String issuer, String subject, String keyId)
            throws JOSEException {
        com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .type(com.nimbusds.jose.JOSEObjectType.JWT)
                        .keyID(keyId)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .subject(subject)
                        .audience(SERVICE_DID)
                        .issueTime(java.util.Date.from(NOW))
                        .expirationTime(java.util.Date.from(NOW.plusSeconds(60)))
                        .jwtID(JWT_ID)
                        .claim("op", "enroll")
                        .build());
        jwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(keys.key));
        return jwt.serialize();
    }

    private static void collide(java.util.function.UnaryOperator<PlatformIdentityRecord.Builder> change) {
        PlatformIdentityStore store = PlatformIdentityStore.inMemory();
        store.findOrCreate(PRINCIPAL, SERVICE_DID, () -> completed(record(ManagedAgentStatus.ACTIVE)))
                .toCompletableFuture()
                .join();
        store.findOrCreate(
                        PRINCIPAL,
                        OTHER_SERVICE_DID,
                        () -> completed(change.apply(record(ManagedAgentStatus.ACTIVE).toBuilder()
                                        .serviceDid(OTHER_SERVICE_DID))
                                .build()))
                .toCompletableFuture()
                .join();
    }

    private static PlatformIdempotentOperation operation() {
        return PlatformIdempotentOperation.SIGN;
    }

    private static void execute(
            PlatformIdempotencyStore store,
            String principal,
            String key,
            PlatformIdempotentOperation operation,
            String hash) {
        store.execute(
                new PlatformIdempotencyInput(principal, key, operation, hash),
                () -> completed(new PlatformResponse<>(200, Aep.MEDIA_TYPE, "b", null, Map.of())));
    }

    private static PlatformLifecyclePolicy policy(boolean sign, boolean verify) {
        return new PlatformLifecyclePolicy() {
            @Override
            public CompletionStage<Boolean> canSign(PlatformIdentityRecord identity, PlatformRequestContext context) {
                return completed(sign);
            }

            @Override
            public CompletionStage<Boolean> canTransition(
                    PlatformIdentityRecord identity, ManagedAgentStatus nextStatus, PlatformRequestContext context) {
                return completed(true);
            }

            @Override
            public CompletionStage<Boolean> canVerify(PlatformIdentityRecord identity, PlatformRequestContext context) {
                return completed(verify);
            }
        };
    }

    private static foundation.aep.core.PlatformLifecycleRequest lifecycle() {
        return new foundation.aep.core.PlatformLifecycleRequest(ManagedAgentStatus.ACTIVE);
    }

    private static PlatformSignResponses.Response completedBody(String agentDid, String serviceDid, String jwtId) {
        return new PlatformSignResponses.Completed(
                "completed", agentDid, "assertion", EXPIRES_AT, ISSUED_AT, jwtId, null, serviceDid);
    }

    private static Map<String, List<String>> headers(Map<String, List<String>> source) {
        return new PlatformResponse<>(200, Aep.MEDIA_TYPE, "body", null, source).headers();
    }

    private static boolean verified(AepPlatform platform, String assertion, String key) {
        return platform.verify(
                        new PlatformVerificationRequest(assertion, AssertionOperation.ENROLL, null, SERVICE_DID),
                        context(key))
                .toCompletableFuture()
                .join()
                .body()
                .verified();
    }

    private static boolean join(CompletionStage<Boolean> stage) {
        return stage.toCompletableFuture().join();
    }

    private static int status(CompletionStage<? extends PlatformResponse<?>> stage) {
        return stage.toCompletableFuture().join().status();
    }

    private static PlatformResponse<?> handled(PlatformResponse<PlatformSignResponses.Response> response)
            throws JOSEException {
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .signHandler((identity, request, context) -> completed(Optional.of(response)))
                .build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        return platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                .toCompletableFuture()
                .join();
    }
}
