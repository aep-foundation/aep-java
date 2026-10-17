package foundation.aep.service;

import static foundation.aep.service.ServiceFixtures.AGENT_DID;
import static foundation.aep.service.ServiceFixtures.API_KEY_HEADER;
import static foundation.aep.service.ServiceFixtures.AUTHORIZATION;
import static foundation.aep.service.ServiceFixtures.NOW;
import static foundation.aep.service.ServiceFixtures.RESOURCE;
import static foundation.aep.service.ServiceFixtures.authenticate;
import static foundation.aep.service.ServiceFixtures.basicCredentials;
import static foundation.aep.service.ServiceFixtures.completed;
import static foundation.aep.service.ServiceFixtures.config;
import static foundation.aep.service.ServiceFixtures.document;
import static foundation.aep.service.ServiceFixtures.enroll;
import static foundation.aep.service.ServiceFixtures.grant;
import static foundation.aep.service.ServiceFixtures.serviceBuilder;
import static foundation.aep.service.ServiceFixtures.storedCredentialService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Requirement-level checks for the Service role across the AEP drafts. */
final class ServiceConformanceTest {
    private static final String AEP_AUTHORIZATION = Aep.AUTHORIZATION_HEADER;
    private static final String NOT_RECOGNIZED = "not_recognized";
    private static final String CACHE_CONTROL = "Cache-Control";
    private static final String IF_NONE_MATCH = "If-None-Match";
    private static final String ALLOW = "Allow";
    private static final String SAFE_METHODS = "GET, HEAD";

    /** OAB-PRS-003, BSC-PRS-003: both carriers authenticate on a protected resource. */
    @Test
    void acceptsEitherAuthorizationCarrierForBearerAndBasicCredentials() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);
        grant(service, Aep.GRANT_TYPE_BASIC);

        assertEquals("oauth-1", authenticated(service, Map.of(AUTHORIZATION, List.of("Bearer oauth-secret"))));
        assertEquals(
                "oauth-1",
                authenticated(service, Map.of(AEP_AUTHORIZATION, List.of("Bearer oauth-secret"))),
                "the dedicated carrier presents the same Bearer field value");
        assertEquals("basic-1", authenticated(service, Map.of(AUTHORIZATION, List.of("Basic " + basicCredentials()))));
        assertEquals(
                "basic-1",
                authenticated(service, Map.of(AEP_AUTHORIZATION, List.of("Basic " + basicCredentials()))),
                "the dedicated carrier presents the same Basic field value");
    }

    /** OAB-PRS-004, BSC-PRS-004: one carrier per request; two is ambiguous, not a choice. */
    @Test
    void refusesAmbiguousCarrierPresentations() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);
        Map<String, List<String>> both = Map.of(
                AUTHORIZATION, List.of("Bearer oauth-secret"), AEP_AUTHORIZATION, List.of("Bearer oauth-secret"));

        assertEquals(NOT_RECOGNIZED, rejected(service, both));
        assertEquals(
                NOT_RECOGNIZED,
                rejected(service, Map.of(AUTHORIZATION, List.of("Bearer oauth-secret", "Bearer other"))));
    }

    /** APK-PRS-004: the dedicated carrier does not carry an API key. */
    @Test
    void doesNotAcceptApiKeysThroughTheDedicatedCarrier() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_API_KEY);

        assertEquals("api-1", authenticated(service, Map.of(API_KEY_HEADER, List.of("api-secret"))));
        assertEquals(
                NOT_RECOGNIZED,
                rejected(service, Map.of(AEP_AUTHORIZATION, List.of("ApiKey api-secret"))),
                "the dedicated carrier is reserved for AEP schemes, so this is a malformed presentation");
        assertEquals(
                NOT_RECOGNIZED,
                rejected(service, Map.of(AEP_AUTHORIZATION, List.of("Bearer api-secret"))),
                "an API key is not a bearer token, whichever field carries it");
    }

    /** APK-CFG-003: header names are case-insensitive on the wire. */
    @Test
    void matchesApiKeyHeadersRegardlessOfCase() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_API_KEY);

        assertEquals("api-1", authenticated(service, Map.of("x-service-key", List.of("api-secret"))));
        assertEquals("api-1", authenticated(service, Map.of("X-SERVICE-KEY", List.of("api-secret"))));
    }

    /** APK-PRS-002 vs APK-PRS-003: a wrong header is no presentation; a wrong value is a bad one. */
    @Test
    void separatesMissingCredentialsFromUnusableOnes() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_API_KEY);

        assertEquals("authentication_required", rejected(service, Map.of()));
        assertEquals("authentication_required", rejected(service, Map.of("X-Other", List.of("api-secret"))));
        assertEquals(NOT_RECOGNIZED, rejected(service, Map.of(API_KEY_HEADER, List.of("wrong"))));
    }

    /** RFC 9110 section 9.3.2: a resource that answers GET answers HEAD. */
    @Test
    void answersHeadWhereverItAnswersGet() {
        AepServiceHttpHandler handler = handler();

        assertEquals(200, handle(handler, AepCommand.INSPECT, "HEAD").status());
        assertEquals(401, handle(handler, AepCommand.STATUS, "HEAD").status());
        assertEquals(200, handle(handler, AepCommand.INSPECT, "GET").status());
        var refused = handle(handler, AepCommand.INSPECT, "POST");
        assertEquals(405, refused.status());
        assertEquals(List.of(SAFE_METHODS), refused.headers().get(ALLOW));
        var unsafe = handle(handler, AepCommand.ENROLL, "HEAD");
        assertEquals(405, unsafe.status());
        assertEquals(List.of("POST"), unsafe.headers().get(ALLOW));
    }

    /** CORE-CACHE-001, CORE-CACHE-002, CORE-CACHE-004: freshness, a validator, and revalidation. */
    @Test
    void sendsInspectCacheMetadataAndRevalidatesThroughNotModified() {
        AepServiceHttpHandler handler = handler();
        var inspect = handle(handler, AepCommand.INSPECT, "GET");
        String entityTag = inspect.headers().get("ETag").get(0);

        assertEquals(List.of("public, max-age=300"), inspect.headers().get(CACHE_CONTROL));
        assertTrue(entityTag.startsWith("\"sha256:"));
        assertEquals(304, conditional(handler, entityTag).status());
        assertEquals(304, conditional(handler, "W/" + entityTag).status(), "the comparison is weak");
        assertEquals(304, conditional(handler, "\"other\", " + entityTag).status(), "If-None-Match is a list");
        assertEquals(304, conditional(handler, "*").status());
        assertEquals(200, conditional(handler, "\"other\"").status());
        assertEquals(0, conditional(handler, entityTag).body().length);
        assertEquals(
                entityTag,
                conditional(handler, "\"other\"").headers().get("ETag").get(0));
    }

    /** CORE-CACHE-001: the validator is derived from the document, so unlike documents differ. */
    @Test
    void inspectEntityTagTracksTheAdvertisedDocument() {
        AepServiceHttpHandler first = handler();
        AepServiceHttpHandler same = handler();
        AepServiceHttpHandler other = new AepServiceHttpHandler(
                serviceBuilder(document(List.of(), Map.of(), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                        .build());

        assertEquals(first.inspectEntityTag(), same.inspectEntityTag());
        assertNotEquals(first.inspectEntityTag(), other.inspectEntityTag());
    }

    /** Command responses carry enrollment state and credential secrets; caches must not keep them. */
    @Test
    void keepsCommandResponsesOutOfCaches() {
        AepServiceHttpHandler handler = handler();

        assertEquals(
                List.of("no-store"),
                handle(handler, AepCommand.STATUS, "GET").headers().get(CACHE_CONTROL));
        assertEquals(
                List.of("no-store"),
                handle(handler, AepCommand.INSPECT, "POST").headers().get(CACHE_CONTROL));
        assertEquals(
                List.of("no-store"),
                handle(handler, AepCommand.ENROLL, "POST").headers().get(CACHE_CONTROL));
    }

    @Test
    void preservesOptionalTargetedRevocationAdvertisement() {
        for (String advertised : java.util.Arrays.asList("false", null)) {
            var configuration = new InspectDocument.GrantTypeConfig(advertised);
            var service = serviceBuilder(document(
                            List.of(Aep.GRANT_TYPE_OAUTH_BEARER), Map.of(Aep.GRANT_TYPE_OAUTH_BEARER, configuration)))
                    .storedCredentialGrantType(StoredCredentialGrantTypes.oauthBearer(
                            configuration,
                            (request, context) -> completed(bearer()),
                            ServiceCredentialStore.inMemory()))
                    .build();
            enroll(service);
            grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);
            assertEquals(
                    400,
                    service.revoke(
                                    new RevokeRequest(Aep.GRANT_TYPE_OAUTH_BEARER, "oauth-1", null),
                                    CommandOptions.idempotent("targeted", "targeted-key"))
                            .toCompletableFuture()
                            .join()
                            .status());
            assertEquals("oauth-1", authenticated(service, Map.of(AUTHORIZATION, List.of("Bearer oauth-secret"))));
            assertEquals(
                    200,
                    service.revoke(
                                    new RevokeRequest(Aep.GRANT_TYPE_OAUTH_BEARER, null, null),
                                    CommandOptions.idempotent("all", "all-key"))
                            .toCompletableFuture()
                            .join()
                            .status());
            assertEquals(NOT_RECOGNIZED, rejected(service, Map.of(AUTHORIZATION, List.of("Bearer oauth-secret"))));
        }
    }

    /** OAB-RVK-002: a targeted revoke leaves the Agent's other credentials of that type alone. */
    @Test
    void revokesOnlyTheNamedCredential() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = storedCredentialService(store);
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);
        grant(service, Aep.GRANT_TYPE_API_KEY);

        var response = service.revoke(
                        new RevokeRequest(Aep.GRANT_TYPE_OAUTH_BEARER, "oauth-1", null),
                        CommandOptions.idempotent("revoke", "revoke-key"))
                .toCompletableFuture()
                .join();

        assertEquals(200, response.status());
        assertEquals(NOT_RECOGNIZED, rejected(service, Map.of(AUTHORIZATION, List.of("Bearer oauth-secret"))));
        assertEquals("api-1", authenticated(service, Map.of(API_KEY_HEADER, List.of("api-secret"))));
    }

    /** BSC-RSP-003: an issued Basic credential must survive RFC 7617 encoding unchanged. */
    @Test
    void issuesAndAuthenticatesUtf8BasicCredentials() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = serviceBuilder(
                        document(List.of(Aep.GRANT_TYPE_BASIC), Map.of(Aep.GRANT_TYPE_BASIC, config(List.of()))))
                .storedCredentialGrantType(StoredCredentialGrantTypes.basic(
                        config(List.of()),
                        (request, context) -> completed(new GrantResponses.Basic(
                                "basic-1",
                                NOW.plusSeconds(600).toString(),
                                "paßwort-12345678901234567890",
                                "service",
                                List.of("read"),
                                "agént")),
                        store))
                .build();
        enroll(service);

        assertEquals(
                200,
                service.grant(
                                new foundation.aep.core.GrantRequest(Aep.GRANT_TYPE_BASIC, List.of("read")),
                                CommandOptions.idempotent("grant", "grant-key"))
                        .toCompletableFuture()
                        .join()
                        .status());
        String encoded = java.util.Base64.getEncoder()
                .encodeToString("agént:paßwort-12345678901234567890".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals("basic-1", authenticated(service, Map.of(AUTHORIZATION, List.of("Basic " + encoded))));
        assertEquals("basic-1", authenticated(service, Map.of(AEP_AUTHORIZATION, List.of("Basic " + encoded))));
    }

    @Test
    void refusesBasicCredentialsWithMalformedUtf8OrProhibitedCharacters() {
        for (String[] values : List.of(
                new String[] {"\uD800", "password"}, new String[] {"agent", "\uDC00"},
                new String[] {"agent:name", "password"}, new String[] {"agent", "pass\nword"})) {
            var stored = StoredCredentialGrantTypes.basic(
                    config(List.of()),
                    (request, context) -> completed(new GrantResponses.Basic(
                            "invalid", NOW.plusSeconds(600).toString(), values[1], null, List.of(), values[0])),
                    ServiceCredentialStore.inMemory());
            assertThrows(
                    java.util.concurrent.CompletionException.class,
                    () -> stored.definition()
                            .handler()
                            .grant(
                                    new foundation.aep.core.GrantRequest(Aep.GRANT_TYPE_BASIC, List.of()),
                                    new GrantContext(AGENT_DID, null, Aep.GRANT_TYPE_BASIC, NOW))
                            .toCompletableFuture()
                            .join());
        }
    }

    @Test
    void reservesCredentialIdentifiersAfterExpiryAndRevocation() {
        for (boolean revoked : List.of(false, true)) {
            var store = ServiceCredentialStore.inMemory();
            var expiry = NOW.plusSeconds(600);
            store.save(new ServiceCredentialRecord(
                            AGENT_DID, NOW, bearer(), "oauth-1", expiry, Aep.GRANT_TYPE_OAUTH_BEARER))
                    .toCompletableFuture()
                    .join();
            if (revoked)
                store.revoke(AGENT_DID, Aep.GRANT_TYPE_OAUTH_BEARER, "oauth-1", NOW)
                        .toCompletableFuture()
                        .join();
            var later = NOW.plusSeconds(7200);
            var replacement = new GrantResponses.ApiKey(
                    "different-secret", "oauth-1", later.plusSeconds(600).toString(), API_KEY_HEADER, List.of());
            assertThrows(
                    java.util.concurrent.CompletionException.class,
                    () -> store.save(new ServiceCredentialRecord(
                                    "did:web:other.example",
                                    later,
                                    replacement,
                                    "oauth-1",
                                    later.plusSeconds(600),
                                    Aep.GRANT_TYPE_API_KEY))
                            .toCompletableFuture()
                            .join());
            assertTrue(store.authenticate(
                            Aep.GRANT_TYPE_OAUTH_BEARER,
                            new CredentialAuthenticationInput(
                                    Map.of(AUTHORIZATION, List.of("Bearer oauth-secret")), "GET", RESOURCE, later))
                    .toCompletableFuture()
                    .join()
                    .isEmpty());
        }
    }

    /** CORE-ERR-009: every lifecycle state maps to its fixed code and status. */
    @Test
    void mapsLifecycleStatesToTheirDefinedErrorCodes() {
        assertEquals("verification_pending", blockedGrant(foundation.aep.core.AgentStatus.PENDING, 403));
        assertEquals("identity_suspended", blockedGrant(foundation.aep.core.AgentStatus.SUSPENDED, 403));
        assertEquals("identity_terminated", blockedGrant(foundation.aep.core.AgentStatus.TERMINATED, 403));
        assertEquals("identity_unavailable", blockedGrant(foundation.aep.core.AgentStatus.UNAVAILABLE, 403));
        assertEquals("enrollment_failed", blockedGrant(foundation.aep.core.AgentStatus.REJECTED, 400));
    }

    /** CORE-PR-*: a rejected protected-resource request carries an AEP challenge, not a bare 401. */
    @Test
    void challengesRejectedProtectedResourceRequests() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_API_KEY);

        var response =
                authenticate(service, Map.of(API_KEY_HEADER, List.of("wrong"))).response();
        String challenge = response.headers().get("WWW-Authenticate").get(0);

        assertEquals(401, response.status());
        assertTrue(challenge.startsWith("AEP "));
        assertTrue(challenge.contains("service_did=\"" + ServiceFixtures.SERVICE_DID + "\""));
        assertTrue(challenge.contains("reason=\"" + NOT_RECOGNIZED + "\""));
        assertTrue(challenge.contains("inspect=\"https://service.example" + Aep.WELL_KNOWN_PATH + "\""));
        assertFalse(response.headers().containsKey("Content-Length"));
    }

    /** PLT-IDP-004 shape, CORE-IDEM: an exact retry at the retention boundary still replays. */
    @Test
    void replaysIdempotentResultsForTheFullRetentionWindow() {
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
        IdempotencyStore store = IdempotencyStore.inMemory(moving);
        IdempotencyInput input = new IdempotencyInput(AGENT_DID, "key", "enroll", "hash");
        java.util.concurrent.atomic.AtomicInteger runs = new java.util.concurrent.atomic.AtomicInteger();
        java.util.function.Supplier<java.util.concurrent.CompletionStage<ServiceResponse<String>>> operation =
                () -> completed(ServiceResponse.success("run-" + runs.incrementAndGet()));

        store.execute(input, operation).toCompletableFuture().join();
        instant[0] = NOW.plus(java.time.Duration.ofHours(1));
        var boundary = store.execute(input, operation).toCompletableFuture().join();
        instant[0] = NOW.plus(java.time.Duration.ofHours(1)).plusNanos(1);
        var past = store.execute(input, operation).toCompletableFuture().join();

        assertEquals(IdempotencyResult.State.REPLAYED, boundary.state());
        assertEquals("run-1", boundary.response().body());
        assertEquals(IdempotencyResult.State.CREATED, past.state());
        assertEquals(2, runs.get());
    }

    /** Credential material reaches every authenticator, so it must not reach their logs. */
    @Test
    void redactsCredentialMaterialFromTheAuthenticationInput() {
        CredentialAuthenticationInput input = new CredentialAuthenticationInput(
                Map.of(AUTHORIZATION, List.of("Basic " + basicCredentials())), "GET", RESOURCE, NOW);

        assertFalse(input.toString().contains(basicCredentials()));
        assertTrue(input.toString().contains(AUTHORIZATION), "the field names alone carry no secret");
    }

    private static GrantResponses.OAuthBearer bearer() {
        return new GrantResponses.OAuthBearer(
                "oauth-secret", "oauth-1", NOW.plusSeconds(600).toString(), List.of("read"), "opaque", "Bearer");
    }

    private static String blockedGrant(foundation.aep.core.AgentStatus status, int expectedStatus) {
        EnrollmentStore store = EnrollmentStore.inMemory();
        UnusedHandler handler = new UnusedHandler();
        AepService service = serviceBuilder(
                        document(List.of(Aep.GRANT_TYPE_API_KEY), Map.of(Aep.GRANT_TYPE_API_KEY, config(List.of()))))
                .enrollmentStore(store)
                .grantType(new GrantTypeDefinition(Aep.GRANT_TYPE_API_KEY, handler))
                .credentialAuthenticator(Aep.GRANT_TYPE_API_KEY, handler)
                .build();
        enroll(service);
        // The lifecycle states beyond the initial ones are reached by a later Service decision, not
        // by an enrollment policy, so the record is moved through the store the same way.
        store.save(EnrollmentRecord.builder(AGENT_DID, "enrollment-1", status, NOW)
                        .since(NOW)
                        .updatedAt(NOW)
                        .build())
                .toCompletableFuture()
                .join();

        var response = service.grant(
                        new foundation.aep.core.GrantRequest(Aep.GRANT_TYPE_API_KEY, List.of()),
                        CommandOptions.idempotent("grant", "grant-key"))
                .toCompletableFuture()
                .join();
        assertEquals(expectedStatus, response.status());
        return response.problem().code();
    }

    private static AepServiceHttpHandler handler() {
        return new AepServiceHttpHandler(
                serviceBuilder(document(List.of(), Map.of(), List.of())).build());
    }

    private static AepHttpResponse handle(AepServiceHttpHandler handler, AepCommand command, String method) {
        Map<String, List<String>> headers = command == AepCommand.ENROLL || command == AepCommand.GRANT
                ? Map.of("Content-Type", List.of(Aep.MEDIA_TYPE))
                : Map.of();
        byte[] body = command == AepCommand.ENROLL && "POST".equals(method)
                ? "{\"agent_did\":\"did:web:agent.example\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8)
                : new byte[0];
        return handler.handle(command, new AepHttpRequest(method, RESOURCE, headers, body))
                .toCompletableFuture()
                .join();
    }

    private static AepHttpResponse conditional(AepServiceHttpHandler handler, String entityTag) {
        return handler.handle(
                        AepCommand.INSPECT,
                        new AepHttpRequest("GET", RESOURCE, Map.of(IF_NONE_MATCH, List.of(entityTag)), new byte[0]))
                .toCompletableFuture()
                .join();
    }

    private static String authenticated(AepService service, Map<String, List<String>> headers) {
        ProtectedResourceResult result = authenticate(service, headers);
        assertTrue(result.authenticated(), "expected an authenticated principal");
        return result.principal().credentialId();
    }

    private static String rejected(AepService service, Map<String, List<String>> headers) {
        ProtectedResourceResult result = authenticate(service, headers);
        assertFalse(result.authenticated(), "expected a rejection");
        return result.response().problem().code();
    }

    private static final class UnusedHandler implements GrantTypeHandler, CredentialAuthenticator {
        @Override
        public java.util.concurrent.CompletionStage<GrantResult> grant(
                foundation.aep.core.GrantRequest request, GrantContext context) {
            return completed(new GrantResult("credential-1", Map.of("credential_id", "credential-1")));
        }

        @Override
        public java.util.concurrent.CompletionStage<Void> revoke(RevokeRequest request, RevokeContext context) {
            return completed(null);
        }

        @Override
        public java.util.concurrent.CompletionStage<Boolean> hasPresentation(CredentialAuthenticationInput input) {
            return completed(false);
        }

        @Override
        public java.util.concurrent.CompletionStage<java.util.Optional<AuthenticatedPrincipal>> authenticate(
                CredentialAuthenticationInput input) {
            return completed(java.util.Optional.empty());
        }
    }
}
