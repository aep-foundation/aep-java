package foundation.aep.service;

import static foundation.aep.service.ServiceFixtures.AGENT_DID;
import static foundation.aep.service.ServiceFixtures.API_KEY_HEADER;
import static foundation.aep.service.ServiceFixtures.AUTHORIZATION;
import static foundation.aep.service.ServiceFixtures.CLOCK;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;

/** Boundary conditions across the AEP Service HTTP binding and its reference stores. */
final class ServiceEdgeTest {
    private static final String API_KEY = Aep.GRANT_TYPE_API_KEY;
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String EXPIRY = "2026-09-01T12:10:00Z";
    private static final String CREDENTIAL_ID = "api-1";
    private static final byte[] ENROLL_BODY =
            "{\"agent_did\":\"did:web:agent.example\"}".getBytes(StandardCharsets.UTF_8);

    @Test
    void refusesRequestsTheBindingCannotRoute() {
        AepServiceHttpHandler handler = handler();

        assertEquals(
                404,
                handle(handler, AepCommand.GRANT, "POST", Map.of(), new byte[0]).status());
        assertEquals(
                400,
                handle(handler, AepCommand.INSPECT, "GET", Map.of(), ENROLL_BODY)
                        .status(),
                "Inspect has no body");
        assertEquals(
                400,
                handle(handler, AepCommand.STATUS, "GET", Map.of(), ENROLL_BODY).status(),
                "Status has no body");
        assertThrows(NullPointerException.class, () -> handler.handle(null, request("GET", Map.of(), new byte[0])));
        assertThrows(NullPointerException.class, () -> handler.handle(AepCommand.INSPECT, null));
        assertThrows(NullPointerException.class, () -> handler.authenticate(null));
    }

    @Test
    void refusesBodiesTheBindingCannotRead() {
        AepServiceHttpHandler small = new AepServiceHttpHandler(commandService(), 3);
        Map<String, List<String>> aep = Map.of(CONTENT_TYPE, List.of(Aep.MEDIA_TYPE));

        assertEquals(
                413, handle(small, AepCommand.ENROLL, "POST", aep, ENROLL_BODY).status());
        assertEquals(
                400,
                handle(small, AepCommand.ENROLL, "POST", aep, new byte[] {(byte) 0xc3, (byte) 0x28, 0x20})
                        .status(),
                "the body has to be UTF-8");
        assertEquals(
                400,
                handle(handler(), AepCommand.ENROLL, "POST", aep, "not json".getBytes(StandardCharsets.UTF_8))
                        .status());
        assertEquals(
                415,
                handle(
                                handler(),
                                AepCommand.ENROLL,
                                "POST",
                                Map.of(CONTENT_TYPE, List.of("application/json")),
                                ENROLL_BODY)
                        .status());
        assertEquals(
                415,
                handle(handler(), AepCommand.ENROLL, "POST", Map.of(), ENROLL_BODY)
                        .status(),
                "the media type is required");
        assertEquals(
                415,
                handle(
                                handler(),
                                AepCommand.ENROLL,
                                "POST",
                                Map.of(CONTENT_TYPE, List.of(Aep.MEDIA_TYPE, Aep.MEDIA_TYPE)),
                                ENROLL_BODY)
                        .status(),
                "one media type, not two");
        assertEquals(
                200,
                handle(
                                handler(),
                                AepCommand.ENROLL,
                                "POST",
                                Map.of(CONTENT_TYPE, List.of("APPLICATION/AEP+JSON; charset=utf-8")),
                                ENROLL_BODY)
                        .status(),
                "the essence matches case-insensitively and ignores parameters");
    }

    @Test
    void routesEveryAdvertisedCommand() {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(commandService());
        Map<String, List<String>> aep = Map.of(CONTENT_TYPE, List.of(Aep.MEDIA_TYPE));

        assertEquals(5, handler.routes().size());
        assertEquals(Aep.WELL_KNOWN_PATH, handler.routes().get(AepCommand.INSPECT));
        assertEquals("/aep/enroll", handler.routes().get(AepCommand.ENROLL));
        assertEquals(AepServiceHttpHandler.DEFAULT_MAXIMUM_REQUEST_BYTES, handler.maximumRequestBytes());
        assertEquals("public, max-age=300", handler.inspectCacheControl());
        assertEquals(
                200,
                handle(handler, AepCommand.ENROLL, "POST", aep, ENROLL_BODY).status());
        assertEquals(
                200,
                handle(
                                handler,
                                AepCommand.GRANT,
                                "POST",
                                aep,
                                "{\"grant_type\":\"api-key\"}".getBytes(StandardCharsets.UTF_8))
                        .status());
        assertEquals(
                200,
                handle(
                                handler,
                                AepCommand.REVOKE,
                                "POST",
                                aep,
                                "{\"grant_type\":\"api-key\"}".getBytes(StandardCharsets.UTF_8))
                        .status());
    }

    @Test
    void readsTheAssertionOnlyFromASingleAepAuthorizationField() {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(commandService());
        Map<String, List<String>> aep = new LinkedHashMap<>();
        aep.put(CONTENT_TYPE, List.of(Aep.MEDIA_TYPE));

        assertEquals(401, statusWith(handler, headers(aep, AUTHORIZATION, List.of("Bearer token"))));
        assertEquals(401, statusWith(handler, headers(aep, AUTHORIZATION, List.of("nonsense"))));
        assertEquals(401, statusWith(handler, headers(aep, AUTHORIZATION, List.of("AEP a", "AEP b"))));
        assertEquals(200, statusWith(handler, headers(aep, AUTHORIZATION, List.of("AEP assertion"))));
    }

    @Test
    void refusesUnusableHandlerConfiguration() {
        AepService service = commandService();

        assertThrows(NullPointerException.class, () -> new AepServiceHttpHandler(null));
        assertThrows(IllegalArgumentException.class, () -> new AepServiceHttpHandler(service, 0));
        assertThrows(IllegalArgumentException.class, () -> new AepServiceHttpHandler(service, -1));
        assertThrows(NullPointerException.class, () -> new AepServiceHttpHandler(service, 1024, null));
        assertThrows(IllegalArgumentException.class, () -> new AepServiceHttpHandler(service, 1024, " "));
        assertThrows(IllegalArgumentException.class, () -> new AepServiceHttpHandler(service, 1024, "max-age=5 "));
        assertThrows(
                IllegalArgumentException.class, () -> new AepServiceHttpHandler(service, 1024, "max-age=5\r\nX: 1"));
        assertEquals("no-store", new AepServiceHttpHandler(service, 1024, "no-store").inspectCacheControl());
    }

    @Test
    void buildsRequestUrlsFromAPublicOrigin() {
        URI origin = URI.create("https://service.example");

        assertEquals(
                URI.create("https://service.example/aep/status?x=1"),
                AepHttpRequest.publicUrl(origin, "/aep/status", "x=1"));
        assertEquals(List.of(), request("GET", Map.of(), new byte[0]).headerValues("Absent"));
        assertThrows(IllegalArgumentException.class, () -> AepHttpRequest.publicUrl(null, "/x", null));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttpRequest.publicUrl(URI.create("ftp://service.example"), "/x", null));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttpRequest.publicUrl(URI.create("https://user@service.example"), "/x", null));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttpRequest.publicUrl(URI.create("https://service.example/base"), "/x", null));
        assertThrows(IllegalArgumentException.class, () -> AepHttpRequest.publicUrl(origin, "relative", null));
        assertThrows(IllegalArgumentException.class, () -> AepHttpRequest.publicUrl(origin, "//evil.example", null));
        assertThrows(NullPointerException.class, () -> new AepHttpRequest(null, RESOURCE, Map.of(), new byte[0]));
        assertThrows(NullPointerException.class, () -> new AepHttpRequest("GET", null, Map.of(), new byte[0]));
        assertEquals(0, new AepHttpRequest("GET", RESOURCE, Map.of(), null).body().length);
    }

    @Test
    void reportsAuthenticationResultsAsOneOrTheOther() {
        AuthenticatedPrincipal principal = new AuthenticatedPrincipal(
                AGENT_DID,
                API_KEY,
                CREDENTIAL_ID,
                API_KEY,
                List.of("read"),
                AuthenticatedPrincipal.Kind.SESSION_CREDENTIAL);
        AepHttpResponse response = new AepHttpResponse(401, Aep.PROBLEM_MEDIA_TYPE, Map.of(), new byte[0]);

        assertTrue(AepHttpAuthenticationResult.authenticated(principal).authenticated());
        assertFalse(AepHttpAuthenticationResult.rejected(response).authenticated());
        assertThrows(IllegalArgumentException.class, () -> new AepHttpAuthenticationResult(false, principal, response));
        assertEquals(
                principal, AepHttpAuthenticationResult.authenticated(principal).principal());
    }

    @Test
    void authenticatesThroughTheBindingAndRejectsThroughIt() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, API_KEY);
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service);

        AepHttpAuthenticationResult accepted = handler.authenticate(
                        new AepHttpRequest("GET", RESOURCE, Map.of(API_KEY_HEADER, List.of("api-secret")), new byte[0]))
                .toCompletableFuture()
                .join();
        AepHttpAuthenticationResult refused = handler.authenticate(
                        new AepHttpRequest("GET", RESOURCE, Map.of(API_KEY_HEADER, List.of("wrong")), new byte[0]))
                .toCompletableFuture()
                .join();

        assertTrue(accepted.authenticated());
        assertEquals(CREDENTIAL_ID, accepted.principal().credentialId());
        assertFalse(refused.authenticated());
        assertEquals(401, refused.response().status());
    }

    @Test
    void guardsGrantResultsAndTheirJsonPayloads() {
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("list", List.of(1, "two", true));
        nested.put("absent", null);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("credential_id", CREDENTIAL_ID);
        response.put("nested", nested);

        GrantResult result = new GrantResult(CREDENTIAL_ID, response);

        assertEquals(nested, result.response().get("nested"));
        assertThrows(IllegalArgumentException.class, () -> new GrantResult(" ", Map.of()));
        assertThrows(
                IllegalArgumentException.class, () -> new GrantResult(CREDENTIAL_ID, Map.of("credential_id", "other")));
        assertThrows(IllegalArgumentException.class, () -> new GrantResult(CREDENTIAL_ID, null));
        assertThrows(IllegalArgumentException.class, () -> new GrantResult(CREDENTIAL_ID, Map.of("x", Double.NaN)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new GrantResult(CREDENTIAL_ID, Map.of("x", Float.POSITIVE_INFINITY)));
        assertThrows(IllegalArgumentException.class, () -> new GrantResult(CREDENTIAL_ID, Map.of("x", new Object())));
        assertThrows(
                IllegalArgumentException.class,
                () -> new GrantResult(CREDENTIAL_ID, Map.of("x", java.util.Collections.singletonMap(1, "v"))));
        assertThrows(
                IllegalArgumentException.class,
                () -> new GrantResult(CREDENTIAL_ID, java.util.Collections.singletonMap(null, "v")));
        assertThrows(IllegalArgumentException.class, () -> new GrantTypeDefinition(" ", null));
    }

    @Test
    void guardsStoredCredentialMetadata() {
        InspectDocument.GrantTypeConfig apiConfig = config(List.of(API_KEY_HEADER));
        StoredCredentialGrantType stored = StoredCredentialGrantTypes.apiKey(
                apiConfig, (request, context) -> completed(apiKey()), ServiceCredentialStore.inMemory());

        assertEquals(API_KEY, stored.grantType());
        assertEquals(apiConfig, stored.config());
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredCredentialGrantType("other", apiConfig, stored.definition(), stored.authenticator()));
        assertThrows(
                NullPointerException.class,
                () -> StoredCredentialGrantTypes.apiKey(apiConfig, null, ServiceCredentialStore.inMemory()));
        assertThrows(
                NullPointerException.class,
                () -> StoredCredentialGrantTypes.apiKey(apiConfig, (request, context) -> completed(apiKey()), null));
    }

    @Test
    void exposesEnrollmentRecordState() {
        EnrollmentRecord record = EnrollmentRecord.builder(AGENT_DID, "enrollment-1", AgentStatus.ACTIVE, NOW)
                .claims(foundation.aep.core.ClaimValues.builder()
                        .contactEmail("agent@example.com")
                        .build())
                .since(NOW)
                .updatedAt(NOW.plusSeconds(1))
                .ownerActionRequired(true)
                .verificationPending(List.of("contact.email"))
                .requirementsPending(List.of("person.username"))
                .build();

        assertEquals("enrollment-1", record.enrollmentId());
        assertEquals("agent@example.com", record.claims().contactEmail());
        assertEquals(NOW, record.createdAt());
        assertEquals(NOW.plusSeconds(1), record.updatedAt());
        assertEquals(NOW, record.since());
        assertTrue(record.ownerActionRequired());
        assertThrows(
                IllegalArgumentException.class,
                () -> EnrollmentRecord.builder(" ", "enrollment-1", AgentStatus.ACTIVE, NOW)
                        .build());
        assertThrows(
                NullPointerException.class,
                () -> EnrollmentRecord.builder(AGENT_DID, "enrollment-1", null, NOW)
                        .build());
    }

    @Test
    void coalescesConcurrentEnrollmentCreation() {
        EnrollmentStore store = EnrollmentStore.inMemory();
        CompletableFuture<EnrollmentRecord> creation = new CompletableFuture<>();
        EnrollmentRecord record = EnrollmentRecord.builder(AGENT_DID, "enrollment-1", AgentStatus.ACTIVE, NOW)
                .since(NOW)
                .updatedAt(NOW)
                .build();

        var first = store.findOrCreate(AGENT_DID, () -> creation).toCompletableFuture();
        var second = store.findOrCreate(AGENT_DID, () -> creation).toCompletableFuture();
        creation.complete(record);

        assertTrue(first.join().created());
        assertFalse(second.join().created());
        assertFalse(store.findOrCreate(AGENT_DID, () -> creation)
                .toCompletableFuture()
                .join()
                .created());
        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate("did:web:other.example", () -> completed(record))
                        .toCompletableFuture()
                        .join(),
                "a record has to belong to the Agent it was created for");
        assertThrows(
                CompletionException.class,
                () -> store.findOrCreate(
                                "did:web:third.example",
                                () -> CompletableFuture.failedFuture(new IllegalStateException("boom")))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void enrollmentCreationCanRetryAfterSynchronousAndAsynchronousFailures() {
        EnrollmentRecord record = EnrollmentRecord.builder(AGENT_DID, "enrollment-1", AgentStatus.PENDING, NOW)
                .status(AgentStatus.ACTIVE)
                .build();
        for (boolean synchronous : List.of(true, false)) {
            EnrollmentStore store = EnrollmentStore.inMemory();
            IllegalStateException failure = new IllegalStateException("policy unavailable");
            var attempt = store.findOrCreate(AGENT_DID, () -> {
                        if (synchronous) throw failure;
                        return CompletableFuture.failedFuture(failure);
                    })
                    .toCompletableFuture();
            assertEquals(
                    failure,
                    assertThrows(CompletionException.class, attempt::join).getCause());
            assertTrue(store.find(AGENT_DID).toCompletableFuture().join().isEmpty());
            var retried = store.findOrCreate(AGENT_DID, () -> completed(record))
                    .toCompletableFuture()
                    .join();
            assertTrue(retried.created());
            assertEquals(
                    record, store.find(AGENT_DID).toCompletableFuture().join().orElseThrow());
        }
    }

    @Test
    void sharesAnInFlightIdempotentOperationAndSurfacesItsFailure() {
        IdempotencyStore store = IdempotencyStore.inMemory(CLOCK);
        IdempotencyInput input = new IdempotencyInput(AGENT_DID, "key", "enroll", "hash");
        CompletableFuture<ServiceResponse<String>> pending = new CompletableFuture<>();

        var started = store.execute(input, () -> pending).toCompletableFuture();
        var joined = store.execute(input, () -> completed(ServiceResponse.success("ignored")))
                .toCompletableFuture();
        var conflicting = store.execute(
                        new IdempotencyInput(AGENT_DID, "key", "grant", "hash"),
                        () -> completed(ServiceResponse.success("no")))
                .toCompletableFuture()
                .join();
        pending.complete(ServiceResponse.success("done"));

        assertEquals("done", started.join().response().body());
        assertEquals(IdempotencyResult.State.REPLAYED, joined.join().state());
        assertEquals(IdempotencyResult.State.CONFLICT, conflicting.state());
        assertThrows(
                CompletionException.class,
                () -> store.execute(new IdempotencyInput(AGENT_DID, "other", "enroll", "hash"), () -> {
                            throw new IllegalStateException("boom");
                        })
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void refusesUnusableReplayRecords() {
        ReplayStore store = ReplayStore.inMemory();

        assertThrows(
                CompletionException.class,
                () -> store.consume(new ReplayRecord(" ", "jti", NOW.plusSeconds(60)), NOW)
                        .toCompletableFuture()
                        .join());
        assertThrows(
                CompletionException.class,
                () -> store.consume(new ReplayRecord(AGENT_DID, " ", NOW.plusSeconds(60)), NOW)
                        .toCompletableFuture()
                        .join());
        assertThrows(
                CompletionException.class,
                () -> store.consume(new ReplayRecord(AGENT_DID, "jti", NOW), NOW)
                        .toCompletableFuture()
                        .join());
        assertTrue(store.consume(new ReplayRecord(AGENT_DID, "jti", NOW.plusSeconds(60)), NOW)
                .toCompletableFuture()
                .join());
        assertTrue(
                store.consume(new ReplayRecord(AGENT_DID, "jti", NOW.plusSeconds(120)), NOW.plusSeconds(61))
                        .toCompletableFuture()
                        .join(),
                "an expired entry stops blocking its own identifier");
    }

    @Test
    void boundsClaimValuesByEveryConfiguredLimit() {
        assertThrows(IllegalArgumentException.class, () -> new ClaimValueLimits(0, 1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new ClaimValueLimits(1, 0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new ClaimValueLimits(1, 1, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new ClaimValueLimits(1, 1, 1, 0));

        ClaimValueLimits limits = new ClaimValueLimits(65_536, 4, 2, 20);

        assertTrue(limits.accepts(null));
        assertTrue(limits.accepts(
                foundation.aep.core.ClaimValues.builder().personUsername("ada").build()));
        assertFalse(
                limits.accepts(foundation.aep.core.ClaimValues.builder()
                        .personUsername("a-username-well-past-the-limit")
                        .build()),
                "a long string is refused");
        assertFalse(
                limits.accepts(foundation.aep.core.ClaimValues.builder()
                        .additional("a", Map.of("b", Map.of("c", "d")))
                        .build()),
                "a deep object is refused");
        assertFalse(
                new ClaimValueLimits(32, 8, 8, 64)
                        .accepts(foundation.aep.core.ClaimValues.builder()
                                .contactEmail("a-fairly-long-address@example.com")
                                .personUsername("ada")
                                .build()),
                "an oversized encoding is refused");
    }

    @Test
    void redactsStoredCredentialRecords() {
        ServiceCredentialRecord record =
                new ServiceCredentialRecord(AGENT_DID, NOW, apiKey(), CREDENTIAL_ID, Instant.parse(EXPIRY), API_KEY);

        assertFalse(record.toString().contains("api-secret"));
        assertTrue(record.toString().contains(CREDENTIAL_ID));
        assertThrows(
                NullPointerException.class,
                () -> new ServiceCredentialRecord(AGENT_DID, NOW, null, CREDENTIAL_ID, Instant.parse(EXPIRY), API_KEY));
    }

    @Test
    void refusesCredentialRecordsTheStoreCannotIndex() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();

        assertThrows(CompletionException.class, () -> save(store, CREDENTIAL_ID, "other-id", EXPIRY));
        assertThrows(CompletionException.class, () -> save(store, " ", " ", EXPIRY));
        assertThrows(
                CompletionException.class,
                () -> save(store, CREDENTIAL_ID, CREDENTIAL_ID, "2026-09-01T11:00:00Z"),
                "expiry has to follow creation");
        save(store, CREDENTIAL_ID, CREDENTIAL_ID, EXPIRY);
        assertThrows(
                CompletionException.class,
                () -> save(store, CREDENTIAL_ID, CREDENTIAL_ID, EXPIRY),
                "an identifier is issued once");
        assertThrows(CompletionException.class, () -> save(store, "api-2", "api-2", EXPIRY), "a secret is issued once");
    }

    @Test
    void credentialStoreRejectsMissingAndMultiplePresentations() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        save(store, CREDENTIAL_ID, CREDENTIAL_ID, EXPIRY);
        for (Map<String, List<String>> headers :
                List.of(Map.<String, List<String>>of(), Map.of(API_KEY_HEADER, List.of("api-secret", "api-secret")))) {
            assertTrue(store.authenticate(API_KEY, new CredentialAuthenticationInput(headers, "GET", RESOURCE, NOW))
                    .toCompletableFuture()
                    .join()
                    .isEmpty());
        }
        assertTrue(store.authenticate(
                        API_KEY,
                        new CredentialAuthenticationInput(
                                Map.of(API_KEY_HEADER, List.of("api-secret")), "GET", RESOURCE, NOW))
                .toCompletableFuture()
                .join()
                .isPresent());
    }

    @Test
    void revokesOnlyWhatTheRequestNames() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = storedCredentialService(store);
        enroll(service);
        grant(service, API_KEY);
        Map<String, List<String>> presented = Map.of(API_KEY_HEADER, List.of("api-secret"));

        store.revoke("did:web:someone.example", API_KEY, CREDENTIAL_ID, NOW)
                .toCompletableFuture()
                .join();
        store.revoke(AGENT_DID, Aep.GRANT_TYPE_BASIC, CREDENTIAL_ID, NOW)
                .toCompletableFuture()
                .join();
        store.revoke(AGENT_DID, API_KEY, "absent", NOW).toCompletableFuture().join();
        assertTrue(authenticate(service, presented).authenticated(), "none of those named this credential");

        store.revokeGrantType(AGENT_DID, API_KEY, NOW).toCompletableFuture().join();

        assertFalse(authenticate(service, presented).authenticated());
        assertThrows(
                CompletionException.class,
                () -> store.revoke(AGENT_DID, API_KEY, CREDENTIAL_ID, null)
                        .toCompletableFuture()
                        .join());
        assertThrows(
                CompletionException.class,
                () -> store.revokeGrantType(AGENT_DID, API_KEY, null)
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void revokesEveryCredentialOfAGrantTypeForABlankIdentifier() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = storedCredentialService(store);
        enroll(service);
        grant(service, API_KEY);
        GrantTypeHandler handler = StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)), (request, context) -> completed(apiKey()), store)
                .definition()
                .handler();

        handler.revoke(
                        new foundation.aep.core.RevokeRequest(API_KEY, " ", null),
                        new RevokeContext(AGENT_DID, null, API_KEY, NOW))
                .toCompletableFuture()
                .join();

        assertFalse(
                authenticate(service, Map.of(API_KEY_HEADER, List.of("api-secret")))
                        .authenticated(),
                "a blank identifier names no credential, so the whole Grant Type is revoked");
    }

    @Test
    void reportsAMalformedAepPresentationAsUnrecognized() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);

        // CORE-PR-038 separates a missing credential from a malformed one. A value naming an AEP
        // scheme is an AEP presentation even when the rest of it does not parse, so ignoring it and
        // answering authentication_required both reported the wrong code and told the caller its
        // credential had never been seen.
        assertEquals("not_recognized", rejected(service, Map.of(AUTHORIZATION, List.of("AEP"))));
        assertEquals("not_recognized", rejected(service, Map.of(AUTHORIZATION, List.of("Bearer"))));
        assertEquals(
                "not_recognized",
                rejected(service, Map.of(AUTHORIZATION, List.of("aep  "))),
                "scheme matching is case-insensitive and whitespace does not make credentials");
        assertEquals(
                "not_recognized",
                rejected(service, Map.of(AUTHORIZATION, List.of("Basic not a token"))),
                "credentials carrying a space are not a single credential");
        assertEquals(
                "authentication_required",
                rejected(service, Map.of(AUTHORIZATION, List.of("Negotiate"))),
                "an unrelated scheme with no credentials is still not an AEP presentation");
    }

    @Test
    void ignoresUnrelatedAuthorizationSchemesOnProtectedResources() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);

        assertEquals("authentication_required", rejected(service, Map.of(AUTHORIZATION, List.of("Negotiate abc"))));
        assertTrue(authenticate(
                        service,
                        Map.of(
                                Aep.AUTHORIZATION_HEADER,
                                List.of("Bearer oauth-secret"),
                                AUTHORIZATION,
                                List.of("Payment unrelated-payment")))
                .authenticated());
        assertEquals(
                "authentication_required",
                rejected(service, Map.of(AUTHORIZATION, List.of("Negotiate abc", "Digest xyz"))),
                "two unrelated schemes are still no AEP presentation");
        assertEquals(
                "not_recognized",
                rejected(service, Map.of(AUTHORIZATION, List.of("Bearer oauth-secret", "Negotiate abc"))),
                "an AEP scheme alongside anything else is ambiguous");
        assertEquals(
                "not_recognized",
                rejected(
                        service,
                        Map.of(
                                Aep.AUTHORIZATION_HEADER,
                                List.of("Bearer oauth-secret"),
                                AUTHORIZATION,
                                List.of("Basic " + basicCredentials()))),
                "the dedicated carrier does not win a race against a recognized standard one");
    }

    @Test
    void doesNotResolveNamesWhenDecidingWhatIsLoopback() {
        AepService service = serviceBuilder(document(List.of(), Map.of(), List.of()))
                .allowInsecureLoopback(true)
                .build();

        assertThrows(
                CompletionException.class,
                () -> service.authenticate(new ProtectedResourceRequest(
                                Map.of(), "GET", URI.create("http://not-a-real-host.invalid/x")))
                        .toCompletableFuture()
                        .join());
        assertThrows(
                CompletionException.class,
                () -> service.authenticate(
                                new ProtectedResourceRequest(Map.of(), "GET", URI.create("http://[2001:db8::1]/x")))
                        .toCompletableFuture()
                        .join());
        assertFalse(
                service.authenticate(new ProtectedResourceRequest(Map.of(), "GET", URI.create("http://[::1]:8080/x")))
                        .toCompletableFuture()
                        .join()
                        .authenticated());
    }

    private static GrantResponses.ApiKey apiKey() {
        return new GrantResponses.ApiKey("api-secret", CREDENTIAL_ID, EXPIRY, API_KEY_HEADER, List.of("read"));
    }

    private static void save(ServiceCredentialStore store, String credentialId, String responseId, String expiry) {
        store.save(new ServiceCredentialRecord(
                        AGENT_DID,
                        NOW,
                        new GrantResponses.ApiKey("api-secret", responseId, expiry, API_KEY_HEADER, List.of("read")),
                        credentialId,
                        Instant.parse(expiry),
                        API_KEY))
                .toCompletableFuture()
                .join();
    }

    private static AepService commandService() {
        return serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of(API_KEY_HEADER)))))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)),
                        (request, context) -> completed(apiKey()),
                        ServiceCredentialStore.inMemory()))
                .build();
    }

    private static AepServiceHttpHandler handler() {
        return new AepServiceHttpHandler(
                serviceBuilder(document(List.of(), Map.of(), List.of())).build());
    }

    private static Map<String, List<String>> headers(Map<String, List<String>> base, String name, List<String> values) {
        Map<String, List<String>> result = new LinkedHashMap<>(base);
        result.put(name, values);
        return result;
    }

    private static int statusWith(AepServiceHttpHandler handler, Map<String, List<String>> headers) {
        return handle(handler, AepCommand.ENROLL, "POST", headers, ENROLL_BODY).status();
    }

    private static AepHttpResponse handle(
            AepServiceHttpHandler handler,
            AepCommand command,
            String method,
            Map<String, List<String>> headers,
            byte[] body) {
        return handler.handle(command, request(method, headers, body))
                .toCompletableFuture()
                .join();
    }

    private static AepHttpRequest request(String method, Map<String, List<String>> headers, byte[] body) {
        Map<String, List<String>> all = new LinkedHashMap<>(headers);
        int sequence = counter();
        all.putIfAbsent(AUTHORIZATION, List.of("AEP assertion-" + sequence));
        all.putIfAbsent("Idempotency-Key", List.of("key-" + sequence));
        return new AepHttpRequest(method, RESOURCE, all, body);
    }

    private static int counter() {
        return COUNTER.incrementAndGet();
    }

    private static final java.util.concurrent.atomic.AtomicInteger COUNTER =
            new java.util.concurrent.atomic.AtomicInteger();

    private static String rejected(AepService service, Map<String, List<String>> headers) {
        ProtectedResourceResult result = authenticate(service, headers);
        assertFalse(result.authenticated(), "expected a rejection");
        return result.response().problem().code();
    }
}
