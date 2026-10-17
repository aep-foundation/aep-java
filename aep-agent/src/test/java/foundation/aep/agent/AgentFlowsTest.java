package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.RevokeRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

/** Command flows, credential handling, and Platform delegation failure paths. */
class AgentFlowsTest {
    private static final URI ORIGIN = URI.create("https://service.example");
    private static final URI PLATFORM = URI.create("https://platform.example");
    private static final String SERVICE_DID = "did:web:service.example";
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");

    @Test
    void discoveryFollowsRedirectsButAuthenticatedCommandsNeverDo() {
        for (int status : List.of(301, 302, 303, 307, 308)) {
            QueueTransport inspect = new QueueTransport(
                    response(status, Map.of("Location", List.of("/metadata/aep")), ""),
                    aepResponse(200, document(List.of("inspect", "status"))));
            QueueTransport commands = new QueueTransport(
                    response(status, Map.of("Location", List.of("https://attacker.example/collect")), ""));
            AepServiceSession session = agent(inspect, commands).build().service(ORIGIN);
            assertEquals("command_redirect", error(session.status()).code());
            assertEquals(2, inspect.requests.size());
            assertEquals(
                    ORIGIN.resolve("/metadata/aep"), inspect.requests.get(1).uri());
            assertTrue(inspect.requests.stream()
                    .noneMatch(request -> request.headers().containsKey("Authorization")));
            assertEquals(1, commands.requests.size());
            assertEquals("service.example", commands.requests.get(0).uri().getHost());

            QueueTransport platform = new QueueTransport(
                    response(status, Map.of("Location", List.of("/metadata/platform")), ""),
                    aepResponse(200, discovery()),
                    response(status, Map.of("Location", List.of("https://attacker.example/collect")), ""));
            PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                    .transport(platform)
                    .authorization("Bearer owner-token")
                    .build();
            assertEquals(
                    "platform_command_redirect",
                    error(provider.findIdentityByServiceDid("did:web:api.service.example")
                                    .toCompletableFuture())
                            .code());
            assertEquals(3, platform.requests.size());
            assertFalse(platform.requests.get(0).headers().containsKey("Authorization"));
            assertFalse(platform.requests.get(1).headers().containsKey("Authorization"));
            assertEquals(
                    PLATFORM.resolve("/metadata/platform"),
                    platform.requests.get(1).uri());
            assertEquals("platform.example", platform.requests.get(2).uri().getHost());
        }
    }

    @Test
    void customGrantParserFailureDoesNotPersistACredential() {
        MemoryStore store = new MemoryStore();
        IllegalArgumentException cause = new IllegalArgumentException("unsupported credential payload");
        AepServiceSession session = agent(
                        new QueueTransport(aepResponse(200, document(List.of("inspect", "grant")))),
                        new QueueTransport(aepResponse(200, "{\"credential_id\":\"c-1\"}")))
                .credentialStore(store)
                .credentialHandler(handler("custom-session", "custom-grant", (serviceDid, json) -> {
                    throw cause;
                }))
                .build()
                .service(ORIGIN);
        assertSame(
                cause,
                assertThrows(
                                CompletionException.class,
                                () -> session.grant("custom-grant", List.of()).join())
                        .getCause());
        assertTrue(store.saved.isEmpty());
    }

    @Test
    void customGrantCannotChangeTheGrantTypeBeforePersistence() {
        MemoryStore store = new MemoryStore();
        AepServiceSession session = agent(
                        new QueueTransport(aepResponse(200, document(List.of("inspect", "grant")))),
                        new QueueTransport(aepResponse(200, "{\"credential_id\":\"c-1\"}")))
                .credentialStore(store)
                .credentialHandler(handler(
                        "custom-session",
                        "custom-grant",
                        (serviceDid, json) -> new AgentCredential(serviceDid, "another-grant", "c-1", null, json)))
                .build()
                .service(ORIGIN);
        assertEquals(
                "invalid_credential",
                error(session.grant("custom-grant", List.of())).code());
        assertTrue(store.saved.isEmpty());
    }

    @Test
    void customCredentialsWithoutAnExpiryRemainUsable() {
        AgentCredentialStore store = AgentCredentialStore.inMemory();
        store.save(new AgentCredential(SERVICE_DID, "custom-grant", "c-1", null, "{}"))
                .toCompletableFuture()
                .join();
        AepServiceSession session = agent(
                        new QueueTransport(aepResponse(
                                200, document(List.of("inspect"), "custom-grant", List.of("custom-session")))),
                        new QueueTransport())
                .credentialStore(store)
                .credentialHandler(handler("custom-session", "custom-grant", null))
                .build()
                .service(ORIGIN);
        AgentAuthentication authentication =
                session.authenticate(ORIGIN.resolve("/private")).join();
        assertEquals("custom-session", authentication.method());
        assertEquals(List.of("value"), authentication.headers().get("X-Credential"));
    }

    @Test
    void failedSigningDoesNotSendTheCommandOrMutateTheSignersFuture() {
        for (boolean wrapped : List.of(true, false)) {
            IllegalStateException cause = new IllegalStateException("signer unavailable");
            CompletableFuture<String> signing = new CompletableFuture<>();
            QueueTransport commands = new QueueTransport();
            AepServiceSession session = agent(
                            new QueueTransport(aepResponse(200, document(List.of("inspect", "status")))), commands)
                    .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(
                            new AgentIdentity("did:web:agent.example", claims -> signing)))
                    .build()
                    .service(ORIGIN);
            CompletableFuture<?> status = session.status();
            assertFalse(signing.isDone());
            signing.completeExceptionally(wrapped ? new CompletionException(cause) : cause);
            assertSame(
                    cause, assertThrows(CompletionException.class, status::join).getCause());
            assertTrue(commands.requests.isEmpty());
        }
    }

    @Test
    void defaultAssertionIdentifiersAreFreshForEachCommand() {
        List<ClientAssertionClaims> assertions = new ArrayList<>();
        AgentIdentity identity = new AgentIdentity("did:web:agent.example", claims -> {
            assertions.add(claims);
            return CompletableFuture.completedFuture("signed");
        });
        AepServiceSession session = AepAgent.builder()
                .inspectTransport(new QueueTransport(aepResponse(200, document(List.of("inspect", "status")))))
                .commandTransport(new QueueTransport(
                        aepResponse(200, "{\"status\":\"active\"}"), aepResponse(200, "{\"status\":\"active\"}")))
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(identity))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build()
                .service(ORIGIN);
        session.status().join();
        session.status().join();
        assertEquals(2, assertions.size());
        assertFalse(assertions.get(0).jwtId().isBlank());
        assertFalse(assertions.get(1).jwtId().isBlank());
        assertFalse(assertions.get(0).jwtId().equals(assertions.get(1).jwtId()));
        assertTrue(assertions.stream().allMatch(claims -> claims.operation() == AssertionOperation.STATUS));
    }

    @Test
    void concurrentInspectionsShareTransportWithoutSharingCancellation() {
        CompletableFuture<AepHttpTransport.Response> response = new CompletableFuture<>();
        List<AepHttpTransport.Request> requests = new ArrayList<>();
        AepHttpTransport transport = request -> {
            requests.add(request);
            return response;
        };
        AepServiceSession session =
                agent(transport, new QueueTransport()).build().service(ORIGIN);
        CompletableFuture<AgentInspection> first = session.inspect();
        CompletableFuture<AgentInspection> second = session.inspect();
        assertEquals(1, requests.size());
        assertTrue(first.cancel(false));
        assertFalse(response.isCancelled());
        assertFalse(second.isDone());
        response.complete(aepResponse(200, document(List.of("inspect"))));
        assertEquals(SERVICE_DID, second.join().document().service().did());
    }

    @Test
    void inspectionCanRetryAfterAnAsynchronousTransportFailure() {
        CompletableFuture<AepHttpTransport.Response> failed = new CompletableFuture<>();
        List<AepHttpTransport.Request> requests = new ArrayList<>();
        AepHttpTransport transport = request -> {
            requests.add(request);
            return requests.size() == 1
                    ? failed
                    : CompletableFuture.completedFuture(aepResponse(200, document(List.of("inspect"))));
        };
        AepServiceSession session =
                agent(transport, new QueueTransport()).build().service(ORIGIN);
        CompletableFuture<AgentInspection> inspection = session.inspect();
        IllegalStateException failure = new IllegalStateException("connection closed");
        failed.completeExceptionally(new CompletionException(failure));
        assertSame(
                failure,
                assertThrows(CompletionException.class, inspection::join).getCause());
        assertEquals(SERVICE_DID, session.inspect().join().document().service().did());
        assertEquals(2, requests.size());
    }

    @Test
    void platformProvisioningRejectsAnInactiveOrDifferentlyScopedIdentity() {
        for (String body : List.of(
                identity().replace("did:web:api.service.example", "did:web:other.example"),
                identity().replace("\"status\":\"active\"", "\"status\":\"suspended\""))) {
            QueueTransport transport = new QueueTransport(
                    aepResponse(200, discovery()), aepResponse(200, emptyList()), aepResponse(200, body));
            PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                    .transport(transport)
                    .build();
            assertEquals(
                    "platform_identity_mismatch",
                    error(provider.getOrCreate(URI.create("https://api.service.example"), "did:web:api.service.example")
                                    .toCompletableFuture())
                            .code());
            assertEquals(3, transport.requests.size());
            assertEquals("POST", transport.requests.get(2).method());
        }
    }

    @Test
    void grantChecksAdvertisedTypeAndPreflightsStatusWhenAvailable() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "grant", "status"))));
        AepServiceSession advertised =
                agent(inspect, new QueueTransport()).build().service(ORIGIN);
        assertEquals(
                "grant_type_not_advertised",
                error(advertised.grant("absent-grant", List.of())).code());

        QueueTransport withoutStatus = new QueueTransport(aepResponse(200, document(List.of("inspect", "grant"))));
        assertEquals(
                "{\"credential_id\":\"c-1\"}",
                agent(withoutStatus, new QueueTransport(aepResponse(200, "{\"credential_id\":\"c-1\"}")))
                        .build()
                        .service(ORIGIN)
                        .grant("custom-grant", List.of())
                        .join()
                        .responseJson());

        QueueTransport pendingInspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect", "grant", "status"))));
        QueueTransport pendingCommand = new QueueTransport(aepResponse(200, "{\"status\":\"pending\"}"));
        assertEquals(
                "enrollment_not_active",
                error(agent(pendingInspect, pendingCommand)
                                .build()
                                .service(ORIGIN)
                                .grant("custom-grant", List.of()))
                        .code());
    }

    @Test
    void grantStoresAHandledCredentialAndPassesThroughAnUnhandledOne() {
        String credentialJson = "{\"api_key\":\"key-value\",\"credential_id\":\"c-1\","
                + "\"expires_at\":\"2026-09-01T01:00:00Z\",\"header\":\"x-api-key\"}";
        QueueTransport inspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect", "grant", "status"), "api-key")));
        QueueTransport command =
                new QueueTransport(aepResponse(200, "{\"status\":\"active\"}"), aepResponse(200, credentialJson));
        MemoryStore store = new MemoryStore();
        AgentGrantResult handled = agent(inspect, command)
                .credentialStore(store)
                .build()
                .service(ORIGIN)
                .grant("api-key", List.of())
                .join();

        assertEquals("api-key", handled.grantType());
        assertEquals("c-1", handled.credential().orElseThrow().credentialId());
        assertEquals(Optional.of("c-1"), store.saved.map(AgentCredential::credentialId));

        // A Grant Type with no registered handler still returns its raw object.
        QueueTransport rawInspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect", "grant", "status"))));
        QueueTransport rawCommand = new QueueTransport(
                aepResponse(200, "{\"status\":\"active\"}"), aepResponse(200, "{\"credential_id\":\"c-2\"}"));
        AgentGrantResult raw = agent(rawInspect, rawCommand)
                .build()
                .service(ORIGIN)
                .grant("custom-grant", List.of())
                .join();
        assertTrue(raw.credential().isEmpty());
        assertEquals("{\"credential_id\":\"c-2\"}", raw.responseJson());
    }

    @Test
    void grantRefusesACredentialHandlerThatChangesTheCredentialScope() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "grant", "status"))));
        QueueTransport command = new QueueTransport(
                aepResponse(200, "{\"status\":\"active\"}"), aepResponse(200, "{\"credential_id\":\"c-1\"}"));
        AgentCredentialHandler rogue = handler(
                "custom-session",
                "custom-grant",
                (serviceDid, json) ->
                        new AgentCredential("did:web:attacker.example", "custom-grant", "c-1", NOW, json));

        assertEquals(
                "invalid_credential",
                error(agent(inspect, command)
                                .credentialHandler(rogue)
                                .build()
                                .service(ORIGIN)
                                .grant("custom-grant", List.of()))
                        .code());
    }

    @Test
    void revokeDeletesTheMatchingStoredCredentials() {
        for (RevokeRequest request : List.of(
                new RevokeRequest("custom-grant", null, null),
                new RevokeRequest("custom-grant", "c-1", null),
                new RevokeRequest(null, null, "true"))) {
            QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "revoke"))));
            QueueTransport command = new QueueTransport(aepResponse(200, "{}"));
            MemoryStore store = new MemoryStore();
            store.saved = Optional.of(new AgentCredential(SERVICE_DID, "custom-grant", "c-1", NOW, "{}"));

            agent(inspect, command)
                    .credentialStore(store)
                    .build()
                    .service(ORIGIN)
                    .revoke(request)
                    .join();

            assertTrue(store.saved.isEmpty(), request.toString());
        }
    }

    @Test
    void authenticateFallsThroughToTheNextUsableMethod() {
        String credentialJson = "{\"api_key\":\"key-value\",\"credential_id\":\"c-1\","
                + "\"expires_at\":\"2026-09-01T01:00:00Z\",\"header\":\"x-api-key\"}";
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of("inspect"), "api-key", List.of("custom-session", "oauth-bearer", "api-key"))));
        MemoryStore store = new MemoryStore();
        store.saved =
                Optional.of(new AgentCredential(SERVICE_DID, "api-key", "c-1", NOW.plusSeconds(3_600), credentialJson));

        AgentAuthentication authentication = agent(inspect, new QueueTransport())
                .credentialStore(store)
                .build()
                .service(ORIGIN)
                .authenticate(URI.create("https://service.example/private"))
                .join();

        assertEquals("api-key", authentication.method());
        assertEquals(List.of("key-value"), authentication.headers().get("x-api-key"));
    }

    @Test
    void authenticateSkipsAnExpiredCredential() {
        String credentialJson = "{\"api_key\":\"key-value\",\"credential_id\":\"c-1\","
                + "\"expires_at\":\"2026-08-01T00:00:00Z\",\"header\":\"x-api-key\"}";
        QueueTransport inspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect"), "api-key", List.of("api-key"))));
        MemoryStore store = new MemoryStore();
        store.saved = Optional.of(
                new AgentCredential(SERVICE_DID, "api-key", "c-1", NOW.minusSeconds(3_600), credentialJson));

        assertEquals(
                "authentication_unavailable",
                error(agent(inspect, new QueueTransport())
                                .credentialStore(store)
                                .build()
                                .service(ORIGIN)
                                .authenticate(URI.create("https://service.example/private")))
                        .code());
    }

    @Test
    void authenticateRefusesAStoredCredentialFromAnotherService() {
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("inspect"), "custom-grant", List.of("custom-session"))));
        MemoryStore store = new MemoryStore();
        store.saved = Optional.of(
                new AgentCredential("did:web:attacker.example", "custom-grant", "c-1", NOW.plusSeconds(60), "{}"));

        assertEquals(
                "invalid_credential",
                error(agent(inspect, new QueueTransport())
                                .credentialStore(store)
                                .credentialHandler(handler("custom-session", "custom-grant", null))
                                .build()
                                .service(ORIGIN)
                                .authenticate(URI.create("https://service.example/private")))
                        .code());
    }

    @Test
    void waitForActiveResolvesRejectedAndTimedOutEnrollments() {
        for (String status : List.of("rejected", "suspended", "terminated")) {
            QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
            QueueTransport command = new QueueTransport(aepResponse(200, "{\"status\":\"" + status + "\"}"));
            assertEquals(
                    "enrollment_not_active",
                    error(agent(inspect, command)
                                    .build()
                                    .service(ORIGIN)
                                    .waitForActive(Duration.ofMillis(10), Duration.ofSeconds(5)))
                            .code(),
                    status);
        }

        QueueTransport activeInspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport activeCommand = new QueueTransport(aepResponse(200, "{\"status\":\"active\"}"));
        assertEquals(
                foundation.aep.core.AgentStatus.ACTIVE,
                agent(activeInspect, activeCommand)
                        .build()
                        .service(ORIGIN)
                        .waitForActive(Duration.ofMillis(10), Duration.ofSeconds(5))
                        .join()
                        .status());

        // A pending status with no remaining budget stops rather than polling forever.
        QueueTransport pendingInspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport pendingCommand = new QueueTransport(aepResponse(200, "{\"status\":\"pending\"}"));
        assertEquals(
                "poll_timeout",
                error(agent(pendingInspect, pendingCommand)
                                .build()
                                .service(ORIGIN)
                                .waitForActive(Duration.ofSeconds(30), Duration.ofSeconds(1)))
                        .code());
    }

    @Test
    void waitForActiveSurfacesACommandFailure() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport command =
                new QueueTransport(response(500, Map.of("Content-Type", List.of("text/plain")), "boom"));
        assertEquals(
                "command_failed",
                error(agent(inspect, command)
                                .build()
                                .service(ORIGIN)
                                .waitForActive(Duration.ofMillis(10), Duration.ofSeconds(5)))
                        .code());
    }

    @Test
    void inspectReportsFailureStatusesAndRedirectLimits() {
        QueueTransport oversizedHost = new QueueTransport(redirect("https://" + "a".repeat(64) + ".example/aep"));
        assertEquals(
                "cross_origin_redirect",
                error(agent(oversizedHost, new QueueTransport())
                                .build()
                                .service(ORIGIN)
                                .inspect())
                        .code());
        assertEquals(1, oversizedHost.requests.size());
        QueueTransport malformed = new QueueTransport(redirect("https://["));
        assertEquals(
                "invalid_redirect",
                error(agent(malformed, new QueueTransport())
                                .build()
                                .service(ORIGIN)
                                .inspect())
                        .code());
        assertEquals(1, malformed.requests.size());
        QueueTransport failing = new QueueTransport(aepResponse(503, ""));
        assertEquals(
                "inspect_failed",
                error(agent(failing, new QueueTransport())
                                .build()
                                .service(ORIGIN)
                                .inspect())
                        .code());

        QueueTransport looping =
                new QueueTransport(redirect("/one"), redirect("/two"), redirect("/three"), redirect("/four"));
        assertEquals(
                "too_many_redirects",
                error(agent(looping, new QueueTransport())
                                .maximumRedirects(2)
                                .build()
                                .service(ORIGIN)
                                .inspect())
                        .code());
    }

    @Test
    void inspectRefusesADocumentThatIsNotValid() {
        QueueTransport invalid = new QueueTransport(aepResponse(200, "{\"aep_version\":\"1.0\"}"));
        AepAgentException error = error(
                agent(invalid, new QueueTransport()).build().service(ORIGIN).inspect());
        assertEquals("document_invalid", error.code());
        assertTrue(error.getMessage().contains("$."), error.getMessage());
    }

    @Test
    void inspectAcceptsALoopbackServiceUnderTheOptIn() {
        String document = document(List.of("inspect")).replace(SERVICE_DID, "did:web:localhost%3A8080");
        QueueTransport inspect = new QueueTransport(aepResponse(200, document));
        AgentInspection inspection = agent(inspect, new QueueTransport())
                .allowInsecureLoopback(true)
                .build()
                .service(URI.create("http://localhost:8080"))
                .inspect()
                .join();
        assertEquals("did:web:localhost%3A8080", inspection.document().service().did());

        QueueTransport mismatch =
                new QueueTransport(aepResponse(200, document(List.of("inspect")).replace(SERVICE_DID, "did:key:z6Mk")));
        assertEquals(
                "service_identity_mismatch",
                error(agent(mismatch, new QueueTransport())
                                .allowInsecureLoopback(true)
                                .build()
                                .service(URI.create("http://localhost:8080"))
                                .inspect())
                        .code());
    }

    @Test
    void refusesAnIdempotencyKeyProviderThatReturnsNothing() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "enroll"))));
        assertEquals(
                "invalid_configuration",
                error(agent(inspect, new QueueTransport())
                                .idempotencyKeyProvider((did, command, discriminator) -> null)
                                .build()
                                .service(ORIGIN)
                                .enroll(ClaimValues.builder().build()))
                        .code());
    }

    @Test
    void refusesAJwtIdSupplierThatReturnsNothing() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        assertEquals(
                "invalid_configuration",
                error(agent(inspect, new QueueTransport())
                                .jwtIdSupplier(() -> "  ")
                                .build()
                                .service(ORIGIN)
                                .status())
                        .code());
    }

    @Test
    void rejectsInvalidCommandRequestsBeforeAnyNetworkCall() {
        AepServiceSession session =
                agent(new QueueTransport(), new QueueTransport()).build().service(ORIGIN);
        assertThrows(
                foundation.aep.core.AepValidationException.class,
                () -> session.grant(new GrantRequest("", null, null, null)));
        assertThrows(
                foundation.aep.core.AepValidationException.class,
                () -> session.revoke(new RevokeRequest(null, "c-1", null)));
    }

    @Test
    void builtInHandlersRejectMismatchedStoredCredentials() {
        AgentCredentialHandler apiKey = AgentCredentialHandlers.apiKey();
        assertThrows(
                IllegalArgumentException.class,
                () -> apiKey.parse(
                        SERVICE_DID,
                        "{\"api_key\":\"k\",\"credential_id\":\"c-1\","
                                + "\"expires_at\":\"not-a-date\",\"header\":\"x-api-key\"}"));
        String json = "{\"api_key\":\"k\",\"credential_id\":\"c-1\",\"expires_at\":\"2026-09-01T01:00:00Z\","
                + "\"header\":\"x-api-key\"}";
        AgentCredential wrongGrantType = new AgentCredential(SERVICE_DID, "oauth-bearer", "c-1", NOW, json);
        assertThrows(IllegalArgumentException.class, () -> apiKey.authorizationHeaders(wrongGrantType, null));
        AgentCredential wrongId =
                new AgentCredential(SERVICE_DID, "api-key", "c-9", Instant.parse("2026-09-01T01:00:00Z"), json);
        assertThrows(IllegalArgumentException.class, () -> apiKey.authorizationHeaders(wrongId, null));
        AgentCredential wrongExpiry = new AgentCredential(SERVICE_DID, "api-key", "c-1", NOW, json);
        assertThrows(IllegalArgumentException.class, () -> apiKey.authorizationHeaders(wrongExpiry, null));

        AgentCredential valid =
                new AgentCredential(SERVICE_DID, "api-key", "c-1", Instant.parse("2026-09-01T01:00:00Z"), json);
        assertEquals(Map.of("x-api-key", "k"), apiKey.authorizationHeaders(valid, null));
        assertEquals("api-key", apiKey.authenticationMethod());
        assertEquals(3, AgentCredentialHandlers.builtIn().size());

        String bearerJson = "{\"access_token\":\"t\",\"credential_id\":\"c-1\","
                + "\"expires_at\":\"2026-09-01T01:00:00Z\",\"token_type\":\"Bearer\"}";
        AgentCredential bearer = new AgentCredential(
                SERVICE_DID, "oauth-bearer", "c-1", Instant.parse("2026-09-01T01:00:00Z"), bearerJson);
        assertEquals(
                Map.of("Authorization", "Bearer t"),
                AgentCredentialHandlers.oauthBearer().authorizationHeaders(bearer, null));

        String basicJson = "{\"credential_id\":\"c-1\",\"expires_at\":\"2026-09-01T01:00:00Z\","
                + "\"password\":\"pw\",\"username\":\"user\"}";
        AgentCredential basic =
                new AgentCredential(SERVICE_DID, "basic", "c-1", Instant.parse("2026-09-01T01:00:00Z"), basicJson);
        assertEquals(
                Map.of("Authorization", "Basic dXNlcjpwdw=="),
                AgentCredentialHandlers.basic().authorizationHeaders(basic, null));
    }

    @Test
    void platformProviderRefusesSigningForAnotherIdentity() {
        QueueTransport transport = new QueueTransport(aepResponse(200, discovery()), aepResponse(200, activeList()));
        PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                .transport(transport)
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
        AgentIdentity identity = provider.getOrCreate(
                        URI.create("https://api.service.example"), "did:web:api.service.example")
                .toCompletableFuture()
                .join();

        ClientAssertionClaims foreign = new ClientAssertionClaims(
                "did:web:other.example",
                "did:web:other.example",
                "did:web:api.service.example",
                AssertionOperation.ENROLL,
                1_783_425_600L,
                1_783_425_900L,
                "jti-1",
                null);
        assertEquals(
                "platform_identity_mismatch",
                error(identity.signer().sign(foreign).toCompletableFuture()).code());
    }

    @Test
    void platformProviderRefusesAnUnboundServiceDidAndANonDid() {
        PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                .transport(request -> CompletableFuture.failedFuture(new AssertionError("unused")))
                .build();
        assertEquals(
                "service_identity_mismatch",
                error(provider.getOrCreate(URI.create("https://api.service.example"), "did:web:other.example")
                                .toCompletableFuture())
                        .code());
        assertThrows(
                IllegalArgumentException.class,
                () -> provider.getOrCreate(URI.create("https://api.service.example"), "not-a-did"));
        assertThrows(IllegalArgumentException.class, () -> provider.findIdentityByServiceDid("did:"));
    }

    @Test
    void platformProviderValidatesItsConfiguration() {
        assertThrows(NullPointerException.class, () -> PlatformIdentityProvider.builder(null));
        PlatformIdentityProvider.Builder builder = PlatformIdentityProvider.builder(PLATFORM);
        assertThrows(NullPointerException.class, () -> builder.transport(null));
        assertThrows(NullPointerException.class, () -> builder.authenticationHeaders(null));
        assertThrows(NullPointerException.class, () -> builder.idempotencyKeys(null));
        assertThrows(NullPointerException.class, () -> builder.platformContext(null));
        assertThrows(NullPointerException.class, () -> builder.pendingSignResolver(null));
        assertThrows(NullPointerException.class, () -> builder.clock(null));
        assertThrows(NullPointerException.class, PlatformIdentityProvider.builder(PLATFORM)::build);
        for (String value : List.of("", "  ", "Bearer a\rb", "Bearer a\nb")) {
            assertThrows(IllegalArgumentException.class, () -> builder.authorization(value), value);
        }
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
            assertThrows(IllegalArgumentException.class, () -> builder.defaultDiscoveryFreshness(invalid));
            assertThrows(IllegalArgumentException.class, () -> builder.requestTimeout(invalid));
        }
        assertThrows(NullPointerException.class, () -> builder.requestTimeout(null));
        assertThrows(IllegalArgumentException.class, () -> builder.maximumRedirects(-1));
        assertThrows(IllegalArgumentException.class, () -> builder.maximumResponseBytes(0));
        builder.maximumRedirects(1)
                .maximumResponseBytes(2048)
                .defaultDiscoveryFreshness(Duration.ofSeconds(30))
                .requestTimeout(Duration.ofSeconds(5))
                .allowInsecureLoopback(true)
                .authorization("Bearer token")
                .transport(request -> CompletableFuture.failedFuture(new AssertionError("unused")))
                .build();

        for (URI origin : List.of(
                URI.create("http://platform.example"),
                URI.create("https://user:pw@platform.example"),
                URI.create("https://platform.example/path"),
                URI.create("/relative"))) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> PlatformIdentityProvider.builder(origin)
                            .transport(request -> CompletableFuture.failedFuture(new AssertionError("unused")))
                            .build(),
                    origin.toString());
        }
    }

    @Test
    void platformProviderRefusesUnusableSuppliedHeaders() {
        for (Map<String, List<String>> headers : List.of(
                Map.of("X-Bad\r\nName", List.of("value")),
                Map.of(" ", List.of("value")),
                Map.<String, List<String>>of("X-Tenant", List.of()),
                Map.of("X-Tenant", List.of("bad\rvalue")))) {
            QueueTransport transport = new QueueTransport(aepResponse(200, discovery()));
            PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                    .transport(transport)
                    .authenticationHeaders(() -> CompletableFuture.completedFuture(headers))
                    .build();
            assertThrows(
                    CompletionException.class,
                    () -> provider.findIdentityByServiceDid("did:web:api.service.example")
                            .toCompletableFuture()
                            .join(),
                    headers.toString());
        }
    }

    @Test
    void platformProviderRefusesIdempotencyKeysThatCannotTravel() {
        for (String key : List.of(" key", "key ", "key\r\nX: 1", "")) {
            QueueTransport transport = new QueueTransport(aepResponse(200, discovery()), aepResponse(200, emptyList()));
            PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                    .transport(transport)
                    .idempotencyKeys(() -> key)
                    .build();
            assertEquals(
                    "platform_idempotency_key_invalid",
                    error(provider.getOrCreate(URI.create("https://api.service.example"), "did:web:api.service.example")
                                    .toCompletableFuture())
                            .code(),
                    key);
        }
    }

    @Test
    void platformProviderRefusesAnInvalidHostedIdentity() {
        String fragmentedKeyId = identity()
                .replace(
                        "\"key_id\":\"did:web:p.example:a:4Yf7p2xQd9\"",
                        "\"key_id\":\"did:web:p.example:a:4Yf7p2xQd9#key-1\"");
        String wrongDocumentUrl = identity()
                .replace("https://p.example/a/4Yf7p2xQd9/did.json", "https://elsewhere.example/a/4Yf7p2xQd9/did.json");
        String unadvertisedAlgorithm = identity().replace("[\"ES256\"]", "[\"EdDSA\"]");
        for (String body : List.of(fragmentedKeyId, wrongDocumentUrl, unadvertisedAlgorithm)) {
            QueueTransport transport = new QueueTransport(
                    aepResponse(200, discovery()),
                    aepResponse(200, "{\"count\":\"1\",\"data\":[" + body + "],\"total\":\"1\"}"));
            PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                    .transport(transport)
                    .build();
            assertEquals(
                    "platform_identity_invalid",
                    error(provider.findIdentityByServiceDid("did:web:api.service.example")
                                    .toCompletableFuture())
                            .code(),
                    body);
        }

        // A list whose totals disagree is not usable either.
        QueueTransport totals = new QueueTransport(
                aepResponse(200, discovery()),
                aepResponse(200, "{\"count\":\"1\",\"data\":[" + identity() + "],\"total\":\"0\"}"));
        assertThrows(
                CompletionException.class,
                () -> PlatformIdentityProvider.builder(PLATFORM)
                        .transport(totals)
                        .build()
                        .findIdentityByServiceDid("did:web:api.service.example")
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void platformProviderRefusesUnsafeDiscoveryRedirectsAndEndpoints() {
        for (String location : List.of(
                "https://[",
                "https://attacker.example/.well-known/aep-platform",
                "http://platform.example/.well-known/aep-platform",
                "https://user:pw@platform.example/x",
                "https://platform.example/x#fragment")) {
            QueueTransport transport = new QueueTransport(redirect(location));
            assertEquals(
                    "platform_discovery_redirect",
                    error(PlatformIdentityProvider.builder(PLATFORM)
                                    .transport(transport)
                                    .build()
                                    .findIdentityByServiceDid("did:web:api.service.example")
                                    .toCompletableFuture())
                            .code(),
                    location);
        }
        QueueTransport noLocation = new QueueTransport(response(302, Map.of(), ""));
        assertEquals(
                "platform_discovery_redirect",
                error(PlatformIdentityProvider.builder(PLATFORM)
                                .transport(noLocation)
                                .build()
                                .findIdentityByServiceDid("did:web:api.service.example")
                                .toCompletableFuture())
                        .code());

        QueueTransport limit = new QueueTransport(redirect("/one"), redirect("/two"));
        assertEquals(
                "platform_discovery_redirect",
                error(PlatformIdentityProvider.builder(PLATFORM)
                                .transport(limit)
                                .maximumRedirects(1)
                                .build()
                                .findIdentityByServiceDid("did:web:api.service.example")
                                .toCompletableFuture())
                        .code());

        // An advertised endpoint that is not an origin-relative path is refused. The shared document
        // validator rejects these first, so the provider's own endpoint check is the second line.
        for (String list : List.of("\"relative\"", "\"//attacker.example/x\"", "\"/x?y=1\"", "\"/x#y\"")) {
            QueueTransport transport = new QueueTransport(
                    aepResponse(200, discovery().replace("\"/v1/aep/agent-identities\",", list + ",")));
            CompletionException failure = assertThrows(
                    CompletionException.class,
                    () -> PlatformIdentityProvider.builder(PLATFORM)
                            .transport(transport)
                            .build()
                            .findIdentityByServiceDid("did:web:api.service.example")
                            .toCompletableFuture()
                            .join(),
                    list);
            assertTrue(
                    failure.getCause() instanceof foundation.aep.core.AepValidationException
                            || failure.getCause() instanceof AepAgentException,
                    list + " produced " + failure.getCause());
        }
    }

    @Test
    void platformProviderReportsDiscoveryAndCommandFailures() {
        QueueTransport failing = new QueueTransport(aepResponse(503, ""));
        assertEquals(
                "platform_discovery_failed",
                error(PlatformIdentityProvider.builder(PLATFORM)
                                .transport(failing)
                                .build()
                                .findIdentityByServiceDid("did:web:api.service.example")
                                .toCompletableFuture())
                        .code());

        QueueTransport notModified = new QueueTransport(response(304, Map.of(), ""));
        assertEquals(
                "platform_discovery_invalid",
                error(PlatformIdentityProvider.builder(PLATFORM)
                                .transport(notModified)
                                .build()
                                .findIdentityByServiceDid("did:web:api.service.example")
                                .toCompletableFuture())
                        .code());

        QueueTransport redirected = new QueueTransport(aepResponse(200, discovery()), redirect("/elsewhere"));
        assertEquals(
                "platform_command_redirect",
                error(PlatformIdentityProvider.builder(PLATFORM)
                                .transport(redirected)
                                .build()
                                .findIdentityByServiceDid("did:web:api.service.example")
                                .toCompletableFuture())
                        .code());

        QueueTransport problem = new QueueTransport(
                aepResponse(200, discovery()),
                response(
                        403,
                        Map.of("Content-Type", List.of(Aep.PROBLEM_MEDIA_TYPE)),
                        "{\"type\":\"urn:aep:error:not_recognized\",\"title\":\"Not recognized\","
                                + "\"status\":403,\"code\":\"not_recognized\"}"));
        assertEquals(
                "not_recognized",
                error(PlatformIdentityProvider.builder(PLATFORM)
                                .transport(problem)
                                .build()
                                .findIdentityByServiceDid("did:web:api.service.example")
                                .toCompletableFuture())
                        .code());
    }

    @Test
    void activeEnrollmentSkipsStatusButExplicitPendingStatusClearsIt() {
        QueueTransport inspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect", "enroll", "grant", "status"))));
        QueueTransport commands = new QueueTransport(
                aepResponse(200, "{\"status\":\"active\"}"),
                aepResponse(200, "{\"credential_id\":\"c-1\"}"),
                aepResponse(200, "{\"status\":\"pending\"}"),
                aepResponse(200, "{\"status\":\"pending\"}"));
        AepServiceSession session = agent(inspect, commands)
                .inspectCache(AgentInspectCache.inMemory())
                .build()
                .service(ORIGIN);
        session.enroll(ClaimValues.builder().build()).join();
        session.grant("custom-grant", List.of()).join();
        assertEquals("/aep/grant", commands.requests.get(1).uri().getPath());
        session.status().join();
        assertEquals(
                "enrollment_not_active",
                error(session.grant("custom-grant", List.of())).code());
        assertEquals(4, commands.requests.size());
    }

    @Test
    void customGrantRequiresAnIdentifierAndPreservesExtensionFields() {
        for (String json :
                List.of("{}", "{\"credential_id\":null}", "{\"credential_id\":1}", "{\"credential_id\":\"\"}")) {
            QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "grant"))));
            assertEquals(
                    "invalid_credential",
                    error(agent(inspect, new QueueTransport(aepResponse(200, json)))
                                    .build()
                                    .service(ORIGIN)
                                    .grant("custom-grant", List.of()))
                            .code());
        }
        String json = "{\"credential_id\":\"c-1\",\"custom_material\":{\"token\":\"value\"}}";
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "grant"))));
        assertEquals(
                json,
                agent(inspect, new QueueTransport(aepResponse(200, json)))
                        .build()
                        .service(ORIGIN)
                        .grant("custom-grant", List.of())
                        .join()
                        .responseJson());
    }

    @Test
    void handlerCannotReplaceTheServiceIssuedIdentifier() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "grant"))));
        AgentCredentialHandler changed = handler(
                "custom-session",
                "custom-grant",
                (serviceDid, json) -> new AgentCredential(serviceDid, "custom-grant", "different", null, json));
        assertEquals(
                "invalid_credential",
                error(agent(inspect, new QueueTransport(aepResponse(200, "{\"credential_id\":\"c-1\"}")))
                                .credentialHandler(changed)
                                .build()
                                .service(ORIGIN)
                                .grant("custom-grant", List.of()))
                        .code());
    }

    @Test
    void pollingDeadlineCompletesWhileStatusTransportIsStillPending() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        CompletableFuture<AepHttpTransport.Response> response = new CompletableFuture<>();
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        AepServiceSession session = agent(inspect, request -> {
                    calls.incrementAndGet();
                    return response;
                })
                .build()
                .service(ORIGIN);
        CompletableFuture<?> waiting = session.waitForActive(Duration.ofMillis(10), Duration.ofMillis(100));
        assertEquals(
                "poll_timeout",
                error(waiting.orTimeout(3, java.util.concurrent.TimeUnit.SECONDS))
                        .code());
        response.complete(aepResponse(200, "{\"status\":\"active\"}"));
        assertEquals("poll_timeout", error(waiting).code());
        assertEquals(1, calls.get());
    }

    @Test
    void cancellingPollingIgnoresALatePendingResponse() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        CompletableFuture<AepHttpTransport.Response> response = new CompletableFuture<>();
        AepServiceSession session = agent(inspect, request -> response).build().service(ORIGIN);
        CompletableFuture<?> waiting = session.waitForActive(Duration.ofMillis(10), Duration.ofSeconds(5));
        assertTrue(waiting.cancel(false));
        response.complete(aepResponse(200, "{\"status\":\"pending\"}"));
        assertTrue(waiting.isCancelled());
    }

    @Test
    void authenticationUsesTheAgentClockToSelectAnUnexpiredCredential() {
        AgentCredentialStore store = AgentCredentialStore.inMemory();
        store.save(new AgentCredential(SERVICE_DID, "custom-grant", "live", NOW.plusSeconds(60), "{}"))
                .toCompletableFuture()
                .join();
        store.save(new AgentCredential(SERVICE_DID, "custom-grant", "expired", NOW.minusSeconds(1), "{}"))
                .toCompletableFuture()
                .join();
        store.save(new AgentCredential(SERVICE_DID, "custom-grant", "at-expiry", NOW, "{}"))
                .toCompletableFuture()
                .join();
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("inspect"), "custom-grant", List.of("custom-session"))));
        AgentCredentialHandler selected = new AgentCredentialHandler() {
            public String authenticationMethod() {
                return "custom-session";
            }

            public String grantType() {
                return "custom-grant";
            }

            public AgentCredential parse(String serviceDid, String json) {
                throw new AssertionError("No Grant request");
            }

            public Map<String, String> authorizationHeaders(AgentCredential credential, URI resource) {
                return Map.of("X-Credential", credential.credentialId());
            }
        };
        AgentAuthentication authentication = agent(inspect, new QueueTransport())
                .credentialStore(store)
                .credentialHandler(selected)
                .build()
                .service(ORIGIN)
                .authenticate(ORIGIN.resolve("/private"))
                .join();
        assertEquals(List.of("live"), authentication.headers().get("X-Credential"));
        assertTrue(store.find(SERVICE_DID, "custom-grant", NOW.plusSeconds(60))
                .toCompletableFuture()
                .join()
                .isEmpty());
    }

    private static AepAgent.Builder agent(AepHttpTransport inspect, AepHttpTransport command) {
        AgentIdentity identity =
                new AgentIdentity("did:web:agent.example", claims -> CompletableFuture.completedFuture("signed"));
        return AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(command)
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(identity))
                .inspectCache(AgentInspectCache.none())
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .jwtIdSupplier(() -> "jwt-id");
    }

    private static String document(List<String> commands) {
        return document(commands, "custom-grant", List.of());
    }

    private static String document(List<String> commands, String grantType) {
        return document(commands, grantType, List.of());
    }

    private static String document(List<String> commands, String grantType, List<String> methods) {
        boolean grants = commands.contains("grant") || commands.contains("revoke");
        String grantTypes = grants ? "[\"" + grantType + "\"]" : "[]";
        String config = grants ? "{\"" + grantType + "\":{\"supports_per_credential_revoke\":\"true\"}}" : "{}";
        String authentication = methods.isEmpty()
                ? ""
                : "\"authentication\":{\"methods\":["
                        + methods.stream()
                                .map(value -> "\"" + value + "\"")
                                .collect(java.util.stream.Collectors.joining(","))
                        + "]},";
        return """
                {
                  "aep_version":"1.0",
                  %s
                  "bindings":{"supported":["http"]},
                  "commands":{"supported":%s,"grant_types":%s,"grant_types_config":%s},
                  "core":{"signing_algorithms":["EdDSA","ES256"]},
                  "http":{"endpoint_base":"/aep/"},
                  "identity":{"methods":["did:web"]},
                  "service":{"did":"did:web:service.example"}
                }
                """.formatted(
                        authentication,
                        commands.stream()
                                .map(value -> "\"" + value + "\"")
                                .collect(java.util.stream.Collectors.joining(",", "[", "]")),
                        grantTypes,
                        config);
    }

    private static String discovery() {
        return "{\"aep_version\":\"1.0\",\"endpoints\":{\"lifecycle\":\"/v1/aep/agent-identities/{agent_identity_id}\","
                + "\"list\":\"/v1/aep/agent-identities\",\"provision\":\"/v1/aep/agent-identities\","
                + "\"sign\":\"/v1/aep/agent-identities/{agent_identity_id}/sign\"},"
                + "\"http\":{\"endpoint_base\":\"/v1/aep\"},"
                + "\"identity\":{\"did_methods\":[\"did:web\"],"
                + "\"did_url_template\":\"https://p.example/a/{agent_did_id}/did.json\"},"
                + "\"platform\":{\"did\":\"did:web:p.example\",\"hosted_verification\":false,\"name\":\"Example\"},"
                + "\"signing\":{\"algorithms\":[\"ES256\"],\"default_lifetime_seconds\":\"300\"}}";
    }

    private static String identity() {
        return "{\"agent_did\":\"did:web:p.example:a:4Yf7p2xQd9\","
                + "\"agent_identity_id\":\"pai_1\",\"created_at\":\"2026-07-06T12:00:00Z\","
                + "\"did_document_url\":\"https://p.example/a/4Yf7p2xQd9/did.json\","
                + "\"key_id\":\"did:web:p.example:a:4Yf7p2xQd9\","
                + "\"service_did\":\"did:web:api.service.example\",\"signing_algorithms\":[\"ES256\"],"
                + "\"status\":\"active\",\"updated_at\":\"2026-07-06T12:00:00Z\"}";
    }

    private static String activeList() {
        return "{\"count\":\"1\",\"data\":[" + identity() + "],\"total\":\"1\"}";
    }

    private static String emptyList() {
        return "{\"count\":\"0\",\"data\":[],\"total\":\"0\"}";
    }

    private static AepHttpTransport.Response redirect(String location) {
        return response(302, Map.of("Location", List.of(location)), "");
    }

    private static AepHttpTransport.Response aepResponse(int status, String body) {
        return response(status, Map.of("Content-Type", List.of(Aep.MEDIA_TYPE)), body);
    }

    private static AepHttpTransport.Response response(int status, Map<String, List<String>> headers, String body) {
        return new AepHttpTransport.Response(status, headers, body.getBytes(StandardCharsets.UTF_8));
    }

    private static AepAgentException error(CompletableFuture<?> future) {
        CompletionException failure = assertThrows(CompletionException.class, future::join);
        return (AepAgentException) failure.getCause();
    }

    private interface Parser {
        AgentCredential parse(String serviceDid, String json);
    }

    private static AgentCredentialHandler handler(String method, String grantType, Parser parser) {
        return new AgentCredentialHandler() {
            @Override
            public String authenticationMethod() {
                return method;
            }

            @Override
            public String grantType() {
                return grantType;
            }

            @Override
            public AgentCredential parse(String serviceDid, String responseJson) {
                return parser == null
                        ? new AgentCredential(serviceDid, grantType, "c-1", NOW.plusSeconds(60), responseJson)
                        : parser.parse(serviceDid, responseJson);
            }

            @Override
            public Map<String, String> authorizationHeaders(AgentCredential credential, URI resource) {
                return Map.of("X-Credential", "value");
            }
        };
    }

    private static final class QueueTransport implements AepHttpTransport {
        private final Deque<Response> responses = new ArrayDeque<>();
        private final List<Request> requests = new ArrayList<>();

        QueueTransport(Response... values) {
            responses.addAll(List.of(values));
        }

        @Override
        public CompletableFuture<Response> execute(Request request) {
            requests.add(request);
            if (responses.isEmpty()) {
                return CompletableFuture.failedFuture(new AssertionError("Unexpected request: " + request));
            }
            return CompletableFuture.completedFuture(responses.removeFirst());
        }
    }

    private static final class MemoryStore implements AgentCredentialStore {
        private Optional<AgentCredential> saved = Optional.empty();

        @Override
        public CompletionStage<Optional<AgentCredential>> find(String serviceDid, String grantType, Instant now) {
            return CompletableFuture.completedFuture(
                    saved.filter(value -> value.grantType().equals(grantType)));
        }

        @Override
        public CompletionStage<Void> save(AgentCredential credential) {
            saved = Optional.of(credential);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<Void> delete(String serviceDid, String credentialId) {
            saved = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<Void> deleteGrantType(String serviceDid, String grantType) {
            saved = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<Void> deleteAll(String serviceDid) {
            saved = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }
    }
}
