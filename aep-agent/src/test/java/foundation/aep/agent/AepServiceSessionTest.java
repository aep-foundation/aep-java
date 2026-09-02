package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
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
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AepServiceSessionTest {
    private static final URI ORIGIN = URI.create("https://service.example");
    private static final String SERVICE_DID = "did:web:service.example";
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");

    @Test
    void inspectFollowsSameOriginRedirectAndCachesDocument() {
        QueueTransport inspect = new QueueTransport(
                response(302, Map.of("Location", List.of("/metadata/aep")), ""),
                aepResponse(200, document(List.of("inspect"), List.of(), List.of())));
        MemoryInspectCache cache = new MemoryInspectCache();
        AepServiceSession session = agent(inspect, request -> failedTransport())
                .inspectCache(cache)
                .build()
                .service(ORIGIN);

        AgentInspection first = session.inspect().join();
        AgentInspection second = session.inspect().join();

        assertEquals(URI.create("https://service.example/metadata/aep"), first.documentUri());
        assertEquals(first.documentUri(), second.documentUri());
        assertEquals(SERVICE_DID, second.document().service().did());
        assertEquals(2, inspect.requests.size());
        assertTrue(
                inspect.requests.stream().allMatch(request -> !request.headers().containsKey("Authorization")));
    }

    @Test
    void inspectRejectsCrossOriginRedirect() {
        QueueTransport inspect =
                new QueueTransport(response(302, Map.of("Location", List.of("https://attacker.example/aep")), ""));
        AepServiceSession session =
                agent(inspect, request -> failedTransport()).build().service(ORIGIN);

        AepAgentException error = agentError(session.inspect());

        assertEquals("cross_origin_redirect", error.code());
        assertEquals(1, inspect.requests.size());
    }

    @Test
    void enrollRejectsMissingRequiredClaimsBeforeCommandRequest() {
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("enroll", "inspect"), List.of(), List.of("contact.email"))));
        QueueTransport command = new QueueTransport();
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        AepAgentException error =
                agentError(session.enroll(ClaimValues.builder().build()));

        assertEquals("requirements_unmet", error.code());
        assertTrue(command.requests.isEmpty());
    }

    @Test
    void enrollUsesAssertionAndMatchingIdempotencyKey() {
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("enroll", "inspect"), List.of(), List.of("contact.email"))));
        QueueTransport command = new QueueTransport(aepResponse(200, "{\"status\":\"pending\"}"));
        List<ClientAssertionClaims> assertions = new ArrayList<>();
        AgentIdentity identity = new AgentIdentity("did:web:agent.example", claims -> {
            assertions.add(claims);
            return CompletableFuture.completedFuture("signed");
        });
        AepAgent configured = agent(inspect, command)
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(identity))
                .idempotencyKeyProvider((serviceDid, operation, discriminator) -> "stable-key")
                .build();

        AgentStatus status = configured
                .service(ORIGIN)
                .enroll(ClaimValues.builder().contactEmail("agent@example.com").build())
                .join()
                .status();

        AepHttpTransport.Request request = command.requests.get(0);
        assertEquals(AgentStatus.PENDING, status);
        assertEquals(List.of("AEP signed"), request.headers().get("Authorization"));
        assertEquals(List.of("stable-key"), request.headers().get("Idempotency-Key"));
        assertTrue(new String(request.body(), StandardCharsets.UTF_8).contains("\"idempotency_key\":\"stable-key\""));
        assertEquals("enroll", assertions.get(0).operation().value());
    }

    @Test
    void unadvertisedCommandDoesNotReachCommandTransport() {
        QueueTransport inspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect"), List.of(), List.of())));
        QueueTransport command = new QueueTransport();
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        AepAgentException error = agentError(session.status());

        assertEquals("command_not_advertised", error.code());
        assertTrue(command.requests.isEmpty());
    }

    @Test
    void authenticationDoesNotInferJwtWhenMethodsAreOmitted() {
        QueueTransport inspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect"), List.of(), List.of())));
        AepServiceSession session =
                agent(inspect, request -> failedTransport()).build().service(ORIGIN);

        AepAgentException error = agentError(session.authenticate(URI.create("https://service.example/private")));

        assertEquals("authentication_unavailable", error.code());
    }

    @Test
    void authenticationUsesAdvertisedMethodOrderAndNeverLeaksAcrossOrigins() {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200,
                document(List.of("inspect"), List.of("custom-session", Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        AgentCredential credential =
                new AgentCredential(SERVICE_DID, "custom-grant", "credential-1", NOW.plusSeconds(60), "{}");
        AepAgent configured = agent(inspect, request -> failedTransport())
                .credentialStore(store(credential))
                .credentialHandler(handler())
                .build();

        AgentAuthentication authentication = configured
                .service(ORIGIN)
                .authenticate(URI.create("https://service.example/private"))
                .join();
        AepAgentException crossOrigin =
                agentError(configured.service(ORIGIN).authenticate(URI.create("https://attacker.example/private")));

        assertEquals("custom-session", authentication.method());
        assertEquals(List.of("Secret value"), authentication.headers().get("X-Credential"));
        assertFalse(authentication.toString().contains("Secret value"));
        assertEquals("origin_mismatch", crossOrigin.code());
    }

    @Test
    void grantRequiresActiveEnrollmentAndPersistsParsedCredential() {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200,
                document(List.of("grant", "inspect", "status"), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        QueueTransport command = new QueueTransport(
                aepResponse(200, "{\"status\":\"active\"}"), aepResponse(200, "{\"credential_id\":\"credential-1\"}"));
        MemoryCredentialStore store = new MemoryCredentialStore();
        AepServiceSession session = agent(inspect, command)
                .credentialStore(store)
                .credentialHandler(handler())
                .build()
                .service(ORIGIN);

        AgentGrantResult result = session.grant("custom-grant", List.of("read")).join();

        assertEquals("credential-1", result.credential().orElseThrow().credentialId());
        assertEquals("credential-1", store.credential.orElseThrow().credentialId());
        assertEquals(2, command.requests.size());
    }

    @Test
    void revokeDeletesCredentialOnlyAfterSuccessfulResponse() {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of("inspect", "revoke"), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        QueueTransport command = new QueueTransport(aepResponse(200, "{}"));
        MemoryCredentialStore store = new MemoryCredentialStore();
        store.credential = Optional.of(new AgentCredential(SERVICE_DID, "custom-grant", "credential-1", null, "{}"));
        AepServiceSession session =
                agent(inspect, command).credentialStore(store).build().service(ORIGIN);

        session.revoke(RevokeRequest.grantType("custom-grant")).join();

        assertTrue(store.credential.isEmpty());
    }

    @Test
    void inMemoryStoreDeletesEveryCredentialForRevokedGrantType() {
        AgentCredentialStore store = AgentCredentialStore.inMemory();
        store.save(new AgentCredential(SERVICE_DID, "custom-grant", "credential-1", null, "{}"))
                .toCompletableFuture()
                .join();
        store.save(new AgentCredential(SERVICE_DID, "custom-grant", "credential-2", null, "{}"))
                .toCompletableFuture()
                .join();

        store.deleteGrantType(SERVICE_DID, "custom-grant").toCompletableFuture().join();

        assertTrue(store.find(SERVICE_DID, "custom-grant")
                .toCompletableFuture()
                .join()
                .isEmpty());
    }

    @Test
    void responseLimitIsEnforcedBeforeParsing() {
        QueueTransport inspect =
                new QueueTransport(aepResponse(200, document(List.of("inspect"), List.of(), List.of())));
        AepServiceSession session = agent(inspect, request -> failedTransport())
                .maximumResponseBytes(4)
                .build()
                .service(ORIGIN);

        AepAgentException error = agentError(session.inspect());

        assertEquals("response_too_large", error.code());
    }

    @Test
    void noStoreResponseIsNotRetained() {
        String json = document(List.of("inspect"), List.of(), List.of());
        AepHttpTransport.Response response = response(
                200, Map.of("Cache-Control", List.of("no-store"), "Content-Type", List.of(Aep.MEDIA_TYPE)), json);
        QueueTransport inspect = new QueueTransport(response, response);
        AepServiceSession session =
                agent(inspect, request -> failedTransport()).build().service(ORIGIN);

        session.inspect().join();
        session.inspect().join();

        assertEquals(2, inspect.requests.size());
    }

    @Test
    void staleRedirectedInspectionRevalidatesFinalDocumentUri() {
        String json = document(List.of("inspect"), List.of(), List.of());
        MemoryInspectCache cache = new MemoryInspectCache();
        cache.entry = Optional.of(new AgentInspectCache.Entry(
                URI.create("https://service.example/metadata/aep"), json, "etag-1", null, NOW.minusSeconds(1)));
        QueueTransport inspect = new QueueTransport(
                response(304, Map.of("Cache-Control", List.of("max-age=300"), "ETag", List.of("etag-1")), ""));

        agent(inspect, request -> failedTransport())
                .inspectCache(cache)
                .build()
                .service(ORIGIN)
                .inspect()
                .join();

        assertEquals(
                URI.create("https://service.example/metadata/aep"),
                inspect.requests.get(0).uri());
        assertEquals(List.of("etag-1"), inspect.requests.get(0).headers().get("If-None-Match"));
    }

    @Test
    void customGrantResponseMustBeAnObject() {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200,
                document(List.of("grant", "inspect", "status"), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        QueueTransport command =
                new QueueTransport(aepResponse(200, "{\"status\":\"active\"}"), aepResponse(200, "[]"));
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        CompletionException failure = assertThrows(
                CompletionException.class,
                () -> session.grant("custom-grant", List.of()).join());

        assertTrue(failure.getCause() instanceof foundation.aep.core.AepValidationException);
    }

    @Test
    void canceledStatusWaitDoesNotContinuePolling() throws InterruptedException {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of("inspect", "status"), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        AtomicInteger calls = new AtomicInteger();
        AepHttpTransport command = request -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(aepResponse(200, "{\"status\":\"pending\"}"));
        };
        CompletableFuture<?> wait = agent(inspect, command)
                .build()
                .service(ORIGIN)
                .waitForActive(Duration.ofMillis(100), Duration.ofSeconds(2));
        long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
        while (calls.get() == 0 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }

        assertEquals(1, calls.get());
        assertTrue(wait.cancel(true));
        Thread.sleep(250);
        assertEquals(1, calls.get());
    }

    private static AepAgent.Builder agent(AepHttpTransport inspect, AepHttpTransport command) {
        AgentIdentity identity =
                new AgentIdentity("did:web:agent.example", claims -> CompletableFuture.completedFuture("signed"));
        assertFalse(identity.toString().contains("signed"));
        return AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(command)
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(identity))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .jwtIdSupplier(() -> "jwt-id");
    }

    private static String document(List<String> commands, List<String> methods, List<String> requiredClaims) {
        String grantTypes = commands.contains("grant") || commands.contains("revoke") ? "[\"custom-grant\"]" : "[]";
        String grantTypesConfig =
                commands.contains("grant") ? "{\"custom-grant\":{\"supports_per_credential_revoke\":\"true\"}}" : "{}";
        String authentication = methods.isEmpty() ? "" : "\"authentication\":{\"methods\":" + array(methods) + "},";
        return """
                {
                  "aep_version":"1.0",
                  %s
                  "bindings":{"supported":["http"]},
                  "claims":{"required":%s,"preferred":[],"optional":[]},
                  "commands":{"supported":%s,"grant_types":%s,"grant_types_config":%s},
                  "core":{"signing_algorithms":["EdDSA","ES256"]},
                  "extensions":{"supported":[]},
                  "http":{"endpoint_base":"/aep/"},
                  "identity":{"methods":["did:web"]},
                  "service":{"did":"did:web:service.example"}
                }
                """.formatted(authentication, array(requiredClaims), array(commands), grantTypes, grantTypesConfig);
    }

    private static String array(List<String> values) {
        return values.stream()
                .map(value -> "\"" + value + "\"")
                .collect(java.util.stream.Collectors.joining(",", "[", "]"));
    }

    private static AepHttpTransport.Response aepResponse(int status, String body) {
        return response(status, Map.of("Content-Type", List.of(Aep.MEDIA_TYPE)), body);
    }

    private static AepHttpTransport.Response response(int status, Map<String, List<String>> headers, String body) {
        return new AepHttpTransport.Response(status, headers, body.getBytes(StandardCharsets.UTF_8));
    }

    private static CompletableFuture<AepHttpTransport.Response> failedTransport() {
        return CompletableFuture.failedFuture(new AssertionError("Transport must not be called"));
    }

    private static AepAgentException agentError(CompletableFuture<?> future) {
        CompletionException failure = assertThrows(CompletionException.class, future::join);
        return (AepAgentException) failure.getCause();
    }

    private static AgentCredentialHandler handler() {
        return new AgentCredentialHandler() {
            @Override
            public String authenticationMethod() {
                return "custom-session";
            }

            @Override
            public String grantType() {
                return "custom-grant";
            }

            @Override
            public AgentCredential parse(String serviceDid, String responseJson) {
                return new AgentCredential(serviceDid, grantType(), "credential-1", NOW.plusSeconds(60), responseJson);
            }

            @Override
            public Map<String, String> authorizationHeaders(AgentCredential credential, URI resource) {
                return Map.of("X-Credential", "Secret value");
            }
        };
    }

    private static AgentCredentialStore store(AgentCredential credential) {
        MemoryCredentialStore store = new MemoryCredentialStore();
        store.credential = Optional.of(credential);
        return store;
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

    private static final class MemoryInspectCache implements AgentInspectCache {
        private Optional<Entry> entry = Optional.empty();

        @Override
        public CompletableFuture<Optional<Entry>> get(URI origin) {
            return CompletableFuture.completedFuture(entry);
        }

        @Override
        public CompletableFuture<Void> put(URI origin, Entry value) {
            entry = Optional.of(value);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> delete(URI origin) {
            entry = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }
    }

    private static final class MemoryCredentialStore implements AgentCredentialStore {
        private Optional<AgentCredential> credential = Optional.empty();

        @Override
        public CompletableFuture<Optional<AgentCredential>> find(String serviceDid, String grantType) {
            return CompletableFuture.completedFuture(
                    credential.filter(value -> value.grantType().equals(grantType)));
        }

        @Override
        public CompletableFuture<Void> save(AgentCredential value) {
            credential = Optional.of(value);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> delete(String serviceDid, String credentialId) {
            credential = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> deleteGrantType(String serviceDid, String grantType) {
            credential = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> deleteAll(String serviceDid) {
            credential = Optional.empty();
            return CompletableFuture.completedFuture(null);
        }
    }
}
