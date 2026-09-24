package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.RevokeRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
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
import org.junit.jupiter.api.Test;

/** Spec-grounded Agent behaviour across Inspect, the commands, and protected-resource use. */
class AgentConformanceTest {
    private static final URI ORIGIN = URI.create("https://service.example");
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");

    /**
     * CORE-RVK-002: an Agent names only a Grant Type the Service advertises. Revoke checked the
     * per-credential configuration but never the advertisement itself, so a request for an
     * unadvertised type spent a signature on something the Service was always going to refuse.
     */
    @Test
    void revokeRefusesAnUnadvertisedGrantType() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "revoke"))));
        QueueTransport command = new QueueTransport();
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        AepAgentException error = agentError(session.revoke(new RevokeRequest("absent-grant", null, null)));

        assertEquals("grant_type_not_advertised", error.code());
        assertTrue(command.requests.isEmpty(), "no assertion is spent on a refused Grant Type");
    }

    @Test
    void revokeAcceptsAnAdvertisedGrantTypeAndTheAllGrantTypesForm() {
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("inspect", "revoke"))),
                aepResponse(200, document(List.of("inspect", "revoke"))));
        QueueTransport command = new QueueTransport(aepResponse(200, "{}"), aepResponse(200, "{}"));
        AepAgent configured = agent(inspect, command).build();

        configured
                .service(ORIGIN)
                .revoke(new RevokeRequest("custom-grant", null, null))
                .join();
        configured.service(ORIGIN).revoke(new RevokeRequest(null, null, "true")).join();

        assertEquals(2, command.requests.size());
        // CORE-RVK-006: all_grant_types carries no grant type to check against the advertisement.
        assertEquals("POST", command.requests.get(1).method());
    }

    /** CORE-INS-011: per-credential Revoke is used only where the configuration advertises it. */
    @Test
    void revokeRefusesAnUnadvertisedPerCredentialForm() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, documentWithoutPerCredentialRevoke()));
        QueueTransport command = new QueueTransport();
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        AepAgentException error = agentError(session.revoke(new RevokeRequest("custom-grant", "credential-1", null)));

        assertEquals("per_credential_revoke_unavailable", error.code());
        assertTrue(command.requests.isEmpty());
    }

    /**
     * CORE-IDP-001 and CORE-IDP-002: the key the Agent records has to be the key the Service sees.
     * A provider value with surrounding whitespace is stripped in transit, and one carrying a
     * control character is not a field value at all.
     */
    @Test
    void refusesIdempotencyKeysThatCannotSurviveAsAFieldValue() {
        for (String key : List.of(" key", "key ", "\tkey", "key\r\nX-Injected: 1", "key\u0000", "")) {
            QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "enroll"))));
            QueueTransport command = new QueueTransport();
            AepServiceSession session = agent(inspect, command)
                    .idempotencyKeyProvider((serviceDid, operation, discriminator) -> key)
                    .build()
                    .service(ORIGIN);

            AepAgentException error =
                    agentError(session.enroll(ClaimValues.builder().build()));

            assertEquals("invalid_configuration", error.code(), key);
            assertTrue(command.requests.isEmpty(), key);
        }
    }

    /** CORE-IDP-009: the header and the Enroll body carry the same key. */
    @Test
    void sendsOneIdempotencyKeyInBothTheHeaderAndTheEnrollBody() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "enroll"))));
        QueueTransport command = new QueueTransport(aepResponse(200, "{\"status\":\"active\"}"));
        agent(inspect, command)
                .idempotencyKeyProvider((serviceDid, operation, discriminator) -> "enroll-key")
                .build()
                .service(ORIGIN)
                .enroll(ClaimValues.builder().build())
                .join();

        AepHttpTransport.Request request = command.requests.get(0);
        assertEquals(List.of("enroll-key"), request.headers().get("Idempotency-Key"));
        assertTrue(new String(request.body(), StandardCharsets.UTF_8).contains("\"idempotency_key\":\"enroll-key\""));
    }

    /** CORE-CA-001: Inspect is unauthenticated and carries no assertion. */
    @Test
    void doesNotAuthenticateInspect() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect"))));
        agent(inspect, new QueueTransport()).build().service(ORIGIN).inspect().join();

        AepHttpTransport.Request request = inspect.requests.get(0);
        assertFalse(request.headers().containsKey("Authorization"));
        assertFalse(request.headers().containsKey(Aep.AUTHORIZATION_HEADER));
        assertFalse(request.headers().containsKey("Idempotency-Key"));
        assertEquals(List.of(Aep.MEDIA_TYPE), request.headers().get("Accept"));
    }

    /**
     * CORE-AUTH-005: the challenged Service DID must match the fetched document, which for did:web
     * means the DID has to bind the origin the document came from.
     */
    @Test
    void refusesADocumentWhoseServiceDidDoesNotBindTheOrigin() {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of("inspect")).replace("did:web:service.example", "did:web:other.example")));
        AepServiceSession session = agent(inspect, new QueueTransport()).build().service(ORIGIN);

        assertEquals("service_identity_mismatch", agentError(session.inspect()).code());
    }

    @Test
    void refusesUnsupportedServiceDidBeforeRequestingIdentity() {
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("inspect")).replace("did:web:service.example", "did:key:example")));
        AepServiceSession session = agent(inspect, new QueueTransport())
                .identityProvider((origin, did) -> {
                    throw new AssertionError("Identity must not be requested");
                })
                .build()
                .service(ORIGIN);
        assertEquals("service_identity_mismatch", agentError(session.inspect()).code());
    }

    /** CORE-PR-031: AEP credentials never cross an origin boundary. */
    @Test
    void refusesToAuthenticateAgainstAnotherOrigin() {
        AepServiceSession session =
                agent(new QueueTransport(), new QueueTransport()).build().service(ORIGIN);

        for (URI resource : List.of(
                URI.create("https://attacker.example/private"),
                URI.create("http://service.example/private"),
                URI.create("https://service.example:8443/private"))) {
            assertEquals(
                    "origin_mismatch",
                    agentError(session.authenticate(resource)).code(),
                    resource.toString());
        }
    }

    /** CORE-PR-001: an authenticate assertion binds to the exact protected-resource target. */
    @Test
    void bindsTheAuthenticateAssertionToTheRequestedResource() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect"), List.of("aep-jwt"))));
        List<foundation.aep.core.ClientAssertionClaims> signed = new ArrayList<>();
        AgentIdentity identity = new AgentIdentity("did:web:agent.example", claims -> {
            signed.add(claims);
            return CompletableFuture.completedFuture("assertion");
        });
        AgentAuthentication authentication = AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(new QueueTransport())
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(identity))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .jwtIdSupplier(() -> "jwt-id")
                .build()
                .service(ORIGIN)
                .authenticate(URI.create("https://service.example/private?q=1"))
                .join();

        assertEquals(Aep.AUTHENTICATION_METHOD_JWT, authentication.method());
        assertEquals(List.of("AEP assertion"), authentication.headers().get("Authorization"));
        assertEquals(
                foundation.aep.core.AssertionOperation.AUTHENTICATE,
                signed.get(0).operation());
        assertEquals("https://service.example/private?q=1", signed.get(0).resource());
        assertEquals("did:web:service.example", signed.get(0).audience());
    }

    /** CORE-PR-038: with no advertised method the Agent has nothing to present. */
    @Test
    void reportsWhenNoAdvertisedAuthenticationMethodIsAvailable() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect"))));
        AepServiceSession session = agent(inspect, new QueueTransport()).build().service(ORIGIN);

        assertEquals(
                "authentication_unavailable",
                agentError(session.authenticate(URI.create("https://service.example/private")))
                        .code());
    }

    /**
     * CORE-DISC-014: `no-cache` requires revalidation. Cache-Control directives are unordered, so
     * the directive that forbids reuse has to win wherever it appears in the field value.
     */
    @Test
    void revalidatesWhenNoCacheAccompaniesAFreshnessLifetime() {
        String body = document(List.of("inspect"));
        QueueTransport inspect = new QueueTransport(
                response(
                        200,
                        Map.of(
                                "Content-Type", List.of(Aep.MEDIA_TYPE),
                                "Cache-Control", List.of("max-age=600, no-cache"),
                                "ETag", List.of("\"v1\"")),
                        body),
                response(
                        200,
                        Map.of("Content-Type", List.of(Aep.MEDIA_TYPE), "Cache-Control", List.of("max-age=600")),
                        body));
        MemoryInspectCache cache = new MemoryInspectCache();
        AepAgent configured =
                agent(inspect, new QueueTransport()).inspectCache(cache).build();

        configured.service(ORIGIN).inspect().join();
        configured.service(ORIGIN).inspect().join();

        assertEquals(2, inspect.requests.size(), "no-cache must force revalidation");
        assertEquals(List.of("\"v1\""), inspect.requests.get(1).headers().get("If-None-Match"));

        // A plain max-age is reused without a second request.
        configured.service(ORIGIN).inspect().join();
        assertEquals(2, inspect.requests.size());
    }

    /** CORE-DISC: `no-store` prohibits persistence beyond the current fetch. */
    @Test
    void doesNotPersistANoStoreDocument() {
        String body = document(List.of("inspect"));
        QueueTransport inspect = new QueueTransport(
                response(
                        200,
                        Map.of("Content-Type", List.of(Aep.MEDIA_TYPE), "Cache-Control", List.of("no-store")),
                        body),
                aepResponse(200, body));
        MemoryInspectCache cache = new MemoryInspectCache();
        AepAgent configured =
                agent(inspect, new QueueTransport()).inspectCache(cache).build();

        configured.service(ORIGIN).inspect().join();
        assertTrue(cache.entry.isEmpty(), "a no-store document is not persisted");
        configured.service(ORIGIN).inspect().join();
        assertEquals(2, inspect.requests.size());
    }

    /** CORE-DISC-013: a 304 refreshes the validators without refetching the body. */
    @Test
    void reusesACachedDocumentOnNotModified() {
        String body = document(List.of("inspect"));
        QueueTransport inspect = new QueueTransport(
                response(
                        200,
                        Map.of(
                                "Content-Type", List.of(Aep.MEDIA_TYPE),
                                "Cache-Control", List.of("max-age=0"),
                                "ETag", List.of("\"v1\""),
                                "Last-Modified", List.of("Mon, 01 Sep 2026 00:00:00 GMT")),
                        body),
                response(304, Map.of("ETag", List.of("\"v2\""), "Cache-Control", List.of("max-age=600")), ""));
        MemoryInspectCache cache = new MemoryInspectCache();
        AepAgent configured =
                agent(inspect, new QueueTransport()).inspectCache(cache).build();

        configured.service(ORIGIN).inspect().join();
        AgentInspection second = configured.service(ORIGIN).inspect().join();

        assertEquals("did:web:service.example", second.document().service().did());
        AepHttpTransport.Request revalidation = inspect.requests.get(1);
        assertEquals(List.of("\"v1\""), revalidation.headers().get("If-None-Match"));
        assertEquals(
                List.of("Mon, 01 Sep 2026 00:00:00 GMT"), revalidation.headers().get("If-Modified-Since"));
        assertEquals("\"v2\"", cache.entry.orElseThrow().etag());
    }

    /** CORE-DISC-017: Inspect redirects stay on the origin and never carry user information. */
    @Test
    void refusesUnsafeInspectRedirects() {
        for (String location : List.of(
                "https://attacker.example/aep",
                "http://service.example/aep",
                "https://user:secret@service.example/aep",
                "https://service.example/aep#fragment")) {
            QueueTransport inspect = new QueueTransport(response(302, Map.of("Location", List.of(location)), ""));
            AepServiceSession session =
                    agent(inspect, new QueueTransport()).build().service(ORIGIN);
            String code = agentError(session.inspect()).code();
            assertTrue(
                    "cross_origin_redirect".equals(code) || "invalid_redirect".equals(code),
                    location + " produced " + code);
        }
        QueueTransport noLocation = new QueueTransport(response(302, Map.of(), ""));
        assertEquals(
                "invalid_redirect",
                agentError(agent(noLocation, new QueueTransport())
                                .build()
                                .service(ORIGIN)
                                .inspect())
                        .code());
    }

    /** CORE-PR-033: a command endpoint never follows a redirect. */
    @Test
    void refusesToFollowACommandRedirect() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport command = new QueueTransport(response(302, Map.of("Location", List.of("/elsewhere")), ""));
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        assertEquals("command_redirect", agentError(session.status()).code());
        assertEquals(1, command.requests.size());
    }

    /** CORE-ERR-001: a Problem Details body becomes the reported failure. */
    @Test
    void surfacesProblemDetailsFromACommandFailure() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport command = new QueueTransport(response(
                403,
                Map.of("Content-Type", List.of(Aep.PROBLEM_MEDIA_TYPE)),
                "{\"type\":\"urn:aep:error:verification_pending\",\"title\":\"Verification pending\","
                        + "\"status\":403,\"code\":\"verification_pending\"}"));
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        AepAgentException error = agentError(session.status());
        assertEquals("verification_pending", error.code());
        assertEquals(403, error.status());
    }

    /** A failure body that is not Problem Details still fails, without inventing a code. */
    @Test
    void reportsANonProblemCommandFailure() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport command =
                new QueueTransport(response(500, Map.of("Content-Type", List.of("text/plain")), "boom"));
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        AepAgentException error = agentError(session.status());
        assertEquals("command_failed", error.code());
        assertEquals(500, error.status());
    }

    /** A command endpoint answers in the AEP media type or not at all. */
    @Test
    void requiresTheAepMediaTypeOnSuccessfulResponses() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect", "status"))));
        QueueTransport command =
                new QueueTransport(response(200, Map.of("Content-Type", List.of("application/json")), "{}"));
        AepServiceSession session = agent(inspect, command).build().service(ORIGIN);

        assertEquals("invalid_media_type", agentError(session.status()).code());
    }

    /** A Service that does not advertise a command never receives it. */
    @Test
    void refusesCommandsTheServiceDoesNotAdvertise() {
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of("inspect"))),
                aepResponse(200, document(List.of("inspect"))),
                aepResponse(200, document(List.of("inspect"))));
        QueueTransport command = new QueueTransport();
        AepAgent configured = agent(inspect, command).build();

        assertEquals(
                "command_not_advertised",
                agentError(configured.service(ORIGIN).status()).code());
        assertEquals(
                "command_not_advertised",
                agentError(configured
                                .service(ORIGIN)
                                .enroll(ClaimValues.builder().build()))
                        .code());
        assertEquals(
                "command_not_advertised",
                agentError(configured.service(ORIGIN).revoke(new RevokeRequest(null, null, "true")))
                        .code());
        assertTrue(command.requests.isEmpty());
    }

    /** A response larger than the configured bound is refused before it is parsed. */
    @Test
    void refusesAnOversizedResponse() {
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of("inspect"))));
        AepServiceSession session = agent(inspect, new QueueTransport())
                .maximumResponseBytes(8)
                .build()
                .service(ORIGIN);

        assertEquals("response_too_large", agentError(session.inspect()).code());
    }

    private static AepAgent.Builder agent(AepHttpTransport inspect, AepHttpTransport command) {
        AgentIdentity identity =
                new AgentIdentity("did:web:agent.example", claims -> CompletableFuture.completedFuture("signed"));
        return AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(command)
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(identity))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .jwtIdSupplier(() -> "jwt-id");
    }

    private static String document(List<String> commands) {
        return document(commands, List.of());
    }

    private static String document(List<String> commands, List<String> methods) {
        boolean grants = commands.contains("grant") || commands.contains("revoke");
        String grantTypes = grants ? "[\"custom-grant\"]" : "[]";
        String grantTypesConfig = grants ? "{\"custom-grant\":{\"supports_per_credential_revoke\":\"true\"}}" : "{}";
        String authentication = methods.isEmpty() ? "" : "\"authentication\":{\"methods\":" + array(methods) + "},";
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
                """.formatted(authentication, array(commands), grantTypes, grantTypesConfig);
    }

    private static String documentWithoutPerCredentialRevoke() {
        return """
                {
                  "aep_version":"1.0",
                  "bindings":{"supported":["http"]},
                  "commands":{"supported":["inspect","revoke"],"grant_types":["custom-grant"],
                    "grant_types_config":{"custom-grant":{"supports_per_credential_revoke":"false"}}},
                  "core":{"signing_algorithms":["EdDSA","ES256"]},
                  "http":{"endpoint_base":"/aep/"},
                  "identity":{"methods":["did:web"]},
                  "service":{"did":"did:web:service.example"}
                }
                """;
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

    private static AepAgentException agentError(CompletableFuture<?> future) {
        CompletionException failure = assertThrows(CompletionException.class, future::join);
        return (AepAgentException) failure.getCause();
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
}
