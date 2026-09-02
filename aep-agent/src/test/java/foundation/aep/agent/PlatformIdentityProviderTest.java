package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PlatformIdentityProviderTest {
    private static final URI PLATFORM = URI.create("https://platform.example");
    private static final URI SERVICE = URI.create("https://api.service.example");
    private static final String SERVICE_DID = "did:web:api.service.example";
    private static final String AGENT_DID = "did:web:p.example:a:4Yf7p2xQd9";
    private static final String IDENTITY_ID = "pai_01J0AEPPLATFORM000000000001";

    @Test
    void provisionsAndDelegatesSigningThroughTheAdvertisedEndpoints() {
        QueueTransport transport = new QueueTransport(
                aepResponse(200, discovery()),
                aepResponse(200, identityList()),
                aepResponse(200, identity()),
                aepResponse(200, completedSign()));
        PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                .transport(transport)
                .authorization("Bearer stale")
                .authenticationHeaders(() -> CompletableFuture.completedFuture(Map.of(
                        "Accept",
                        List.of("text/plain"),
                        "Authorization",
                        List.of("Bearer current"),
                        "X-Platform-Tenant",
                        List.of("tenant-1"))))
                .idempotencyKeys(new Sequence("provision-key", "sign-key"))
                .platformContext((identity, claims) ->
                        CompletableFuture.completedFuture(Map.of("authorization_handle", "opaque-value")))
                .build();

        AgentIdentity identity =
                provider.getOrCreate(SERVICE, SERVICE_DID).toCompletableFuture().join();
        String assertion =
                identity.signer().sign(claims()).toCompletableFuture().join();

        assertEquals(AGENT_DID, identity.did());
        assertEquals("client-assertion", assertion);
        assertEquals(4, transport.requests.size());
        assertEquals(
                URI.create("https://platform.example/.well-known/aep-platform"),
                transport.requests.get(0).uri());
        assertFalse(transport.requests.get(0).headers().containsKey("Authorization"));
        assertEquals(
                URI.create(
                        "https://platform.example/v1/aep/agent-identities?descending=true&limit=100&service_did=did%3Aweb%3Aapi.service.example"),
                transport.requests.get(1).uri());
        assertEquals(
                List.of("Bearer current"), transport.requests.get(2).headers().get("Authorization"));
        assertEquals(
                1,
                transport.requests.get(2).headers().keySet().stream()
                        .filter(name -> name.equalsIgnoreCase("Authorization"))
                        .count());
        assertEquals(
                List.of(Aep.MEDIA_TYPE), transport.requests.get(2).headers().get("Accept"));
        assertEquals(
                List.of("provision-key"), transport.requests.get(2).headers().get("Idempotency-Key"));
        assertTrue(body(transport.requests.get(3)).contains("\"authorization_handle\":\"opaque-value\""));
        assertEquals(List.of("sign-key"), transport.requests.get(3).headers().get("Idempotency-Key"));
    }

    @Test
    void reusesAnActiveIdentityWithoutProvisioning() {
        QueueTransport transport = new QueueTransport(aepResponse(200, discovery()), aepResponse(200, activeList()));
        PlatformIdentityProvider provider = provider(transport);

        AgentIdentity identity =
                provider.getOrCreate(SERVICE, SERVICE_DID).toCompletableFuture().join();

        assertEquals(AGENT_DID, identity.did());
        assertEquals(2, transport.requests.size());
    }

    @Test
    void resolvesPendingSigningWithDistinctStageKeysAndOpaqueContext() {
        QueueTransport transport = new QueueTransport(
                aepResponse(200, discovery()),
                aepResponse(200, activeList()),
                aepResponse(202, pendingSign()),
                aepResponse(200, completedSign()));
        List<PlatformPendingSign> pending = new ArrayList<>();
        PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                .transport(transport)
                .idempotencyKeys(new Sequence("sign-stage-1", "sign-stage-2"))
                .pendingSignResolver(value -> {
                    pending.add(value);
                    return CompletableFuture.completedFuture(Map.of("authorization_handle", "approved"));
                })
                .build();

        AgentIdentity identity =
                provider.getOrCreate(SERVICE, SERVICE_DID).toCompletableFuture().join();
        String assertion =
                identity.signer().sign(claims()).toCompletableFuture().join();

        assertEquals("client-assertion", assertion);
        assertEquals(5, pending.get(0).retryAfterSeconds());
        assertEquals("pending-value", pending.get(0).platformContext().get("authorization_handle"));
        assertEquals(
                List.of("sign-stage-1"), transport.requests.get(2).headers().get("Idempotency-Key"));
        assertEquals(
                List.of("sign-stage-2"), transport.requests.get(3).headers().get("Idempotency-Key"));
        assertTrue(body(transport.requests.get(3)).contains("\"authorization_handle\":\"approved\""));
    }

    @Test
    void returnsPendingResultWhenTheApplicationHasNoResolver() {
        QueueTransport transport = new QueueTransport(
                aepResponse(200, discovery()), aepResponse(200, activeList()), aepResponse(202, pendingSign()));
        AgentIdentity identity = provider(transport)
                .getOrCreate(SERVICE, SERVICE_DID)
                .toCompletableFuture()
                .join();

        CompletionException failure = assertThrows(
                CompletionException.class,
                () -> identity.signer().sign(claims()).toCompletableFuture().join());
        PlatformSignPendingException pending = assertInstanceOf(PlatformSignPendingException.class, failure.getCause());

        assertEquals(5, pending.pending().retryAfterSeconds());
    }

    @Test
    void revalidatesExpiredDiscoveryAtItsFinalRedirectTarget() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-06T12:00:00Z"));
        QueueTransport transport = new QueueTransport(
                redirect("/metadata/aep-platform"),
                aepResponse(
                        200,
                        Map.of("Cache-Control", List.of("max-age=1"), "ETag", List.of("discovery-1")),
                        discovery()),
                aepResponse(200, identityList()),
                response(304, Map.of("Cache-Control", List.of("max-age=300")), ""),
                aepResponse(200, identityList()));
        PlatformIdentityProvider provider = PlatformIdentityProvider.builder(PLATFORM)
                .transport(transport)
                .clock(clock)
                .build();

        provider.findIdentityByServiceDid(SERVICE_DID).toCompletableFuture().join();
        clock.now = clock.now.plusSeconds(2);
        provider.findIdentityByServiceDid(SERVICE_DID).toCompletableFuture().join();

        assertEquals(
                URI.create("https://platform.example/metadata/aep-platform"),
                transport.requests.get(3).uri());
        assertEquals(List.of("discovery-1"), transport.requests.get(3).headers().get("If-None-Match"));
    }

    @Test
    void rejectsCrossOriginDiscoveryRedirectsAndMismatchedSignResponses() {
        PlatformIdentityProvider redirecting =
                provider(new QueueTransport(redirect("https://attacker.example/.well-known/aep-platform")));
        CompletionException redirectFailure = assertThrows(
                CompletionException.class,
                () -> redirecting
                        .findIdentityByServiceDid(SERVICE_DID)
                        .toCompletableFuture()
                        .join());
        assertEquals("platform_discovery_redirect", ((AepAgentException) redirectFailure.getCause()).code());

        PlatformIdentityProvider malformed = provider(new QueueTransport(redirect("https:/missing-host")));
        CompletionException malformedFailure = assertThrows(
                CompletionException.class,
                () -> malformed
                        .findIdentityByServiceDid(SERVICE_DID)
                        .toCompletableFuture()
                        .join());
        assertEquals("platform_discovery_redirect", ((AepAgentException) malformedFailure.getCause()).code());

        QueueTransport transport = new QueueTransport(
                aepResponse(200, discovery()),
                aepResponse(200, activeList()),
                aepResponse(200, completedSign().replace(SERVICE_DID, "did:web:other.example")));
        AgentIdentity identity = provider(transport)
                .getOrCreate(SERVICE, SERVICE_DID)
                .toCompletableFuture()
                .join();
        CompletionException signFailure = assertThrows(
                CompletionException.class,
                () -> identity.signer().sign(claims()).toCompletableFuture().join());
        assertEquals("platform_sign_invalid", ((AepAgentException) signFailure.getCause()).code());
    }

    @Test
    void noStoreDiscoveryIsFetchedForEveryOperation() {
        QueueTransport transport = new QueueTransport(
                aepResponse(200, Map.of("Cache-Control", List.of("no-store")), discovery()),
                aepResponse(200, identityList()),
                aepResponse(200, Map.of("Cache-Control", List.of("no-store")), discovery()),
                aepResponse(200, identityList()));
        PlatformIdentityProvider provider = provider(transport);

        provider.findIdentityByServiceDid(SERVICE_DID).toCompletableFuture().join();
        provider.findIdentityByServiceDid(SERVICE_DID).toCompletableFuture().join();

        assertEquals(4, transport.requests.size());
        assertEquals(
                Aep.PLATFORM_WELL_KNOWN_PATH, transport.requests.get(2).uri().getPath());
    }

    @Test
    void sharesAnInFlightDiscoveryRequestAcrossConcurrentOperations() {
        CompletableFuture<AepHttpTransport.Response> discoveryResponse = new CompletableFuture<>();
        AtomicInteger discoveryRequests = new AtomicInteger();
        AtomicInteger listRequests = new AtomicInteger();
        AepHttpTransport transport = request -> {
            if (Aep.PLATFORM_WELL_KNOWN_PATH.equals(request.uri().getPath())) {
                discoveryRequests.incrementAndGet();
                return discoveryResponse;
            }
            listRequests.incrementAndGet();
            return CompletableFuture.completedFuture(aepResponse(200, identityList()));
        };
        PlatformIdentityProvider provider = provider(transport);

        CompletableFuture<?> first =
                provider.findIdentityByServiceDid(SERVICE_DID).toCompletableFuture();
        CompletableFuture<?> second =
                provider.findIdentityByServiceDid(SERVICE_DID).toCompletableFuture();

        assertEquals(1, discoveryRequests.get());
        discoveryResponse.complete(aepResponse(200, discovery()));
        CompletableFuture.allOf(first, second).join();
        assertEquals(2, listRequests.get());
    }

    @Test
    void acceptsNormativeHttpsDidDocumentsFromALoopbackPlatform() {
        String loopbackDid = "did:web:127.0.0.1%3A4310:agents:managed";
        String loopbackDiscovery = discovery()
                .replace(
                        "https://p.example/a/{agent_did_id}/did.json",
                        "https://127.0.0.1:4310/agents/{agent_did_id}/did.json");
        String loopbackIdentity = identity()
                .replace(AGENT_DID, loopbackDid)
                .replace("https://p.example/a/4Yf7p2xQd9/did.json", "https://127.0.0.1:4310/agents/managed/did.json");
        QueueTransport transport = new QueueTransport(
                aepResponse(200, loopbackDiscovery),
                aepResponse(200, "{\"count\":\"1\",\"data\":[" + loopbackIdentity + "],\"total\":\"1\"}"));
        PlatformIdentityProvider provider = PlatformIdentityProvider.builder(URI.create("http://127.0.0.1:4310"))
                .transport(transport)
                .allowInsecureLoopback(true)
                .build();

        AgentIdentity selected =
                provider.getOrCreate(SERVICE, SERVICE_DID).toCompletableFuture().join();

        assertEquals(loopbackDid, selected.did());
    }

    @Test
    void pendingStagesRejectAReusedIdempotencyKeyAndRetryAfterHeader() {
        QueueTransport duplicateTransport = new QueueTransport(
                aepResponse(200, discovery()), aepResponse(200, activeList()), aepResponse(202, pendingSign()));
        PlatformIdentityProvider duplicate = PlatformIdentityProvider.builder(PLATFORM)
                .transport(duplicateTransport)
                .idempotencyKeys(() -> "same-key")
                .pendingSignResolver(pending -> CompletableFuture.completedFuture(Map.of()))
                .build();
        AgentIdentity duplicateIdentity = duplicate
                .getOrCreate(SERVICE, SERVICE_DID)
                .toCompletableFuture()
                .join();

        CompletionException duplicateFailure = assertThrows(
                CompletionException.class,
                () -> duplicateIdentity
                        .signer()
                        .sign(claims())
                        .toCompletableFuture()
                        .join());
        assertEquals("platform_idempotency_key_reused", ((AepAgentException) duplicateFailure.getCause()).code());
        assertEquals(3, duplicateTransport.requests.size());

        QueueTransport retryAfterTransport = new QueueTransport(
                aepResponse(200, discovery()),
                aepResponse(200, activeList()),
                aepResponse(202, Map.of("Retry-After", List.of("5")), pendingSign()));
        AgentIdentity retryAfterIdentity = provider(retryAfterTransport)
                .getOrCreate(SERVICE, SERVICE_DID)
                .toCompletableFuture()
                .join();
        CompletionException retryAfterFailure = assertThrows(
                CompletionException.class,
                () -> retryAfterIdentity
                        .signer()
                        .sign(claims())
                        .toCompletableFuture()
                        .join());
        assertEquals("platform_sign_invalid", ((AepAgentException) retryAfterFailure.getCause()).code());
    }

    @Test
    void rejectsInvalidHostedIdentityRelationshipsAndCopiesPendingContext() {
        String mismatchedKey = identity()
                .replace(
                        "\"key_id\":\"did:web:p.example:a:4Yf7p2xQd9\"",
                        "\"key_id\":\"did:web:p.example:a:4Yf7p2xQd9#key-1\"");
        QueueTransport transport = new QueueTransport(
                aepResponse(200, discovery()),
                aepResponse(200, "{\"count\":\"1\",\"data\":[" + mismatchedKey + "],\"total\":\"1\"}"));
        CompletionException identityFailure = assertThrows(
                CompletionException.class,
                () -> provider(transport)
                        .findIdentityByServiceDid(SERVICE_DID)
                        .toCompletableFuture()
                        .join());
        assertEquals("platform_identity_invalid", ((AepAgentException) identityFailure.getCause()).code());

        List<Object> nested = new ArrayList<>(List.of("first"));
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("items", nested);
        PlatformPendingSign pending =
                new PlatformPendingSign(AepJson.parsePlatformAgentIdentity(identity()), context, 5);
        nested.add("second");
        context.put("changed", true);

        assertEquals(List.of("first"), pending.platformContext().get("items"));
        assertFalse(pending.platformContext().containsKey("changed"));
    }

    @Test
    void rejectsUnsafeConfigurationBeforeSendingRequests() {
        assertThrows(
                IllegalArgumentException.class,
                () -> PlatformIdentityProvider.builder(URI.create("http://platform.example"))
                        .transport(request -> CompletableFuture.failedFuture(new AssertionError()))
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> PlatformIdentityProvider.builder(PLATFORM)
                        .transport(request -> CompletableFuture.failedFuture(new AssertionError()))
                        .authorization("Bearer value\r\nInjected: true"));
        assertThrows(
                IllegalArgumentException.class,
                () -> PlatformIdentityProvider.builder(PLATFORM).maximumResponseBytes(0));
        assertThrows(
                IllegalArgumentException.class,
                () -> PlatformIdentityProvider.builder(PLATFORM).maximumRedirects(-1));

        QueueTransport transport = new QueueTransport();
        CompletionException bindingFailure = assertThrows(
                CompletionException.class,
                () -> provider(transport)
                        .getOrCreate(URI.create("https://other.example"), SERVICE_DID)
                        .toCompletableFuture()
                        .join());
        assertEquals("service_identity_mismatch", ((AepAgentException) bindingFailure.getCause()).code());
        assertTrue(transport.requests.isEmpty());
    }

    private static PlatformIdentityProvider provider(AepHttpTransport transport) {
        return PlatformIdentityProvider.builder(PLATFORM)
                .transport(transport)
                .idempotencyKeys(new Sequence("key-1", "key-2"))
                .build();
    }

    private static ClientAssertionClaims claims() {
        return new ClientAssertionClaims(
                AGENT_DID,
                AGENT_DID,
                SERVICE_DID,
                AssertionOperation.ENROLL,
                1_783_425_600L,
                1_783_425_900L,
                "01J0AEPASSERTION0000000001",
                null);
    }

    private static String discovery() {
        return """
                {"aep_version":"1.0","endpoints":{"hosted_verification":"/v1/aep/verifications","lifecycle":"/v1/aep/agent-identities/{agent_identity_id}","list":"/v1/aep/agent-identities","provision":"/v1/aep/agent-identities","sign":"/v1/aep/agent-identities/{agent_identity_id}/sign"},"http":{"endpoint_base":"/v1/aep"},"identity":{"did_methods":["did:web"],"did_url_template":"https://p.example/a/{agent_did_id}/did.json"},"platform":{"did":"did:web:p.example","hosted_verification":true,"name":"Example Platform"},"signing":{"algorithms":["ES256"],"default_lifetime_seconds":"300"}}
                """;
    }

    private static String identity() {
        return """
                {"agent_did":"did:web:p.example:a:4Yf7p2xQd9","agent_identity_id":"pai_01J0AEPPLATFORM000000000001","created_at":"2026-07-06T12:00:00Z","did_document_url":"https://p.example/a/4Yf7p2xQd9/did.json","key_id":"did:web:p.example:a:4Yf7p2xQd9","service_did":"did:web:api.service.example","signing_algorithms":["ES256"],"status":"active","updated_at":"2026-07-06T12:00:00Z"}
                """;
    }

    private static String identityList() {
        return "{\"count\":\"0\",\"data\":[],\"total\":\"0\"}";
    }

    private static String activeList() {
        return "{\"count\":\"1\",\"data\":[" + identity() + "],\"total\":\"1\"}";
    }

    private static String completedSign() {
        return """
                {"agent_did":"did:web:p.example:a:4Yf7p2xQd9","client_assertion":"client-assertion","expires_at":"2026-07-06T12:05:00Z","issued_at":"2026-07-06T12:00:00Z","jti":"01J0AEPASSERTION0000000001","platform_context":{"authorization_handle":"opaque-value"},"service_did":"did:web:api.service.example","status":"completed"}
                """;
    }

    private static String pendingSign() {
        return """
                {"platform_context":{"authorization_handle":"pending-value"},"retry_after_seconds":"5","status":"pending"}
                """;
    }

    private static AepHttpTransport.Response redirect(String location) {
        return response(302, Map.of("Location", List.of(location)), "");
    }

    private static AepHttpTransport.Response aepResponse(int status, String body) {
        return aepResponse(status, Map.of(), body);
    }

    private static AepHttpTransport.Response aepResponse(int status, Map<String, List<String>> headers, String body) {
        Map<String, List<String>> values = new java.util.LinkedHashMap<>(headers);
        values.put("Content-Type", List.of(Aep.MEDIA_TYPE));
        return response(status, values, body);
    }

    private static AepHttpTransport.Response response(int status, Map<String, List<String>> headers, String body) {
        return new AepHttpTransport.Response(status, headers, body.getBytes(StandardCharsets.UTF_8));
    }

    private static String body(AepHttpTransport.Request request) {
        return new String(request.body(), StandardCharsets.UTF_8);
    }

    private static final class QueueTransport implements AepHttpTransport {
        private final Deque<Response> responses = new ArrayDeque<>();
        private final List<Request> requests = new ArrayList<>();

        private QueueTransport(Response... values) {
            responses.addAll(List.of(values));
        }

        @Override
        public java.util.concurrent.CompletionStage<Response> execute(Request request) {
            requests.add(request);
            if (responses.isEmpty()) return CompletableFuture.failedFuture(new AssertionError("Unexpected request"));
            return CompletableFuture.completedFuture(responses.removeFirst());
        }
    }

    private static final class Sequence implements java.util.function.Supplier<String> {
        private final List<String> values;
        private final AtomicInteger index = new AtomicInteger();

        private Sequence(String... values) {
            this.values = List.of(values);
        }

        @Override
        public String get() {
            return values.get(index.getAndIncrement());
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant value) {
            now = value;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
