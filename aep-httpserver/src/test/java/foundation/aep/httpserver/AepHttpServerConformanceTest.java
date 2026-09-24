package foundation.aep.httpserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpServer;
import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.ClientAssertionVerifier;
import foundation.aep.service.EnrollmentDecision;
import foundation.aep.service.EnrollmentRecord;
import foundation.aep.service.EnrollmentStore;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/** End-to-end checks of the JDK HTTP server binding. */
final class AepHttpServerConformanceTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String AGENT_DID = "did:web:agent.example";
    private static final String ORIGIN = "https://service.example";
    private static final String ENROLL_BODY = "{\"agent_did\":\"did:web:agent.example\"}";

    @Test
    void authenticatesTheExactEncodedResourceOverHttp() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).generate();
        EnrollmentStore store = EnrollmentStore.inMemory();
        store.save(EnrollmentRecord.builder(AGENT_DID, "enrollment", AgentStatus.ACTIVE, NOW)
                        .build())
                .toCompletableFuture()
                .join();
        AepService service = AepService.builder(
                        service().inspectDocument(),
                        ClientAssertionVerifier.withKeyResolver(
                                (jwt, claims, context) -> CompletableFuture.completedFuture(key.toPublicJWK())))
                .enrollmentStore(store)
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/", AepHttpServer.protect(new AepServiceHttpHandler(service), URI.create(ORIGIN), exchange -> {
                    exchange.sendResponseHeaders(204, -1);
                    exchange.close();
                }));
        server.start();
        try {
            for (String path : List.of("/plain", "/objects/a%2Fb?filter=c%2Fd", "/objects/a%3Fb%23c")) {
                URI target =
                        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
                for (String resource : List.of(ORIGIN + path, ORIGIN + "/different", "https://other.example" + path)) {
                    String assertion = ClientAssertions.sign(
                            new ClientAssertionClaims(
                                    AGENT_DID,
                                    AGENT_DID,
                                    "did:web:service.example",
                                    AssertionOperation.AUTHENTICATE,
                                    NOW.getEpochSecond(),
                                    NOW.plusSeconds(60).getEpochSecond(),
                                    java.util.UUID.randomUUID().toString(),
                                    resource),
                            key,
                            AGENT_DID);
                    HttpResponse<String> response = send(HttpRequest.newBuilder(target)
                            .timeout(java.time.Duration.ofSeconds(5))
                            .header("Authorization", "AEP " + assertion));
                    assertEquals(resource.equals(ORIGIN + path) ? 204 : 401, response.statusCode());
                }
            }
        } finally {
            server.stop(0);
        }
    }

    /** RFC 9110 section 9.3.2: HEAD repeats a GET's header fields and sends no content. */
    @Test
    void answersHeadWithTheHeadersOfAGetAndNoBody() throws Exception {
        served(base -> {
            HttpResponse<String> get = send(HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH)));
            HttpResponse<String> head = send(
                    HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH)).method("HEAD", noBody()));

            assertEquals(200, head.statusCode());
            assertEquals("", head.body());
            assertEquals(get.headers().firstValue("ETag"), head.headers().firstValue("ETag"));
            assertEquals(
                    get.headers().firstValue("Cache-Control"), head.headers().firstValue("Cache-Control"));
            assertFalse(get.body().isEmpty());
        });
    }

    /** CORE-CACHE-004: a matching validator revalidates through 304 with no content. */
    @Test
    void revalidatesThroughNotModified() throws Exception {
        served(base -> {
            HttpResponse<String> first = send(HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH)));
            String entityTag = first.headers().firstValue("ETag").orElseThrow();
            HttpResponse<String> conditional = send(
                    HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH)).header("If-None-Match", entityTag));

            assertEquals(304, conditional.statusCode());
            assertEquals("", conditional.body());
            assertEquals(entityTag, conditional.headers().firstValue("ETag").orElseThrow());
            assertTrue(conditional.headers().firstValue("Content-Length").isEmpty());
        });
    }

    /** CORE-ERR-001: the prefix-matched paths this context also receives answer as Problem Details. */
    @Test
    void refusesPrefixMatchesWithAProblemDocument() throws Exception {
        served(base -> {
            HttpResponse<String> nested = send(HttpRequest.newBuilder(base.resolve("/aep/enroll/extra")));
            HttpResponse<String> extended = send(HttpRequest.newBuilder(base.resolve("/aep/enrollments")));

            assertEquals(404, nested.statusCode());
            assertEquals(
                    Aep.PROBLEM_MEDIA_TYPE,
                    nested.headers().firstValue("Content-Type").orElseThrow());
            assertTrue(nested.body().contains("\"urn:aep:error:invalid_request\""));
            assertTrue(nested.body().contains("\"status\":404"));
            assertEquals(404, extended.statusCode());
        });
    }

    /** RFC 9110 section 9.3.2 again: the refusal names both safe methods. */
    @Test
    void namesEverySafeMethodWhenRefusingOne() throws Exception {
        served(base -> {
            HttpResponse<String> refused = send(HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH))
                    .POST(HttpRequest.BodyPublishers.ofString("")));

            assertEquals(405, refused.statusCode());
            assertEquals("GET, HEAD", refused.headers().firstValue("Allow").orElseThrow());
        });
    }

    /** The command path carries a body, a media type, and an idempotency key end to end. */
    @Test
    void servesAnEnrollCommandOverTheWire() throws Exception {
        served(base -> {
            HttpResponse<String> enrolled = send(HttpRequest.newBuilder(base.resolve("/aep/enroll"))
                    .header("Content-Type", Aep.MEDIA_TYPE)
                    .header("Authorization", "AEP assertion-1")
                    .header("Idempotency-Key", "key-1")
                    .POST(HttpRequest.BodyPublishers.ofString(ENROLL_BODY)));
            HttpResponse<String> wrongMedia = send(HttpRequest.newBuilder(base.resolve("/aep/enroll"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "AEP assertion-2")
                    .header("Idempotency-Key", "key-2")
                    .POST(HttpRequest.BodyPublishers.ofString(ENROLL_BODY)));

            assertEquals(200, enrolled.statusCode());
            assertTrue(enrolled.body().contains("\"status\":\"active\""));
            assertEquals(
                    "no-store", enrolled.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals(415, wrongMedia.statusCode());
        });
    }

    /** An oversized body is refused before it is parsed. */
    @Test
    void refusesBodiesPastTheConfiguredLimit() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AepHttpServer.register(server, new AepServiceHttpHandler(service(), 8));
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpResponse<String> response = send(HttpRequest.newBuilder(base.resolve("/aep/enroll"))
                    .header("Content-Type", Aep.MEDIA_TYPE)
                    .header("Authorization", "AEP assertion")
                    .header("Idempotency-Key", "key")
                    .POST(HttpRequest.BodyPublishers.ofString(ENROLL_BODY)));

            assertEquals(413, response.statusCode());
        } finally {
            server.stop(0);
        }
    }

    /** A protected route reaches the application only once a credential has been accepted. */
    @Test
    void passesAuthenticatedRequestsToTheApplication() throws Exception {
        AtomicReference<Object> principal = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());
        server.createContext("/orders", AepHttpServer.protect(handler, URI.create(ORIGIN), exchange -> {
            principal.set(exchange.getAttribute(AepHttpServer.PRINCIPAL_ATTRIBUTE));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        }));
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            enroll(handler);
            HttpResponse<String> rejected = send(HttpRequest.newBuilder(base.resolve("/orders")));
            HttpResponse<String> accepted =
                    send(HttpRequest.newBuilder(base.resolve("/orders")).header("Authorization", "AEP assertion"));
            HttpResponse<String> head =
                    send(HttpRequest.newBuilder(base.resolve("/orders")).method("HEAD", noBody()));

            assertEquals(401, rejected.statusCode());
            assertTrue(rejected.headers()
                    .firstValue("WWW-Authenticate")
                    .orElseThrow()
                    .startsWith("AEP "));
            assertFalse(rejected.body().isEmpty(), "a rejection is a Problem Details document");
            assertEquals(204, accepted.statusCode());
            assertEquals(AGENT_DID, ((foundation.aep.service.AuthenticatedPrincipal) principal.get()).agentDid());
            assertEquals(401, head.statusCode());
            assertEquals("", head.body(), "a HEAD rejection carries no content either");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void refusesUnusableRegistrationArguments() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());

        assertThrows(NullPointerException.class, () -> AepHttpServer.register(null, handler));
        assertThrows(NullPointerException.class, () -> AepHttpServer.register(server, null));
        assertThrows(NullPointerException.class, () -> AepHttpServer.protect(null, URI.create(ORIGIN), e -> {}));
        assertThrows(NullPointerException.class, () -> AepHttpServer.protect(handler, URI.create(ORIGIN), null));
        assertThrows(IllegalArgumentException.class, () -> AepHttpServer.protect(handler, null, e -> {}));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttpServer.protect(handler, URI.create("https://service.example/base"), e -> {}));
        assertEquals(3, AepHttpServer.register(server, handler).size(), "inspect, enroll, and status");
    }

    private static void enroll(AepServiceHttpHandler handler) {
        handler.handle(
                        foundation.aep.core.AepCommand.ENROLL,
                        new AepHttpRequest(
                                "POST",
                                URI.create(ORIGIN + "/aep/enroll"),
                                Map.of(
                                        "Content-Type",
                                        List.of(Aep.MEDIA_TYPE),
                                        "Authorization",
                                        List.of("AEP enrollment"),
                                        "Idempotency-Key",
                                        List.of("enroll-key")),
                                ENROLL_BODY.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .toCompletableFuture()
                .join();
    }

    private static void served(Consumer<URI> body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AepHttpServer.register(server, new AepServiceHttpHandler(service()));
        server.start();
        try {
            body.accept(URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
        } finally {
            server.stop(0);
        }
    }

    private static HttpRequest.BodyPublisher noBody() {
        return HttpRequest.BodyPublishers.noBody();
    }

    private static HttpResponse<String> send(HttpRequest.Builder request) {
        try {
            return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static AepService service() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        return AepService.builder(
                        document,
                        (assertion, context) -> CompletableFuture.completedFuture(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentPolicy((request, now) -> CompletableFuture.completedFuture(
                        new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of())))
                .build();
    }
}
