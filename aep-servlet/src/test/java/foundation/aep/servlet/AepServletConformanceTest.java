package foundation.aep.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.AuthenticatedPrincipal;
import foundation.aep.service.EnrollmentDecision;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Checks of the Jakarta Servlet binding. */
final class AepServletConformanceTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String AGENT_DID = "did:web:agent.example";
    private static final String ORIGIN = "https://service.example";
    private static final String ENROLL_BODY = "{\"agent_did\":\"did:web:agent.example\"}";
    private static final String CONTENT_LENGTH = "Content-Length";

    /** RFC 9110 section 9.3.2: HEAD keeps a GET's headers, Content-Length included, and no content. */
    @Test
    void answersHeadWithoutContentButWithAnAccurateLength() throws Exception {
        MockHttpServletResponse get = serve("GET", Aep.WELL_KNOWN_PATH);
        MockHttpServletResponse head = serve("HEAD", Aep.WELL_KNOWN_PATH);

        assertEquals(200, head.getStatus());
        assertEquals("", head.getContentAsString());
        assertEquals(get.getContentAsString().length(), head.getContentLength());
        assertEquals(get.getHeader("ETag"), head.getHeader("ETag"));
        assertEquals(get.getHeader("Cache-Control"), head.getHeader("Cache-Control"));
    }

    @Test
    void rejectsProtectedHeadRequestsWithoutWritingContent() throws Exception {
        AepAuthenticationFilter filter =
                new AepAuthenticationFilter(new AepServiceHttpHandler(service()), URI.create(ORIGIN));
        MockHttpServletResponse get = new MockHttpServletResponse();
        MockHttpServletResponse head = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", "/orders"), get, new MockFilterChain());
        filter.doFilter(new MockHttpServletRequest("HEAD", "/orders"), head, new MockFilterChain());
        assertEquals(401, head.getStatus());
        assertEquals(0, head.getContentAsByteArray().length);
        assertEquals(get.getContentAsByteArray().length, head.getContentLength());
        assertEquals(get.getHeader("WWW-Authenticate"), head.getHeader("WWW-Authenticate"));
        assertEquals(get.getContentType(), head.getContentType());
    }

    /** RFC 9110 section 15.4.5: a 304 repeats the validators and describes no representation. */
    @Test
    void answersNotModifiedWithNoContentAndNoLength() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", Aep.WELL_KNOWN_PATH);
        request.setRequestURI(Aep.WELL_KNOWN_PATH);
        request.addHeader("If-None-Match", handler.inspectEntityTag());
        MockHttpServletResponse response = new MockHttpServletResponse();

        new AepServlet(handler).service(request, response);

        assertEquals(304, response.getStatus());
        assertEquals("", response.getContentAsString());
        assertFalse(response.containsHeader(CONTENT_LENGTH), "a 304 describes no representation");
        assertEquals(handler.inspectEntityTag(), response.getHeader("ETag"));
    }

    /** CORE-ERR-001: an unrouted path answers as Problem Details, not as a container error page. */
    @Test
    void refusesUnroutedPathsWithAProblemDocument() throws Exception {
        MockHttpServletResponse response = serve("GET", "/aep/unknown");

        assertEquals(404, response.getStatus());
        assertEquals(Aep.PROBLEM_MEDIA_TYPE, response.getContentType());
        assertTrue(response.getContentAsString().contains("\"urn:aep:error:invalid_request\""));
        assertEquals("no-store", response.getHeader("Cache-Control"));
    }

    /** The command path carries its body, media type, and idempotency key through the container. */
    @Test
    void servesCommandsSynchronouslyAndAsynchronously() throws Exception {
        assertEquals(200, enroll(false).getStatus());
        MockHttpServletResponse asynchronous = enroll(true);
        assertEquals(200, asynchronous.getStatus());
        assertTrue(asynchronous.getContentAsString().contains("\"status\":\"active\""));
        assertEquals("no-store", asynchronous.getHeader("Cache-Control"));
    }

    /** A failure after the response is handed off still completes the request rather than hanging. */
    @Test
    void completesAsynchronousRequestsThatFail() throws Exception {
        AepService failing = AepService.builder(
                        document(), (assertion, context) -> CompletableFuture.failedFuture(new IllegalStateException()))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", Aep.WELL_KNOWN_PATH);
        request.setRequestURI("/aep/status");
        request.setAsyncSupported(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        new AepServlet(new AepServiceHttpHandler(failing)).service(request, response);

        assertEquals(401, response.getStatus(), "a verifier failure is an unrecognized credential, not a crash");
    }

    /** A protected route reaches the application only once a credential has been accepted. */
    @Test
    void protectsApplicationRoutes() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());
        enroll(handler);
        AepAuthenticationFilter filter = new AepAuthenticationFilter(handler, URI.create(ORIGIN));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRequestURI("/orders");
        request.setQueryString("page=2");
        request.addHeader("Authorization", "AEP assertion");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertEquals(
                AGENT_DID,
                ((AuthenticatedPrincipal) request.getAttribute(AepAuthenticationFilter.PRINCIPAL_ATTRIBUTE))
                        .agentDid());
    }

    @Test
    void refusesNonHttpExchangesAndUnusableConfiguration() {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());
        AepAuthenticationFilter filter = new AepAuthenticationFilter(handler, URI.create(ORIGIN));

        assertThrows(NullPointerException.class, () -> new AepServlet(null));
        assertThrows(NullPointerException.class, () -> new AepAuthenticationFilter(null, URI.create(ORIGIN)));
        assertThrows(IllegalArgumentException.class, () -> new AepAuthenticationFilter(handler, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AepAuthenticationFilter(handler, URI.create("https://service.example/base")));
        assertThrows(
                ServletException.class,
                () -> filter.doFilter(
                        stub(jakarta.servlet.ServletRequest.class),
                        stub(jakarta.servlet.ServletResponse.class),
                        new MockFilterChain()),
                "AEP authentication is defined over HTTP");
    }

    @Test
    void collectsHeadersAndBoundsTheBody() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/aep/enroll");
        request.setRequestURI("/aep/enroll");
        request.addHeader("X-Trace", "one");
        request.addHeader("X-Trace", "two");
        request.setContent("abcdef".getBytes(StandardCharsets.UTF_8));

        AepHttpRequest full = AepServletSupport.request(request, URI.create(ORIGIN + "/aep/enroll"), true, 64);
        AepHttpRequest none = AepServletSupport.request(request, URI.create(ORIGIN + "/aep/enroll"), false, 64);

        assertEquals(List.of("one", "two"), full.headerValues("x-trace"));
        assertEquals("abcdef", new String(full.body(), StandardCharsets.UTF_8));
        assertEquals(0, none.body().length);
        assertEquals("POST", full.method());
    }

    @Test
    void reconstructsTheRequestUrlWithAndWithoutAQuery() {
        MockHttpServletRequest plain = new MockHttpServletRequest("GET", "/aep/status");
        plain.setRequestURI("/aep/status");
        MockHttpServletRequest queried = new MockHttpServletRequest("GET", "/aep/status");
        queried.setRequestURI("/aep/status");
        queried.setQueryString("x=1");

        assertEquals("/aep/status", AepServletSupport.requestUrl(plain).getPath());
        assertEquals("x=1", AepServletSupport.requestUrl(queried).getQuery());
    }

    @Test
    void writesResponsesWithoutARequestToCompareAgainst() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        AepServletSupport.write(
                response,
                new AepHttpResponse(
                        200,
                        Aep.MEDIA_TYPE,
                        Map.of("X-Trace", List.of("one", "two")),
                        "body".getBytes(StandardCharsets.UTF_8)));

        assertEquals("body", response.getContentAsString());
        assertEquals(List.of("one", "two"), response.getHeaders("X-Trace"));
        assertEquals(4, response.getContentLength());
    }

    /** A failed command stage still completes the exchange instead of leaving it open. */
    @Test
    void reportsAsynchronousFailuresAsServerErrors() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/aep/status");
        request.setRequestURI("/aep/status");
        request.addHeader("Authorization", "AEP assertion");
        request.setAsyncSupported(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        new AepServlet(new AepServiceHttpHandler(throwingService())).service(request, response);

        assertEquals(500, response.getStatus());
    }

    /** A failure while writing completes the exchange rather than escaping into the async machinery. */
    @Test
    void reportsFailuresRaisedWhileWritingTheResponse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", Aep.WELL_KNOWN_PATH);
        request.setRequestURI(Aep.WELL_KNOWN_PATH);
        request.setAsyncSupported(true);
        MockHttpServletResponse exploding = new MockHttpServletResponse() {
            @Override
            public void setContentType(String contentType) {
                throw new IllegalStateException("boom");
            }
        };

        new AepServlet(new AepServiceHttpHandler(service())).service(request, exploding);

        assertEquals(500, exploding.getStatus());
    }

    /** A response that can no longer take an error is left to the container. */
    @Test
    void leavesACommittedResponseAlone() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", Aep.WELL_KNOWN_PATH);
        request.setRequestURI(Aep.WELL_KNOWN_PATH);
        request.setAsyncSupported(true);
        MockHttpServletResponse stubborn = new MockHttpServletResponse() {
            @Override
            public void setContentType(String contentType) {
                throw new IllegalStateException("boom");
            }

            @Override
            public void sendError(int status) {
                throw new IllegalStateException("already committed");
            }
        };

        new AepServlet(new AepServiceHttpHandler(service())).service(request, stubborn);

        assertEquals(200, stubborn.getStatus(), "nothing was written, and nothing threw out of the servlet");
    }

    /** The servlet holds a handler, so a deserialized instance would hold nothing at all. */
    @Test
    void refusesToBeDeserialized() throws Exception {
        java.lang.reflect.Method readObject =
                AepServlet.class.getDeclaredMethod("readObject", java.io.ObjectInputStream.class);
        readObject.setAccessible(true);

        var failure = assertThrows(
                java.lang.reflect.InvocationTargetException.class,
                () -> readObject.invoke(new AepServlet(new AepServiceHttpHandler(service())), (Object) null));

        assertTrue(failure.getCause() instanceof java.io.InvalidObjectException);
    }

    /** A container that reports no header names at all still produces a usable request. */
    @Test
    void toleratesAContainerThatEnumeratesNoHeaders() throws Exception {
        HttpServletRequest bare = (HttpServletRequest) java.lang.reflect.Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getHeaderNames", "getHeaders" -> null;
                    case "getMethod" -> "GET";
                    default -> throw new UnsupportedOperationException(method.getName());
                });

        AepHttpRequest request = AepServletSupport.request(bare, URI.create(ORIGIN + "/x"), false, 64);

        assertEquals(Map.of(), request.headers());
        assertEquals("GET", request.method());
    }

    /** AEP authentication is defined over HTTP, so a half-HTTP exchange is refused too. */
    @Test
    void refusesAHalfHttpExchange() {
        AepAuthenticationFilter filter =
                new AepAuthenticationFilter(new AepServiceHttpHandler(service()), URI.create(ORIGIN));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRequestURI("/orders");

        assertThrows(
                ServletException.class,
                () -> filter.doFilter(request, stub(jakarta.servlet.ServletResponse.class), new MockFilterChain()));
    }

    private static AepService throwingService() {
        foundation.aep.service.EnrollmentStore failing = new foundation.aep.service.EnrollmentStore() {
            @Override
            public CompletableFuture<java.util.Optional<foundation.aep.service.EnrollmentRecord>> find(
                    String agentDid) {
                return CompletableFuture.failedFuture(new IllegalStateException("boom"));
            }

            @Override
            public CompletableFuture<foundation.aep.service.EnrollmentSelection> findOrCreate(
                    String agentDid,
                    java.util.function.Supplier<
                                    java.util.concurrent.CompletionStage<foundation.aep.service.EnrollmentRecord>>
                            create) {
                return CompletableFuture.failedFuture(new IllegalStateException("boom"));
            }

            @Override
            public CompletableFuture<foundation.aep.service.EnrollmentRecord> save(
                    foundation.aep.service.EnrollmentRecord record) {
                return CompletableFuture.failedFuture(new IllegalStateException("boom"));
            }
        };
        return AepService.builder(
                        document(),
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
                .enrollmentStore(failing)
                .build();
    }

    // A bare ServletRequest/ServletResponse that is not the HTTP subtype; the interfaces are wide
    // and every method is unreachable for this test, so a proxy says it more plainly than a stub.
    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> type) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(
                type.getClassLoader(), new Class<?>[] {type}, (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static MockHttpServletResponse enroll(boolean asynchronous) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/aep/enroll");
        request.setRequestURI("/aep/enroll");
        request.addHeader("Content-Type", Aep.MEDIA_TYPE);
        request.addHeader("Authorization", "AEP assertion-" + asynchronous);
        request.addHeader("Idempotency-Key", "key-" + asynchronous);
        request.setContent(ENROLL_BODY.getBytes(StandardCharsets.UTF_8));
        request.setAsyncSupported(asynchronous);
        MockHttpServletResponse response = new MockHttpServletResponse();
        new AepServlet(new AepServiceHttpHandler(service())).service(request, response);
        return response;
    }

    private static void enroll(AepServiceHttpHandler handler) {
        handler.handle(
                        AepCommand.ENROLL,
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
                                ENROLL_BODY.getBytes(StandardCharsets.UTF_8)))
                .toCompletableFuture()
                .join();
    }

    private static MockHttpServletResponse serve(String method, String path) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestURI(path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        new AepServlet(new AepServiceHttpHandler(service())).service(request, response);
        return response;
    }

    private static InspectDocument document() {
        return InspectDocument.builder()
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
    }

    private static AepService service() {
        return AepService.builder(
                        document(),
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
