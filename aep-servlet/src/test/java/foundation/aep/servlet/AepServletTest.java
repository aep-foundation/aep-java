package foundation.aep.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.EnrollmentDecision;
import java.net.URI;
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

final class AepServletTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");

    @Test
    void servesTheInspectRoute() throws Exception {
        AepServlet servlet = new AepServlet(new AepServiceHttpHandler(service()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", Aep.WELL_KNOWN_PATH);
        request.setRequestURI(Aep.WELL_KNOWN_PATH);
        MockHttpServletResponse response = new MockHttpServletResponse();

        servlet.service(request, response);

        assertEquals(200, response.getStatus());
        assertEquals(Aep.MEDIA_TYPE, response.getContentType());
        assertTrue(response.getContentAsString().contains("\"aep_version\""));
    }

    @Test
    void servesTheInspectRouteWithServletAsyncProcessing() throws Exception {
        AepServlet servlet = new AepServlet(new AepServiceHttpHandler(service()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", Aep.WELL_KNOWN_PATH);
        request.setRequestURI(Aep.WELL_KNOWN_PATH);
        request.setAsyncSupported(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        servlet.service(request, response);

        assertEquals(200, response.getStatus());
        assertFalse(request.isAsyncStarted());
        assertTrue(response.getContentAsString().contains("\"aep_version\""));
    }

    @Test
    void protectsAResourceAndPreservesItsBodyStream() throws Exception {
        AepAuthenticationFilter filter = new AepAuthenticationFilter(
                new AepServiceHttpHandler(service()), URI.create("https://service.example"));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/orders");
        request.setRequestURI("/orders");
        request.setContent("request body".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertEquals(
                "request body",
                new String(request.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(response.containsHeader("WWW-Authenticate"));
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
                                "did:web:agent.example",
                                "did:web:agent.example",
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentPolicy((request, now) -> CompletableFuture.completedFuture(
                        new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of())))
                .inspectUri(URI.create("https://service.example/.well-known/aep"))
                .build();
    }
}
