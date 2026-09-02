package foundation.aep.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.InspectDocument;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

final class AepServiceHttpHandlerTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String AGENT_DID = "did:web:agent.example";

    @Test
    void derivesRoutesAndServesTheInspectDocument() {
        AepServiceHttpHandler handler = handler();

        AepHttpResponse response =
                await(handler.handle(AepCommand.INSPECT, request("GET", Aep.WELL_KNOWN_PATH, Map.of(), new byte[0])));

        assertEquals(
                Map.of(
                        AepCommand.ENROLL, "/aep/enroll",
                        AepCommand.INSPECT, Aep.WELL_KNOWN_PATH,
                        AepCommand.STATUS, "/aep/status"),
                handler.routes());
        assertEquals(200, response.status());
        assertEquals(Aep.MEDIA_TYPE, response.contentType());
        assertTrue(response.bodyText().contains("\"aep_version\""));
    }

    @Test
    void enrollsThroughTheHttpBoundary() {
        AepServiceHttpHandler handler = handler();
        EnrollRequest enroll = new EnrollRequest(
                AGENT_DID,
                foundation.aep.core.ClaimValues.builder()
                        .contactEmail("agent@example.com")
                        .build(),
                null);

        AepHttpResponse response = await(handler.handle(
                AepCommand.ENROLL,
                request(
                        "POST",
                        "/aep/enroll",
                        Map.of(
                                "Authorization", List.of("AEP assertion"),
                                "Content-Type", List.of(Aep.MEDIA_TYPE),
                                "Idempotency-Key", List.of("enroll-key")),
                        foundation.aep.core.AepJson.write(enroll).getBytes(StandardCharsets.UTF_8))));

        assertEquals(200, response.status());
        assertTrue(response.bodyText().contains("\"status\":\"active\""));
    }

    @Test
    void rejectsWrongMethodsAndContentTypes() {
        AepServiceHttpHandler handler = handler();

        AepHttpResponse method =
                await(handler.handle(AepCommand.STATUS, request("POST", "/aep/status", Map.of(), new byte[0])));
        AepHttpResponse contentType = await(handler.handle(
                AepCommand.ENROLL,
                request("POST", "/aep/enroll", Map.of("Content-Type", List.of("application/json")), new byte[0])));

        assertEquals(405, method.status());
        assertEquals(List.of("GET"), method.headers().get("Allow"));
        assertEquals(415, contentType.status());
    }

    @Test
    void rejectsMalformedUtf8AndOversizedBodies() {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service(), 3);

        AepHttpResponse malformed = await(handler.handle(
                AepCommand.ENROLL,
                request("POST", "/aep/enroll", Map.of("Content-Type", List.of(Aep.MEDIA_TYPE)), new byte[] {
                    (byte) 0xc3, (byte) 0x28
                })));
        AepHttpResponse oversized = await(handler.handle(
                AepCommand.ENROLL,
                request("POST", "/aep/enroll", Map.of("Content-Type", List.of(Aep.MEDIA_TYPE)), new byte[] {1, 2, 3, 4
                })));

        assertEquals(400, malformed.status());
        assertEquals(413, oversized.status());
    }

    @Test
    void rejectsAmbiguousSecurityHeaders() {
        AepServiceHttpHandler handler = handler();

        AepHttpResponse response = await(handler.handle(
                AepCommand.STATUS,
                request(
                        "GET",
                        "/aep/status",
                        Map.of("Authorization", List.of("AEP first", "AEP second")),
                        new byte[0])));

        assertEquals(401, response.status());
        assertTrue(response.bodyText().contains("not_recognized"));
    }

    @Test
    void challengesAProtectedResourceWithoutCredentials() {
        AepHttpAuthenticationResult result =
                await(handler().authenticate(request("GET", "/orders/1", Map.of(), new byte[0])));

        assertFalse(result.authenticated());
        assertNull(result.principal());
        assertEquals(401, result.response().status());
        assertTrue(result.response().headers().containsKey("WWW-Authenticate"));
    }

    @Test
    void defensivelyCopiesRequestAndResponseBodies() {
        byte[] requestBody = {1};
        AepHttpRequest request = request("POST", "/aep/enroll", Map.of(), requestBody);
        requestBody[0] = 2;
        byte[] responseBody = {3};
        AepHttpResponse response = new AepHttpResponse(200, Aep.MEDIA_TYPE, Map.of(), responseBody);
        responseBody[0] = 4;

        assertArrayEquals(new byte[] {1}, request.body());
        assertArrayEquals(new byte[] {3}, response.body());
        assertThrows(IllegalArgumentException.class, () -> new AepHttpAuthenticationResult(true, null, response));
    }

    @Test
    void constructsPublicUrlsWithoutAllowingAuthorityReplacement() {
        assertEquals(
                URI.create("https://service.example/orders/1?view=full"),
                AepHttpRequest.publicUrl(URI.create("https://service.example"), "/orders/1", "view=full"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttpRequest.publicUrl(URI.create("https://service.example"), "//attacker.example", null));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttpRequest.publicUrl(URI.create("mailto:service@example.com"), "/orders/1", null));
    }

    private static AepServiceHttpHandler handler() {
        return new AepServiceHttpHandler(service());
    }

    private static AepService service() {
        return AepService.builder(
                        document(),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentPolicy((request, now) ->
                        completed(new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of())))
                .identifierSupplier(() -> "enrollment-1")
                .inspectUri(URI.create("https://service.example/.well-known/aep"))
                .build();
    }

    private static InspectDocument document() {
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of("contact.email"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
    }

    private static AepHttpRequest request(String method, String path, Map<String, List<String>> headers, byte[] body) {
        return new AepHttpRequest(method, URI.create("https://service.example" + path), headers, body);
    }

    private static <T> T await(CompletionStage<T> stage) {
        return stage.toCompletableFuture().join();
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }
}
