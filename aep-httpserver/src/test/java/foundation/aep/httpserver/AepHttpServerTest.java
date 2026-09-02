package foundation.aep.httpserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.EnrollmentDecision;
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
import org.junit.jupiter.api.Test;

final class AepHttpServerTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");

    @Test
    void servesAepRoutesAndRejectsPrefixMatches() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AepHttpServer.register(server, new AepServiceHttpHandler(service()));
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> inspect = client.send(
                    HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH)).build(),
                    HttpResponse.BodyHandlers.ofString());
            HttpResponse<String> prefix = client.send(
                    HttpRequest.newBuilder(base.resolve(Aep.WELL_KNOWN_PATH + "/extra"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertEquals(200, inspect.statusCode());
            assertEquals(
                    Aep.MEDIA_TYPE, inspect.headers().firstValue("Content-Type").orElseThrow());
            assertTrue(inspect.body().contains("\"aep_version\""));
            assertEquals(404, prefix.statusCode());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void protectsApplicationRoutes() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());
        server.createContext(
                "/orders", AepHttpServer.protect(handler, URI.create("https://service.example"), exchange -> {
                    exchange.sendResponseHeaders(204, -1);
                    exchange.close();
                }));
        server.start();
        try {
            URI requestUrl =
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/orders");
            HttpResponse<String> response = HttpClient.newHttpClient()
                    .send(HttpRequest.newBuilder(requestUrl).build(), HttpResponse.BodyHandlers.ofString());

            assertEquals(401, response.statusCode());
            assertTrue(response.headers().firstValue("WWW-Authenticate").isPresent());
        } finally {
            server.stop(0);
        }
    }

    private static AepService service() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
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
                .build();
    }
}
