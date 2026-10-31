package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.ServiceDocument;
import foundation.aep.core.ServiceDocuments;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
final class AepDocumentReaderTest {
    private static final String JSON = """
            {"format":"aep-service-document","version":"1.0","id":"terms",
             "summary":[{"type":"paragraph","text":"Service-authored summary"}],
             "content":[{"type":"paragraph","text":"Full café terms"}]}
            """;
    private static final URI WEB_URL = URI.create("https://service.example/terms");
    private HttpServer server;
    private String origin;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        origin = "http://localhost:" + server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void readsPortableContentAnonymouslyAndDoesNotRetainCookies() {
        AtomicReference<List<String>> authorization = new AtomicReference<>();
        AtomicReference<List<String>> cookies = new AtomicReference<>();
        AtomicReference<String> accept = new AtomicReference<>();
        AtomicInteger requests = new AtomicInteger();
        server.createContext("/terms", exchange -> {
            requests.incrementAndGet();
            authorization.set(exchange.getRequestHeaders().get("Authorization"));
            cookies.set(exchange.getRequestHeaders().get("Cookie"));
            accept.set(exchange.getRequestHeaders().getFirst("Accept"));
            exchange.getResponseHeaders().add("Set-Cookie", "identity=private; Path=/");
            respond(exchange, 200, "application/json; charset=\"UTF-8\"", JSON.getBytes(StandardCharsets.UTF_8), false);
        });
        ServiceDocument descriptor = descriptor(origin + "/terms");
        for (int index = 0; index < 2; index++) {
            var result = AepDocumentReader.read(descriptor).join();
            assertEquals(descriptor, result.descriptor());
            assertEquals(WEB_URL, result.webUrl());
            assertNull(result.reason());
            assertEquals("Full café terms", result.document().content().get(0).text());
            assertEquals(
                    "Service-authored summary",
                    result.document().summary().get(0).text());
        }
        assertEquals(2, requests.get());
        assertNull(authorization.get());
        assertNull(cookies.get());
        assertEquals("application/json", accept.get());
    }

    @Test
    void offersWebLinkWithoutFetchingWhenPortableIsAbsent() {
        var descriptor = new ServiceDocument(
                "terms",
                "terms_of_service",
                "Terms",
                "required",
                List.of(new ServiceDocument.Representation("text/html", WEB_URL.toString())));
        var result = AepDocumentReader.read(descriptor).join();
        assertEquals("not_advertised", result.reason());
        assertNull(result.document());
        assertEquals(WEB_URL, result.webUrl());
    }

    @Test
    void refusesRedirectsWithoutContactingTheirDestination() {
        AtomicInteger destinationRequests = new AtomicInteger();
        server.createContext("/target", exchange -> {
            destinationRequests.incrementAndGet();
            respond(exchange, 200, "application/json", JSON.getBytes(StandardCharsets.UTF_8), false);
        });
        for (int status : List.of(301, 302, 303, 307, 308)) {
            String path = "/redirect-" + status;
            server.createContext(path, exchange -> {
                exchange.getResponseHeaders().add("Location", origin + "/target");
                respond(exchange, status, "application/json", new byte[0], false);
            });
            assertFallback(AepDocumentReader.read(descriptor(origin + path)).join());
        }
        assertEquals(0, destinationRequests.get());
    }

    @Test
    void rejectsErrorStatusWrongMediaEncodingAndCharset() {
        server.createContext("/missing", exchange -> respond(exchange, 404, "application/json", new byte[0], false));
        assertFallback(AepDocumentReader.read(descriptor(origin + "/missing")).join());
        int index = 0;
        for (String media : List.of("text/html", "application/json; charset=iso-8859-1", "application/json; charset")) {
            String path = "/media-" + index++;
            server.createContext(
                    path, exchange -> respond(exchange, 200, media, JSON.getBytes(StandardCharsets.UTF_8), false));
            assertFallback(AepDocumentReader.read(descriptor(origin + path)).join());
        }
        server.createContext("/encoding", exchange -> {
            exchange.getResponseHeaders().add("Content-Encoding", "gzip");
            respond(exchange, 200, "application/json", JSON.getBytes(StandardCharsets.UTF_8), false);
        });
        assertFallback(AepDocumentReader.read(descriptor(origin + "/encoding")).join());
    }

    @Test
    void rejectsMalformedUtf8JsonMismatchedIdsAndUnsupportedBlocks() {
        List<byte[]> bodies = List.of(
                new byte[] {(byte) 0xc3, 0x28},
                "{".getBytes(StandardCharsets.UTF_8),
                JSON.replace("\"id\":\"terms\"", "\"id\":\"other\"").getBytes(StandardCharsets.UTF_8),
                JSON.replace("paragraph", "script").getBytes(StandardCharsets.UTF_8));
        for (int index = 0; index < bodies.size(); index++) {
            String path = "/body-" + index;
            byte[] body = bodies.get(index);
            server.createContext(path, exchange -> respond(exchange, 200, "application/json", body, false));
            assertFallback(AepDocumentReader.read(descriptor(origin + path)).join());
        }
    }

    @Test
    void boundsBothDeclaredAndChunkedBodiesAndAcceptsExactLimit() {
        byte[] exact = (JSON + " ".repeat(ServiceDocuments.MAX_BYTES - JSON.getBytes(StandardCharsets.UTF_8).length))
                .getBytes(StandardCharsets.UTF_8);
        byte[] excessive = new byte[ServiceDocuments.MAX_BYTES + 1];
        server.createContext("/exact", exchange -> respond(exchange, 200, "application/json", exact, true));
        server.createContext("/large", exchange -> respond(exchange, 200, "application/json", excessive, false));
        server.createContext("/chunked", exchange -> respond(exchange, 200, "application/json", excessive, true));
        assertNotNull(
                AepDocumentReader.read(descriptor(origin + "/exact")).join().document());
        assertFallback(AepDocumentReader.read(descriptor(origin + "/large")).join());
        assertFallback(AepDocumentReader.read(descriptor(origin + "/chunked")).join());
    }

    @Test
    void timeoutCoversStalledBodyNotOnlyResponseHeaders() throws InterruptedException {
        CountDownLatch headersSent = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        server.createContext("/stall", exchange -> stall(exchange, headersSent, release));
        try {
            var future = AepDocumentReader.read(descriptor(origin + "/stall"), Duration.ofSeconds(1));
            assertTrue(headersSent.await(2, TimeUnit.SECONDS));
            assertFallback(future.join());
        } finally {
            release.countDown();
        }
    }

    @Test
    void callerCancellationRemainsCancellation() throws InterruptedException {
        CountDownLatch headersSent = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        server.createContext("/cancel", exchange -> stall(exchange, headersSent, release));
        try {
            var future = AepDocumentReader.read(descriptor(origin + "/cancel"));
            assertTrue(headersSent.await(2, TimeUnit.SECONDS));
            assertFalse(future.isDone());
            assertTrue(future.cancel(true));
            assertThrows(CancellationException.class, future::join);
        } finally {
            release.countDown();
        }
    }

    @Test
    void invalidDescriptorsAndTimeoutsFailBeforeNetworkAccess() {
        assertThrows(AepValidationException.class, () -> AepDocumentReader.read(null));
        for (String url : List.of(
                "http://service.example/terms", "http://localhost.example/terms", "https://user@localhost/terms")) {
            assertThrows(AepValidationException.class, () -> AepDocumentReader.read(descriptor(url)));
        }
        for (Duration timeout : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AepDocumentReader.read(descriptor(origin + "/terms"), timeout));
        }
        assertThrows(NullPointerException.class, () -> AepDocumentReader.read(descriptor(origin + "/terms"), null));
        assertThrows(
                ArithmeticException.class,
                () -> AepDocumentReader.read(descriptor(origin + "/terms"), Duration.ofSeconds(Long.MAX_VALUE)));
    }

    @Test
    void connectionFailureOffersHtml() {
        server.stop(0);
        assertFallback(AepDocumentReader.read(descriptor(origin + "/terms")).join());
    }

    @Test
    void truncatedResponseDoesNotProducePartialDocument() {
        server.createContext("/truncated", exchange -> {
            try (exchange) {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, 5000);
                exchange.getResponseBody().write(JSON.getBytes(StandardCharsets.UTF_8));
            }
        });
        assertFallback(AepDocumentReader.read(descriptor(origin + "/truncated")).join());
    }

    private static ServiceDocument descriptor(String portableUrl) {
        return new ServiceDocument(
                "terms",
                "terms_of_service",
                "Terms",
                "required",
                List.of(
                        new ServiceDocument.Representation("text/html", WEB_URL.toString()),
                        new ServiceDocument.Representation("application/json", portableUrl)));
    }

    private static void assertFallback(AepDocumentReader.Result result) {
        assertNull(result.document());
        assertEquals("unavailable_or_unsupported", result.reason());
        assertEquals(WEB_URL, result.webUrl());
    }

    private static void respond(HttpExchange exchange, int status, String media, byte[] body, boolean chunked)
            throws IOException {
        try (exchange) {
            exchange.getResponseHeaders().set("Content-Type", media);
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : chunked ? 0 : body.length);
            exchange.getResponseBody().write(body);
        }
    }

    private static void stall(HttpExchange exchange, CountDownLatch headersSent, CountDownLatch release)
            throws IOException {
        try (exchange) {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().write('{');
            exchange.getResponseBody().flush();
            headersSent.countDown();
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
