package foundation.aep.service;

import static org.junit.jupiter.api.Assertions.*;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.AssertionOperation;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;

final class HostedPlatformClientAssertionVerifierTest {
    private static final URI ENDPOINT = URI.create("https://platform.example/verify");
    private static final String AGENT = "did:web:agent.example";
    private static final String SERVICE = "did:web:service.example";

    @Test
    void sendsBoundRequestAndStableAssertionSpecificKey() {
        List<AepHttpTransport.Request> requests = new ArrayList<>();
        var verifier = HostedPlatformClientAssertionVerifier.builder(ENDPOINT, request -> {
                    requests.add(request);
                    return CompletableFuture.completedFuture(response(200, success("authenticate")));
                })
                .authorization("Bearer service-token")
                .build();
        String assertion = assertion("one", "authenticate");
        var claims = verifier.verify(assertion, context(AssertionOperation.AUTHENTICATE))
                .toCompletableFuture()
                .join();
        verifier.verify(assertion, context(AssertionOperation.AUTHENTICATE))
                .toCompletableFuture()
                .join();
        verifier.verify(assertion("two", "authenticate"), context(AssertionOperation.AUTHENTICATE))
                .toCompletableFuture()
                .join();
        assertEquals(AGENT, claims.subject());
        var request = requests.get(0);
        assertEquals(ENDPOINT, request.uri());
        assertEquals("POST", request.method());
        assertEquals(Duration.ofSeconds(30), request.timeout());
        assertEquals(List.of("Bearer service-token"), request.headers().get("Authorization"));
        assertEquals(List.of(Aep.MEDIA_TYPE), request.headers().get("Content-Type"));
        assertEquals(List.of(Aep.MEDIA_TYPE), request.headers().get("Accept"));
        var body = AepJson.parsePlatformVerificationRequest(new String(request.body(), StandardCharsets.UTF_8));
        assertEquals(assertion, body.clientAssertion());
        assertEquals(SERVICE, body.serviceDid());
        assertEquals(AssertionOperation.AUTHENTICATE, body.operation());
        assertEquals("https://service.example/resource", body.resource());
        assertEquals(
                request.headers().get("Idempotency-Key"),
                requests.get(1).headers().get("Idempotency-Key"));
        assertNotEquals(
                request.headers().get("Idempotency-Key"),
                requests.get(2).headers().get("Idempotency-Key"));
    }

    @Test
    void omitsResourceAndAuthorizationForCommand() {
        var verifier = HostedPlatformClientAssertionVerifier.builder(ENDPOINT, request -> {
                    assertFalse(request.headers().containsKey("Authorization"));
                    var body = AepJson.parseObject(new String(request.body(), StandardCharsets.UTF_8), "verification");
                    assertFalse(body.containsKey("resource"));
                    return CompletableFuture.completedFuture(response(200, success("status")));
                })
                .build();
        assertEquals(
                AGENT,
                verifier.verify(assertion("one", "status"), context(AssertionOperation.STATUS))
                        .toCompletableFuture()
                        .join()
                        .subject());
    }

    @Test
    void rejectsUnrecognizedMismatchedAndMalformedResponses() {
        for (String body : List.of(
                "{\"verified\":false,\"reason\":\"not_recognized\",\"service_did\":\"" + SERVICE + "\"}",
                success("status").replace(AGENT, "did:web:other.example"),
                success("status").replace(SERVICE, "did:web:other.example"),
                success("enroll"),
                "{}",
                "[]",
                "not json")) {
            var verifier = HostedPlatformClientAssertionVerifier.builder(
                            ENDPOINT, request -> CompletableFuture.completedFuture(response(200, body)))
                    .build();
            assertThrows(
                    CompletionException.class,
                    () -> verifier.verify(assertion("one", "status"), context(AssertionOperation.STATUS))
                            .toCompletableFuture()
                            .join());
        }
    }

    @Test
    void rejectsRedirectAndHttpFailureWithoutRetrying() {
        for (int status : List.of(199, 302, 401, 500)) {
            List<AepHttpTransport.Request> requests = new ArrayList<>();
            var verifier = HostedPlatformClientAssertionVerifier.builder(ENDPOINT, request -> {
                        requests.add(request);
                        return CompletableFuture.completedFuture(response(status, success("status")));
                    })
                    .build();
            assertThrows(
                    CompletionException.class,
                    () -> verifier.verify(assertion("one", "status"), context(AssertionOperation.STATUS))
                            .toCompletableFuture()
                            .join());
            assertEquals(1, requests.size());
        }
    }

    @Test
    void boundsWaitingAndPropagatesTransportFailure() {
        CompletableFuture<AepHttpTransport.Response> pending = new CompletableFuture<>();
        var verifier = HostedPlatformClientAssertionVerifier.builder(ENDPOINT, request -> pending)
                .timeout(Duration.ofMillis(10))
                .build();
        var failure = assertThrows(
                CompletionException.class,
                () -> verifier.verify(assertion("one", "status"), context(AssertionOperation.STATUS))
                        .toCompletableFuture()
                        .join());
        assertInstanceOf(TimeoutException.class, failure.getCause());
        assertFalse(pending.isDone());
        pending.complete(response(200, success("status")));
        var broken = HostedPlatformClientAssertionVerifier.builder(
                        ENDPOINT, request -> CompletableFuture.failedFuture(new IllegalStateException("offline")))
                .build();
        assertThrows(
                CompletionException.class,
                () -> broken.verify(assertion("one", "status"), context(AssertionOperation.STATUS))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void rejectsUnsafeConfigurationAndMalformedAssertion() {
        AepHttpTransport unused = request -> {
            throw new AssertionError("Must not send a request");
        };
        for (String endpoint : List.of(
                "http://platform.example/v",
                "https:/verify",
                "/v",
                "https://user:pass@platform.example/v",
                "https://platform.example/v#fragment")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostedPlatformClientAssertionVerifier.builder(URI.create(endpoint), unused)
                            .build());
        }
        for (Duration timeout : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofNanos(1))) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostedPlatformClientAssertionVerifier.builder(ENDPOINT, unused)
                            .timeout(timeout)
                            .build());
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> HostedPlatformClientAssertionVerifier.builder(ENDPOINT, unused)
                        .build()
                        .verify("bad", context(AssertionOperation.STATUS)));
    }

    private static AssertionVerificationContext context(AssertionOperation operation) {
        return new AssertionVerificationContext(
                SERVICE,
                operation,
                operation == AssertionOperation.AUTHENTICATE ? "https://service.example/resource" : null,
                "command-key",
                List.of("ES256"),
                Clock.systemUTC(),
                Duration.ofSeconds(30),
                false);
    }

    private static String assertion(String id, String operation) {
        long now = java.time.Instant.now().getEpochSecond();
        String payload = "{\"iss\":\"" + AGENT + "\",\"sub\":\"" + AGENT + "\",\"aud\":\"" + SERVICE
                + "\",\"op\":\"" + operation + "\",\"iat\":" + now + ",\"exp\":" + (now + 300)
                + ",\"jti\":\"" + id + "\""
                + (operation.equals("authenticate") ? ",\"resource\":\"https://service.example/resource\"" : "") + "}";
        return encoded("{\"alg\":\"ES256\"}") + "." + encoded(payload) + ".c2ln";
    }

    private static String encoded(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String success(String operation) {
        return "{\"verified\":true,\"reason\":\"verified\",\"status\":\"active\",\"agent_identity_id\":\"pai_one\","
                + "\"agent_did\":\"" + AGENT + "\",\"service_did\":\"" + SERVICE + "\",\"op\":\"" + operation + "\"}";
    }

    private static AepHttpTransport.Response response(int status, String body) {
        return new AepHttpTransport.Response(status, Map.of(), body.getBytes(StandardCharsets.UTF_8));
    }
}
