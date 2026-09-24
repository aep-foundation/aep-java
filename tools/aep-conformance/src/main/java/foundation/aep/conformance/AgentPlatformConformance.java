package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import foundation.aep.agent.AgentIdentity;
import foundation.aep.agent.PlatformIdentityProvider;
import foundation.aep.agent.PlatformSignPendingException;
import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.DidWeb;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.platform.PlatformIdentityListQuery;
import foundation.aep.platform.PlatformRequestContext;
import foundation.aep.platform.PlatformResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;

final class AgentPlatformConformance {
    private static final String KEY_FIELD = "idempotency_key_header";
    private static final String LIST_RESPONSE = "list-response";
    private static final String SIGN_REQUEST = "sign-request";
    private static final String SERVICE_DID = "did:web:api.service.example";
    private static final String SERVICE_FIELD = "service_did";
    private static final String SIGN_RESPONSE = "sign-response";
    private static final Instant NOW = Instant.parse("2026-07-06T12:00:00Z");
    private static final String IDENTITY_PATH = "/v1/aep/agent-identities";
    private static final String IDEMPOTENCY_HEADER = "Idempotency-Key";
    private static final Map<String, Object> CONTEXT = Map.of("authorization_handle", "opaque-value");

    private AgentPlatformConformance() {}

    static boolean evaluate(AdapterRequest vector) {
        return switch (vector.vector().id()) {
            case "discovery", LIST_RESPONSE, "provision-request", "provision-response" -> provision(vector);
            case "provision-response-distinct-services" -> distinct(vector);
            case SIGN_REQUEST, SIGN_RESPONSE, "sign-response-pending", "idempotency-replay-conflict" -> sign(vector);
            default -> throw ConformanceSupport.unmapped(vector);
        };
    }

    private static boolean provision(AdapterRequest vector) {
        Exchange exchange = new Exchange(false);
        JsonNode expected = vector.testCase().expected();
        String key = expected.has(KEY_FIELD) ? expected.get(KEY_FIELD).asText() : "provision";
        PlatformIdentityProvider provider =
                provider(exchange).idempotencyKeys(() -> key).build();
        if (LIST_RESPONSE.equals(vector.vector().id())) exchange.provision(SERVICE_DID);
        AgentIdentity identity = provider.getOrCreate(URI.create("https://api.service.example"), SERVICE_DID)
                .toCompletableFuture()
                .join();
        if (!identity.did().equals(exchange.identities.get(0).agentDid())) return false;
        return switch (vector.vector().id()) {
            case "discovery" ->
                ConformanceSupport.jsonEquals(
                                exchange.fixture.platform().discovery().body(), expected)
                        && exchange.requests.get(0).headers().get("Authorization") == null;
            case LIST_RESPONSE ->
                ConformanceSupport.jsonEquals(exchange.listResponse, expected)
                        && exchange.requests.stream().noneMatch(request -> "POST".equals(request.method()));
            case "provision-request" -> {
                var request = exchange.requests.get(exchange.requests.size() - 1);
                yield ConformanceSupport.json(new String(request.body(), StandardCharsets.UTF_8))
                                .equals(vector.testCase().input())
                        && request.headers().get(IDEMPOTENCY_HEADER).equals(List.of(key));
            }
            default -> ConformanceSupport.jsonEquals(exchange.identities.get(0), expected);
        };
    }

    private static boolean distinct(AdapterRequest vector) {
        Exchange exchange = new Exchange(false);
        PlatformIdentityProvider provider = provider(exchange).build();
        JsonNode input = vector.testCase().input();
        String firstDid = input.path("first_request").path(SERVICE_FIELD).asText();
        String secondDid = input.path("second_request").path(SERVICE_FIELD).asText();
        var first = provider.getOrCreate(DidWeb.documentUri(firstDid).resolve("/"), firstDid)
                .toCompletableFuture()
                .join();
        exchange.fixture.advanceMinute();
        var second = provider.getOrCreate(DidWeb.documentUri(secondDid).resolve("/"), secondDid)
                .toCompletableFuture()
                .join();
        return !first.did().equals(second.did())
                && ConformanceSupport.jsonEquals(
                        exchange.identities.get(0), vector.testCase().expected().get("first_response"))
                && ConformanceSupport.jsonEquals(
                        exchange.identities.get(1), vector.testCase().expected().get("second_response"));
    }

    private static boolean sign(AdapterRequest vector) {
        String id = vector.vector().id();
        boolean continuation = "idempotency-replay-conflict".equals(id);
        boolean pending = "sign-response-pending".equals(id);
        Exchange exchange = new Exchange(pending || continuation);
        exchange.provision(SERVICE_DID);
        JsonNode input = vector.testCase().input();
        JsonNode expected = vector.testCase().expected();
        List<String> keys = continuation
                ? List.of(
                        input.path("initial_sign_key").asText(),
                        input.path("final_sign_key").asText())
                : List.of(
                        input.has(KEY_FIELD)
                                ? input.path(KEY_FIELD).asText()
                                : expected.has(KEY_FIELD)
                                        ? expected.path(KEY_FIELD).asText()
                                        : "sign");
        AtomicInteger index = new AtomicInteger();
        var builder = provider(exchange)
                .idempotencyKeys(() -> keys.get(index.getAndIncrement()))
                .platformContext((identity, claims) -> CompletableFuture.completedFuture(CONTEXT));
        if (continuation)
            builder.pendingSignResolver(value -> CompletableFuture.completedFuture(value.platformContext()));
        var identity = builder.build()
                .getOrCreate(URI.create("https://api.service.example"), SERVICE_DID)
                .toCompletableFuture()
                .join();
        String jwtId = input.has("jti") ? input.path("jti").asText() : "01J0AEPASSERTION0000000001";
        var claims = new ClientAssertionClaims(
                identity.did(),
                identity.did(),
                SERVICE_DID,
                AssertionOperation.ENROLL,
                NOW.getEpochSecond(),
                NOW.plusSeconds(300).getEpochSecond(),
                jwtId,
                null);
        try {
            String token = identity.signer().sign(claims).toCompletableFuture().join();
            if (pending || !ClientAssertions.decodeUnverified(token).equals(claims)) return false;
            var signRequests = exchange.requests.stream()
                    .filter(request -> request.uri().getPath().endsWith("/sign"))
                    .toList();
            if (!signRequests.stream()
                    .map(request -> request.headers().get(IDEMPOTENCY_HEADER).get(0))
                    .toList()
                    .equals(keys)) return false;
            if (SIGN_REQUEST.equals(id))
                return ConformanceSupport.json(new String(signRequests.get(0).body(), StandardCharsets.UTF_8))
                        .equals(input);
            if (SIGN_RESPONSE.equals(id)) {
                var actual = ConformanceSupport.json(AepJson.write(exchange.signResponse))
                        .deepCopy();
                ((com.fasterxml.jackson.databind.node.ObjectNode) actual)
                        .put(
                                "client_assertion",
                                expected.path("client_assertion").asText());
                return actual.equals(expected);
            }
            return signRequests.size() == 2 && !keys.get(0).equals(keys.get(1)) && replayConflict(vector);
        } catch (CompletionException failure) {
            if (!pending || !(failure.getCause() instanceof PlatformSignPendingException waiting)) throw failure;
            return waiting.pending().retryAfterSeconds()
                            == Integer.parseInt(
                                    expected.path("retry_after_seconds").asText())
                    && ConformanceSupport.jsonEquals(
                            waiting.pending().platformContext(), expected.get("platform_context"))
                    && identity.did().equals(waiting.pending().identity().agentDid());
        }
    }

    private static boolean replayConflict(AdapterRequest vector) {
        Exchange exchange = new Exchange(false);
        exchange.provision(SERVICE_DID);
        String key = vector.testCase().input().path("initial_sign_key").asText();
        var identity = provider(exchange)
                .idempotencyKeys(() -> key)
                .build()
                .getOrCreate(URI.create("https://api.service.example"), SERVICE_DID)
                .toCompletableFuture()
                .join();
        var claims = new ClientAssertionClaims(
                identity.did(),
                identity.did(),
                SERVICE_DID,
                AssertionOperation.ENROLL,
                NOW.getEpochSecond(),
                NOW.plusSeconds(300).getEpochSecond(),
                "replay",
                null);
        String first = identity.signer().sign(claims).toCompletableFuture().join();
        String replay = identity.signer().sign(claims).toCompletableFuture().join();
        if (!first.equals(replay)) return false;
        var changed = new ClientAssertionClaims(
                identity.did(),
                identity.did(),
                SERVICE_DID,
                AssertionOperation.ENROLL,
                claims.issuedAt(),
                claims.expiresAt(),
                "different",
                null);
        try {
            identity.signer().sign(changed).toCompletableFuture().join();
            return false;
        } catch (CompletionException rejected) {
            return rejected.getCause() instanceof foundation.aep.agent.AepAgentException failure
                    && failure.status()
                            == vector.testCase()
                                    .expected()
                                    .path("changed_input_or_operation_status")
                                    .asInt()
                    && failure.code()
                            .equals(vector.testCase()
                                    .expected()
                                    .path("changed_input_or_operation_code")
                                    .asText());
        }
    }

    private static PlatformIdentityProvider.Builder provider(Exchange exchange) {
        return PlatformIdentityProvider.builder(URI.create("https://p.example"))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .transport(exchange)
                .authorization("Bearer platform-access");
    }

    private static final class Exchange implements AepHttpTransport {
        private final PlatformConformance.Fixture fixture;
        private final List<Request> requests = new ArrayList<>();
        private final List<PlatformAgentIdentity> identities = new ArrayList<>();
        private Object listResponse;
        private Object signResponse;

        Exchange(boolean pending) {
            AtomicInteger stages = new AtomicInteger();
            fixture = PlatformConformance.fixture(
                    true,
                    true,
                    (identity, request, context) -> CompletableFuture.completedFuture(
                            pending && stages.getAndIncrement() == 0
                                    ? Optional.of(new PlatformResponse<>(
                                            202,
                                            Aep.MEDIA_TYPE,
                                            new PlatformSignResponses.Pending("pending", CONTEXT, "5"),
                                            null,
                                            Map.of()))
                                    : Optional.empty()));
        }

        void provision(String did) {
            identities.add(fixture.platform()
                    .provision(new PlatformProvisionRequest(did), fixture.context("seed"))
                    .toCompletableFuture()
                    .join()
                    .body());
        }

        @Override
        public CompletionStage<Response> execute(Request request) {
            requests.add(request);
            String path = request.uri().getPath();
            if (Aep.PLATFORM_WELL_KNOWN_PATH.equals(path))
                return CompletableFuture.completedFuture(
                        response(fixture.platform().discovery()));
            if (!List.of("Bearer platform-access").equals(request.headers().get("Authorization"))) {
                throw new IllegalArgumentException("Private Platform request lacks authentication");
            }
            String key = request.headers()
                    .getOrDefault(IDEMPOTENCY_HEADER, List.of(""))
                    .get(0);
            PlatformRequestContext context = fixture.context(key);
            String body = new String(request.body(), StandardCharsets.UTF_8);
            if (IDENTITY_PATH.equals(path) && "GET".equals(request.method())) {
                String did = URLDecoder.decode(
                        request.uri().getRawQuery().split("service_did=", 2)[1], StandardCharsets.UTF_8);
                return fixture.platform()
                        .list(new PlatformIdentityListQuery(true, 100, 0, did, null), context)
                        .thenApply(result -> {
                            listResponse = result.body();
                            return response(result);
                        });
            }
            if (IDENTITY_PATH.equals(path) && "POST".equals(request.method())) {
                return fixture.platform()
                        .provision(AepJson.parsePlatformProvisionRequest(body), context)
                        .thenApply(result -> {
                            identities.add(result.body());
                            return response(result);
                        });
            }
            if (path.endsWith("/sign")) {
                String identityId = path.substring(IDENTITY_PATH.length() + 1, path.length() - "/sign".length());
                return fixture.platform()
                        .sign(identityId, AepJson.parsePlatformSignRequest(body), context)
                        .thenApply(result -> {
                            signResponse = result.body();
                            return response(result);
                        });
            }
            throw new IllegalArgumentException("Unexpected Platform route: " + path);
        }

        private static Response response(PlatformResponse<?> result) {
            return new Response(
                    result.status(),
                    Map.of("Content-Type", List.of(result.contentType())),
                    AepJson.write(result.problem() == null ? result.body() : result.problem())
                            .getBytes(StandardCharsets.UTF_8));
        }
    }
}
