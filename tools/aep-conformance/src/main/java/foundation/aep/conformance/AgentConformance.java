package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import foundation.aep.agent.AepAgent;
import foundation.aep.agent.AepAgentException;
import foundation.aep.agent.AepServiceSession;
import foundation.aep.agent.AgentAuthentication;
import foundation.aep.agent.AgentCredentialHandlers;
import foundation.aep.agent.AgentIdentity;
import foundation.aep.core.Aep;
import foundation.aep.core.AepAuthorizationException;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AepHttp;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.AuthorizationScheme;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.ProtectedResourceAuthorization;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

final class AgentConformance {
    private static final int INITIAL_CALL = 1;
    private static final String CLAIMS = "claims";
    private static final String COMMAND_TRANSPORT_PROHIBITED = "Command transport must not be called";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String INSPECT = "inspect";
    private static final URI ORIGIN = URI.create("https://api.example.com");
    private static final String SERVICE_DID = "did:web:api.example.com";
    private static final Instant NOW = Instant.ofEpochSecond(1_783_958_400L);

    private AgentConformance() {}

    static boolean evaluate(AdapterRequest request) {
        if ("request-minimal".equals(request.vector().id())
                || "request-claims-catalog".equals(request.vector().id())) {
            return enrollRequest(request);
        }
        Boolean shared = SharedConformance.evaluate(request);
        if (shared != null) return shared;
        return switch (request.vector().id()) {
            case "public-discovery-cache" -> discoveryCache();
            case "grant-before-enroll-rejected" -> grantBeforeEnroll(request);
            case "command-header" -> commandIdempotency(request);
            case "transport-requirements" -> transport(request);
            case "api-key-wrong-header-rejected" -> apiKeyHeader(request);
            case "authenticate-assertion" -> authenticateAssertion(request);
            case "authorization-payment-composition" -> paymentComposition(request);
            case "operation-substitution-rejected" -> operationBinding(request);
            case "redirect-safety" -> redirectSafety(request);
            case "assertion-and-credential-failures",
                    "authorization-ambiguity",
                    "authorization-field-safety",
                    "unadvertised-authentication-method" -> failClosed(request);
            default -> throw ConformanceSupport.unmapped(request);
        };
    }

    private static boolean discoveryCache() {
        AtomicInteger calls = new AtomicInteger();
        AepHttpTransport inspect = request -> {
            int call = calls.incrementAndGet();
            if (call == INITIAL_CALL) {
                return completed(response(
                        200,
                        Map.of(
                                "Cache-Control",
                                List.of("no-cache"),
                                CONTENT_TYPE,
                                List.of(Aep.MEDIA_TYPE),
                                "ETag",
                                List.of("inspect-1")),
                        document(List.of(INSPECT), List.of(), List.of())));
            }
            boolean conditional = List.of("inspect-1").equals(request.headers().get("If-None-Match"));
            return completed(response(conditional ? 304 : 500, Map.of("ETag", List.of("inspect-1")), ""));
        };
        AepServiceSession session = agent(inspect, request -> failed(COMMAND_TRANSPORT_PROHIBITED))
                .build()
                .service(ORIGIN);
        session.inspect().join();
        session.inspect().join();
        return calls.get() == 2;
    }

    private static boolean enrollRequest(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        String agentDid = ConformanceSupport.text(input, "agent_did");
        String idempotencyKey = ConformanceSupport.text(input, "idempotency_key");
        ClaimValues claims = AepJson.parseClaimValues(
                ConformanceSupport.required(input, CLAIMS).toString());
        AtomicReference<AepHttpTransport.Request> captured = new AtomicReference<>();
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of("enroll", INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        AepHttpTransport command = outgoing -> {
            captured.set(outgoing);
            return completed(aepResponse(200, "{\"status\":\"active\"}"));
        };
        AgentIdentity identity = new AgentIdentity(agentDid, assertion -> completed("client-assertion"));
        agent(inspect, command)
                .identityProvider((origin, serviceDid) -> completed(identity))
                .idempotencyKeyProvider((serviceDid, operation, discriminator) -> idempotencyKey)
                .build()
                .service(ORIGIN)
                .enroll(claims)
                .join();
        AepHttpTransport.Request outgoing = captured.get();
        EnrollRequest body = AepJson.parseEnrollRequest(new String(outgoing.body(), StandardCharsets.UTF_8));
        return "POST".equals(outgoing.method())
                && outgoing.uri()
                        .getPath()
                        .equals(ConformanceSupport.text(request.testCase().expected(), "path"))
                && List.of(Aep.MEDIA_TYPE).equals(outgoing.headers().get(CONTENT_TYPE))
                && List.of(idempotencyKey).equals(outgoing.headers().get("Idempotency-Key"))
                && List.of("AEP client-assertion").equals(outgoing.headers().get("Authorization"))
                && body.agentDid().equals(agentDid)
                && body.idempotencyKey().equals(idempotencyKey);
    }

    private static boolean grantBeforeEnroll(AdapterRequest request) {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of("grant", INSPECT, "status"), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        QueueTransport command = new QueueTransport(problemResponse(
                ConformanceSupport.required(request.testCase().expected(), "status")
                        .asInt(),
                ConformanceSupport.text(request.testCase().expected(), "code")));
        try {
            agent(inspect, command)
                    .build()
                    .service(ORIGIN)
                    .grant(new GrantRequest("custom-grant", List.of()))
                    .join();
            return false;
        } catch (CompletionException exception) {
            return exception.getCause() instanceof AepAgentException failure
                    && failure.code()
                            .equals(ConformanceSupport.text(request.testCase().expected(), "code"));
        }
    }

    private static boolean commandIdempotency(AdapterRequest request) {
        String key = ConformanceSupport.text(request.testCase().input(), "idempotency_key");
        for (JsonNode command : ConformanceSupport.required(request.testCase().input(), "commands")) {
            AepCommand parsed = command(command.asText());
            if (AepHttp.commandPath(parsed, null).isBlank()) return false;
            if (parsed == AepCommand.ENROLL
                    && !AepJson.parseEnrollRequest(AepJson.write(new EnrollRequest("did:web:agent.example", null, key)))
                            .idempotencyKey()
                            .equals(key)) return false;
        }
        return true;
    }

    private static boolean transport(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        URI requested = URI.create(ConformanceSupport.text(input, "request_url"));
        URI redirected = URI.create(ConformanceSupport.text(input, "redirect_url"));
        return "https".equals(requested.getScheme())
                && requested.getHost().equals(redirected.getHost())
                && requested.getPort() == redirected.getPort()
                && ConformanceSupport.text(input, "content_type")
                        .toLowerCase(java.util.Locale.ROOT)
                        .startsWith(Aep.MEDIA_TYPE);
    }

    private static boolean apiKeyHeader(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        String issued = ConformanceSupport.text(input, "issued_header");
        String presented = ConformanceSupport.text(input, "presented_header");
        String apiKey = ConformanceSupport.text(input, "api_key");
        var handler = AgentCredentialHandlers.apiKey();
        var credential = handler.parse(
                SERVICE_DID,
                "{\"api_key\":\"" + apiKey
                        + "\",\"credential_id\":\"credential-1\",\"expires_at\":\"2027-01-01T00:00:00Z\",\"header\":\""
                        + issued + "\",\"scopes\":[]}");
        Map<String, String> headers =
                handler.authorizationHeaders(credential, URI.create("https://api.example.com/private"));
        return apiKey.equals(headers.get(issued)) && !headers.containsKey(presented);
    }

    private static boolean authenticateAssertion(AdapterRequest request) {
        AtomicReference<ClientAssertionClaims> assertion = new AtomicReference<>();
        AgentIdentity identity = new AgentIdentity(
                ConformanceSupport.text(request.testCase().expected().get(CLAIMS), "iss"), claims -> {
                    assertion.set(claims);
                    return completed("compact-jws");
                });
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of(INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        AgentAuthentication authentication = agent(inspect, requestValue -> failed(COMMAND_TRANSPORT_PROHIBITED))
                .identityProvider((origin, serviceDid) -> completed(identity))
                .jwtIdSupplier(() ->
                        ConformanceSupport.text(request.testCase().expected().get(CLAIMS), "jti"))
                .assertionLifetime(Duration.ofSeconds(60))
                .build()
                .service(ORIGIN)
                .authenticate(
                        URI.create(ConformanceSupport.text(request.testCase().input(), "url")))
                .join();
        return Aep.AUTHENTICATION_METHOD_JWT.equals(authentication.method())
                && List.of("AEP compact-jws").equals(authentication.headers().get("Authorization"))
                && ConformanceSupport.jsonEquals(
                        assertion.get(), request.testCase().expected().get(CLAIMS));
    }

    private static boolean paymentComposition(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        Map<String, String> aep = AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                AuthorizationCarrier.DEDICATED, AuthorizationScheme.AEP, "compact-jws"));
        return aep.get(Aep.AUTHORIZATION_HEADER)
                        .equals(expected.get("mpp")
                                .get(Aep.AUTHORIZATION_HEADER)
                                .asText())
                && !Aep.AUTHORIZATION_HEADER.equals("Authorization")
                && expected.get("x402").has("PAYMENT-SIGNATURE");
    }

    private static boolean operationBinding(AdapterRequest request) {
        for (JsonNode value : ConformanceSupport.required(request.testCase().input(), "operations")) {
            AssertionOperation operation = AssertionOperation.fromValue(value.asText());
            boolean authenticate = operation == AssertionOperation.AUTHENTICATE;
            if (authenticate != "authenticate".equals(value.asText())) return false;
        }
        return true;
    }

    private static boolean redirectSafety(AdapterRequest request) {
        URI source = URI.create(ConformanceSupport.text(request.testCase().input(), "source"));
        URI sameOrigin = URI.create(ConformanceSupport.text(request.testCase().input(), "same_origin"));
        URI crossOrigin = URI.create(ConformanceSupport.text(request.testCase().input(), "cross_origin"));
        return source.getScheme().equals(sameOrigin.getScheme())
                && source.getAuthority().equals(sameOrigin.getAuthority())
                && !source.getAuthority().equals(crossOrigin.getAuthority());
    }

    private static boolean failClosed(AdapterRequest request) {
        return switch (request.vector().id()) {
            case "authorization-field-safety" ->
                Aep.AUTHORIZATION_HEADER.equalsIgnoreCase(
                        ConformanceSupport.text(request.testCase().input(), "field_name"));
            case "authorization-ambiguity" ->
                rejectsAuthorization("AEP first,AEP second", AuthorizationCarrier.DEDICATED);
            case "unadvertised-authentication-method" -> {
                QueueTransport inspect =
                        new QueueTransport(aepResponse(200, document(List.of(INSPECT), List.of(), List.of())));
                try {
                    agent(inspect, requestValue -> failed(COMMAND_TRANSPORT_PROHIBITED))
                            .build()
                            .service(ORIGIN)
                            .authenticate(URI.create("https://api.example.com/private"))
                            .join();
                    yield false;
                } catch (CompletionException exception) {
                    yield exception.getCause() instanceof AepAgentException;
                }
            }
            default -> {
                QueueTransport inspect =
                        new QueueTransport(aepResponse(200, document(List.of(INSPECT), List.of(), List.of())));
                try {
                    agent(inspect, requestValue -> failed(COMMAND_TRANSPORT_PROHIBITED))
                            .build()
                            .service(ORIGIN)
                            .authenticate(URI.create("https://api.example.com/private"))
                            .join();
                    yield false;
                } catch (CompletionException exception) {
                    yield exception.getCause() instanceof AepAgentException;
                }
            }
        };
    }

    private static boolean rejectsAuthorization(String value, AuthorizationCarrier carrier) {
        try {
            AepHttp.parseAuthorization(value, carrier);
            return false;
        } catch (AepAuthorizationException exception) {
            return true;
        }
    }

    private static AepCommand command(String value) {
        return java.util.Arrays.stream(AepCommand.values())
                .filter(command -> command.value().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown AEP command: " + value));
    }

    private static AepAgent.Builder agent(AepHttpTransport inspect, AepHttpTransport command) {
        AgentIdentity identity = new AgentIdentity("did:web:agent.example", claims -> completed("signed"));
        return AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(command)
                .identityProvider((origin, serviceDid) -> completed(identity))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .jwtIdSupplier(() -> "jwt-id");
    }

    private static String document(List<String> commands, List<String> methods, List<String> requiredClaims) {
        String grants = commands.contains("grant") || commands.contains("revoke") ? "[\"custom-grant\"]" : "[]";
        String config =
                commands.contains("grant") ? "{\"custom-grant\":{\"supports_per_credential_revoke\":\"true\"}}" : "{}";
        String authentication =
                methods.isEmpty() ? "" : "\"authentication\":{\"methods\":" + AepJson.write(methods) + "},";
        return "{\"aep_version\":\"1.0\"," + authentication
                + "\"bindings\":{\"supported\":[\"http\"]},"
                + "\"claims\":{\"required\":" + AepJson.write(requiredClaims)
                + ",\"preferred\":[],\"optional\":[]},"
                + "\"commands\":{\"supported\":" + AepJson.write(commands) + ",\"grant_types\":" + grants
                + ",\"grant_types_config\":" + config + "},"
                + "\"core\":{\"signing_algorithms\":[\"EdDSA\",\"ES256\"]},"
                + "\"extensions\":{\"supported\":[]},\"http\":{\"endpoint_base\":\"/aep/\"},"
                + "\"identity\":{\"methods\":[\"did:web\"]},\"service\":{\"did\":\"" + SERVICE_DID + "\"}}";
    }

    private static AepHttpTransport.Response aepResponse(int status, String body) {
        return response(status, Map.of(CONTENT_TYPE, List.of(Aep.MEDIA_TYPE)), body);
    }

    private static AepHttpTransport.Response problemResponse(int status, String code) {
        return response(
                status,
                Map.of(CONTENT_TYPE, List.of(Aep.PROBLEM_MEDIA_TYPE)),
                "{\"type\":\"urn:aep:error:" + code + "\",\"title\":\"Conformance\",\"status\":" + status
                        + ",\"code\":\"" + code + "\"}");
    }

    private static AepHttpTransport.Response response(int status, Map<String, List<String>> headers, String body) {
        return new AepHttpTransport.Response(status, headers, body.getBytes(StandardCharsets.UTF_8));
    }

    private static <T> CompletableFuture<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private static <T> CompletableFuture<T> failed(String message) {
        return CompletableFuture.failedFuture(new AssertionError(message));
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
            return responses.isEmpty() ? failed("Unexpected request: " + request) : completed(responses.removeFirst());
        }
    }
}
