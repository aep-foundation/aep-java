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
    private static final String REVOKE = "revoke";
    private static final String GET_METHOD = "GET";
    private static final String GRANT_REVOKE = "grant-revoke";
    private static final int INITIAL_CALL = 1;
    private static final String CLAIMS = "claims";
    private static final String COMMAND_TRANSPORT_PROHIBITED = "Command transport must not be called";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String INSPECT = "inspect";
    private static final String GRANT = "grant";
    private static final String STATUS = "status";
    private static final String CUSTOM_GRANT = "custom-grant";
    private static final String COMPACT_JWS = "compact-jws";
    private static final String ETAG = "inspect-1";
    private static final String IF_NONE_MATCH = "If-None-Match";
    private static final int SINGLE_FIELD = 1;
    private static final String AGENT_DID = "did:web:agent.example";
    private static final URI ORIGIN = URI.create("https://api.example.com");
    private static final String SERVICE_DID = "did:web:api.example.com";
    private static final String SERVICE_ORIGIN_BINDING = "service-did-origin-binding";
    private static final String PLATFORM = "platform";
    private static final Instant NOW = Instant.ofEpochSecond(1_783_958_400L);

    private AgentConformance() {}

    static boolean evaluate(AdapterRequest request) {
        if (PLATFORM.equals(request.vector().category())) return AgentPlatformConformance.evaluate(request);
        if (GRANT_REVOKE.equals(request.vector().category())
                && request.testCase().expected().has("authorization_scheme")) return commandWire(request);
        if (SERVICE_ORIGIN_BINDING.equals(request.vector().id())) return serviceOriginBinding(request);
        if ("request-minimal".equals(request.vector().id())
                || "request-claims-catalog".equals(request.vector().id())) {
            return enrollRequest(request);
        }
        Boolean shared = SharedConformance.evaluate(request);
        if (shared != null) return shared;
        return switch (request.vector().id()) {
            case "public-discovery-cache" -> discoveryCache(request);
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

    private static boolean commandWire(AdapterRequest vector) {
        if (!Boolean.TRUE.equals(SharedConformance.evaluate(vector))) return false;
        JsonNode expected = vector.testCase().expected();
        AssertionOperation operation =
                AssertionOperation.fromValue(ConformanceSupport.text(expected, "client_assertion_op"));
        String document = document(
                        List.of(GRANT, REVOKE, STATUS, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())
                .replace(CUSTOM_GRANT, Aep.GRANT_TYPE_OAUTH_BEARER);
        AtomicReference<ClientAssertionClaims> claims = new AtomicReference<>();
        AtomicReference<AepHttpTransport.Request> captured = new AtomicReference<>();
        var session = agent(new QueueTransport(aepResponse(200, document)), outgoing -> {
                    if (GET_METHOD.equals(outgoing.method()))
                        return completed(aepResponse(200, "{\"status\":\"active\"}"));
                    captured.set(outgoing);
                    String response = operation == AssertionOperation.GRANT
                            ? "{\"access_token\":\"token\",\"credential_id\":\"credential-1\",\"expires_at\":\"2027-01-01T00:00:00Z\",\"token_type\":\"Bearer\",\"format\":\"opaque\"}"
                            : "{}";
                    return completed(aepResponse(200, response));
                })
                .identityProvider((origin, did) -> completed(new AgentIdentity(AGENT_DID, value -> {
                    claims.set(value);
                    return completed(COMPACT_JWS);
                })))
                .build()
                .service(ORIGIN);
        if (operation == AssertionOperation.GRANT) {
            session.grant(AepJson.parseGrantRequest(vector.testCase().input().toString()))
                    .join();
        } else {
            session.revoke(AepJson.parseRevokeRequest(vector.testCase().input().toString()))
                    .join();
        }
        AepHttpTransport.Request sent = captured.get();
        JsonNode body = ConformanceSupport.json(new String(sent.body(), StandardCharsets.UTF_8));
        for (String missing : ConformanceSupport.strings(expected, "must_not_contain")) {
            if (body.has(missing)) return false;
        }
        return sent.method().equals(ConformanceSupport.text(expected, "method"))
                && sent.uri().getPath().equals(ConformanceSupport.text(expected, "path"))
                && sent.headers().get(CONTENT_TYPE).equals(List.of(ConformanceSupport.text(expected, "content_type")))
                && sent.headers()
                        .get("Authorization")
                        .equals(List.of(ConformanceSupport.text(expected, "authorization_scheme") + " " + COMPACT_JWS))
                && claims.get().operation() == operation
                && ConformanceSupport.preserves(
                        operation == AssertionOperation.GRANT
                                ? AepJson.parseGrantRequest(body.toString())
                                : AepJson.parseRevokeRequest(body.toString()),
                        expected.get("body"));
    }

    private static boolean serviceOriginBinding(AdapterRequest vector) {
        JsonNode input = vector.testCase().input();
        JsonNode expected = vector.testCase().expected();
        URI origin = URI.create(ConformanceSupport.text(input, "inspect_url")).resolve("/");
        for (String field : List.of("matching_service_did", "mismatched_service_did", "unsupported_service_did")) {
            String did = ConformanceSupport.text(input, field);
            String inspectDocument = document(List.of(INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())
                    .replace(SERVICE_DID, did);
            AtomicInteger identities = new AtomicInteger();
            AtomicInteger assertions = new AtomicInteger();
            AtomicInteger requests = new AtomicInteger();
            var session = agent(new QueueTransport(aepResponse(200, inspectDocument)), outgoing -> {
                        requests.incrementAndGet();
                        return failed(COMMAND_TRANSPORT_PROHIBITED);
                    })
                    .identityProvider((serviceOrigin, serviceDid) -> {
                        identities.incrementAndGet();
                        return completed(new AgentIdentity(AGENT_DID, claims -> {
                            assertions.incrementAndGet();
                            return completed(COMPACT_JWS);
                        }));
                    })
                    .build()
                    .service(origin);
            try {
                session.authenticate(origin.resolve("private")).join();
                if (!"accept".equals(ConformanceSupport.text(expected, field))
                        || identities.get() != 1
                        || assertions.get() != 1) return false;
            } catch (CompletionException rejected) {
                if (!(rejected.getCause() instanceof AepAgentException failure)
                        || !failure.code().equals(ConformanceSupport.text(expected, field))
                        || identities.get() != 0
                        || assertions.get() != 0
                        || requests.get() != 0) return false;
            }
        }
        return !expected.path("provision_identity").asBoolean()
                && !expected.path("request_assertion").asBoolean()
                && !expected.path("transmit_credentials").asBoolean();
    }

    /**
     * Drives the five caching behaviours expected names: the SDK's default freshness lifetime,
     * no-cache revalidation, no-store non-persistence, reuse of a 304-validated representation, and
     * the cache key taken from the final safe redirect URL.
     */
    private static boolean discoveryCache(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        Duration freshness =
                Duration.ofSeconds(Long.parseLong(ConformanceSupport.text(expected, "default_freshness_seconds")));
        return defaultFreshness(freshness)
                && "revalidate".equals(ConformanceSupport.text(expected, "no_cache"))
                && revalidatesNoCache()
                && "do-not-persist".equals(ConformanceSupport.text(expected, "no_store"))
                && discardsNoStore()
                && "reuse-validated-representation".equals(ConformanceSupport.text(expected, "status_304"))
                && reusesValidated()
                && "final-safe-redirect-url".equals(ConformanceSupport.text(expected, "cache_key"))
                && keysOnFinalUrl();
    }

    /**
     * A response carrying no Cache-Control is reusable for the SDK's own default lifetime, which is
     * the one the vector publishes. The agent is built without configuring freshness so the default
     * under test is the SDK's, not the vector's value handed back to itself.
     */
    private static boolean defaultFreshness(Duration freshness) {
        AtomicInteger calls = new AtomicInteger();
        MovableClock clock = new MovableClock(NOW);
        AepServiceSession session = cachingSession(
                clock,
                requestValue ->
                        completed(counted(calls, aepResponse(200, document(List.of(INSPECT), List.of(), List.of())))));
        session.inspect().join();
        clock.advance(freshness.minusSeconds(1));
        session.inspect().join();
        if (calls.get() != INITIAL_CALL) return false;
        clock.advance(Duration.ofSeconds(2));
        session.inspect().join();
        return calls.get() == 2;
    }

    /** CORE-DISC-014: no-cache stores the document but forces a conditional request before reuse. */
    private static boolean revalidatesNoCache() {
        List<AepHttpTransport.Request> seen = new ArrayList<>();
        AepServiceSession session = cachingSession(new MovableClock(NOW), requestValue -> {
            seen.add(requestValue);
            return completed(
                    seen.size() == INITIAL_CALL
                            ? cacheable("no-cache", document(List.of(INSPECT), List.of(), List.of()))
                            : response(304, Map.of("ETag", List.of(ETAG)), ""));
        });
        session.inspect().join();
        session.inspect().join();
        return seen.size() == 2 && List.of(ETAG).equals(seen.get(1).headers().get(IF_NONE_MATCH));
    }

    /** no-store forbids persisting the document, so the next call cannot revalidate a stored copy. */
    private static boolean discardsNoStore() {
        List<AepHttpTransport.Request> seen = new ArrayList<>();
        AepServiceSession session = cachingSession(new MovableClock(NOW), requestValue -> {
            seen.add(requestValue);
            return completed(cacheable("no-store", document(List.of(INSPECT), List.of(), List.of())));
        });
        session.inspect().join();
        session.inspect().join();
        return seen.size() == 2 && !seen.get(1).headers().containsKey(IF_NONE_MATCH);
    }

    /** A 304 revalidation reuses the stored representation rather than returning an empty document. */
    private static boolean reusesValidated() {
        AtomicInteger calls = new AtomicInteger();
        AepServiceSession session = cachingSession(
                new MovableClock(NOW),
                requestValue -> completed(
                        calls.incrementAndGet() == INITIAL_CALL
                                ? cacheable("no-cache", document(List.of(INSPECT, STATUS), List.of(), List.of()))
                                : response(304, Map.of("ETag", List.of(ETAG)), "")));
        session.inspect().join();
        var revalidated = session.inspect().join();
        return SERVICE_DID.equals(revalidated.document().service().did())
                && revalidated.document().commands().supported().contains(STATUS);
    }

    /** The cache is keyed on the final URL a safe redirect settled on, not the requested one. */
    private static boolean keysOnFinalUrl() {
        URI finalUri = ORIGIN.resolve("/aep/inspect");
        List<AepHttpTransport.Request> seen = new ArrayList<>();
        AepServiceSession session = cachingSession(new MovableClock(NOW), requestValue -> {
            seen.add(requestValue);
            if (seen.size() == INITIAL_CALL) {
                return completed(response(308, Map.of("Location", List.of(finalUri.toString())), ""));
            }
            return completed(cacheable("no-cache", document(List.of(INSPECT), List.of(), List.of())));
        });
        var inspection = session.inspect().join();
        session.inspect().join();
        return finalUri.equals(inspection.documentUri())
                && seen.size() == 3
                && finalUri.equals(seen.get(2).uri())
                && List.of(ETAG).equals(seen.get(2).headers().get(IF_NONE_MATCH));
    }

    private static AepServiceSession cachingSession(Clock clock, AepHttpTransport inspect) {
        AgentIdentity identity = new AgentIdentity(AGENT_DID, claims -> completed("signed"));
        return AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(requestValue -> failed(COMMAND_TRANSPORT_PROHIBITED))
                .identityProvider((origin, serviceDid) -> completed(identity))
                .clock(clock)
                .jwtIdSupplier(() -> "jwt-id")
                .build()
                .service(ORIGIN);
    }

    private static AepHttpTransport.Response cacheable(String cacheControl, String body) {
        return response(
                200,
                Map.of(
                        "Cache-Control",
                        List.of(cacheControl),
                        CONTENT_TYPE,
                        List.of(Aep.MEDIA_TYPE),
                        "ETag",
                        List.of(ETAG)),
                body);
    }

    private static AepHttpTransport.Response counted(AtomicInteger calls, AepHttpTransport.Response response) {
        calls.incrementAndGet();
        return response;
    }

    private static final class MovableClock extends Clock {
        private Instant current;

        MovableClock(Instant start) {
            this.current = start;
        }

        void advance(Duration amount) {
            current = current.plus(amount);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }
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
                && ConformanceSupport.jsonEquals(body.claims(), input.get(CLAIMS))
                && body.idempotencyKey().equals(idempotencyKey);
    }

    private static boolean grantBeforeEnroll(AdapterRequest request) {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of(GRANT, INSPECT, STATUS), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        QueueTransport command = new QueueTransport(problemResponse(
                ConformanceSupport.required(request.testCase().expected(), STATUS)
                        .asInt(),
                ConformanceSupport.text(request.testCase().expected(), "code")));
        try {
            agent(inspect, command)
                    .build()
                    .service(ORIGIN)
                    .grant(new GrantRequest(CUSTOM_GRANT, List.of()))
                    .join();
            return false;
        } catch (CompletionException exception) {
            return exception.getCause() instanceof AepAgentException failure
                    && failure.code()
                            .equals(ConformanceSupport.text(request.testCase().expected(), "code"));
        }
    }

    // expected.header_required is true, so every command input.commands names is issued and the
    // Idempotency-Key is read off the request the Agent actually sent.
    private static boolean commandIdempotency(AdapterRequest request) {
        if (!ConformanceSupport.required(request.testCase().expected(), "header_required")
                .asBoolean()) return false;
        String key = ConformanceSupport.text(request.testCase().input(), "idempotency_key");
        for (JsonNode command : ConformanceSupport.required(request.testCase().input(), "commands")) {
            AepCommand parsed = command(command.asText());
            AepHttpTransport.Request outgoing = issue(parsed, key);
            if (outgoing == null || !List.of(key).equals(outgoing.headers().get("Idempotency-Key"))) return false;
        }
        return true;
    }

    /** Runs one command through an Agent and hands back the request that reached the transport. */
    private static AepHttpTransport.Request issue(AepCommand command, String idempotencyKey) {
        AtomicReference<AepHttpTransport.Request> captured = new AtomicReference<>();
        QueueTransport inspect = new QueueTransport(aepResponse(
                200,
                document(
                        List.of("enroll", GRANT, REVOKE, STATUS, INSPECT),
                        List.of(Aep.AUTHENTICATION_METHOD_JWT),
                        List.of())));
        String path = AepHttp.commandPath(command, null);
        AepHttpTransport transport = outgoing -> {
            // grant runs a status check first, so only the request for the command under test counts.
            if (outgoing.uri().getPath().equals(path)) captured.set(outgoing);
            return completed(aepResponse(
                    200, commandResponse(outgoing.uri().getPath().equals(path) ? command : AepCommand.STATUS)));
        };
        AepServiceSession session = agent(inspect, transport)
                .idempotencyKeyProvider((serviceDid, operation, discriminator) -> idempotencyKey)
                .build()
                .service(ORIGIN);
        try {
            switch (command) {
                case ENROLL -> session.enroll(null).join();
                case GRANT ->
                    session.grant(new GrantRequest(CUSTOM_GRANT, List.of())).join();
                case REVOKE ->
                    session.revoke(new foundation.aep.core.RevokeRequest(CUSTOM_GRANT, null, null))
                            .join();
                default -> {
                    return null;
                }
            }
        } catch (CompletionException rejectedResponse) {
            // A command whose canned response the Agent rejects still produced the request under test.
            assert rejectedResponse != null;
        }
        return captured.get();
    }

    private static AssertionOperation operationOf(AepCommand command) {
        return AssertionOperation.fromValue(command.value());
    }

    private static String commandResponse(AepCommand command) {
        return switch (command) {
            case ENROLL, STATUS -> "{\"status\":\"active\"}";
            case GRANT -> "{\"credential_id\":\"credential-1\"}";
            default -> "{}";
        };
    }

    // Each redirect policy expected names is put to the Agent: a same-origin redirect is followed, a
    // cross-origin one and a scheme downgrade are not, and the advertised media-type essence is
    // accepted with its parameters and casing intact.
    private static boolean transport(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        JsonNode expected = request.testCase().expected();
        URI requested = URI.create(ConformanceSupport.text(input, "request_url"));
        URI redirected = URI.create(ConformanceSupport.text(input, "redirect_url"));
        String contentType = ConformanceSupport.text(input, "content_type");
        if (!contentType
                .toLowerCase(java.util.Locale.ROOT)
                .startsWith(ConformanceSupport.text(expected, "media_type_essence"))) return false;
        if (!inspectFollows(requested, redirected, contentType)) return false;
        boolean rejectsCrossOrigin = "reject".equals(ConformanceSupport.text(expected, "cross_origin_redirect"))
                && inspectRejects(requested, URI.create("https://other.example.net/discovery/aep"), contentType);
        boolean rejectsDowngrade = "reject".equals(ConformanceSupport.text(expected, "scheme_downgrade"))
                && inspectRejects(requested, URI.create("http://api.example.com/discovery/aep"), contentType);
        return rejectsCrossOrigin && rejectsDowngrade;
    }

    /** Answers a redirect to {@code location}, then the document, and reports whether Inspect completed. */
    private static boolean inspectFollows(URI from, URI location, String contentType) {
        try {
            redirectingSession(from, location, contentType).inspect().join();
            return true;
        } catch (CompletionException exception) {
            return false;
        }
    }

    private static boolean inspectRejects(URI from, URI location, String contentType) {
        try {
            redirectingSession(from, location, contentType).inspect().join();
            return false;
        } catch (CompletionException exception) {
            return exception.getCause() instanceof AepAgentException;
        }
    }

    private static AepServiceSession redirectingSession(URI from, URI location, String contentType) {
        AepHttpTransport inspect = outgoing -> outgoing.uri().equals(from)
                ? completed(response(302, Map.of("Location", List.of(location.toString())), ""))
                : completed(response(
                        200,
                        Map.of(CONTENT_TYPE, List.of(contentType)),
                        document(List.of(INSPECT), List.of(), List.of())));
        return agent(inspect, outgoing -> failed(COMMAND_TRANSPORT_PROHIBITED))
                .build()
                .service(URI.create(from.getScheme() + "://" + from.getAuthority()));
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
                    return completed(COMPACT_JWS);
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

    // Each composition in expected names the field the Agent puts its own credential in and the
    // field the payment credential occupies beside it. The Agent must render into the first and
    // leave the second untouched.
    private static boolean paymentComposition(AdapterRequest request) {
        var compositions = request.testCase().expected().fields();
        while (compositions.hasNext()) {
            JsonNode composition = compositions.next().getValue();
            if (!composition.isObject() || !composition.has(Aep.AUTHORIZATION_HEADER)) continue;
            if (composition.path("ambiguous").asBoolean()) return false;
            String carried = ConformanceSupport.text(composition, Aep.AUTHORIZATION_HEADER);
            // The assertion is on the field, not the value: the Agent renders into the one the
            // composition names for it and claims none of the fields beside it.
            Map<String, String> rendered = AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                    AuthorizationCarrier.DEDICATED,
                    carried.startsWith(Aep.AUTHENTICATION_SCHEME + " ")
                            ? AuthorizationScheme.AEP
                            : AuthorizationScheme.BEARER,
                    carried.substring(carried.indexOf(' ') + 1)));
            if (!rendered.containsKey(Aep.AUTHORIZATION_HEADER)) return false;
            var fields = composition.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                if (!field.getValue().isTextual() || Aep.AUTHORIZATION_HEADER.equals(field.getKey())) continue;
                if (rendered.containsKey(field.getKey())) return false;
            }
        }
        return true;
    }

    // expected.allowed pairs each operation with the endpoint it may be presented at. The previous
    // check asked AssertionOperation.fromValue whether its own lookup table was self-consistent; this
    // one reads the operation and resource the Agent puts in the assertion it mints for each command,
    // which is the binding the vector is about.
    private static boolean operationBinding(AdapterRequest request) {
        String resource = ConformanceSupport.text(request.testCase().input(), "protected_resource");
        for (JsonNode pair : ConformanceSupport.required(request.testCase().expected(), "allowed")) {
            String[] parts = pair.asText().split(":", 2);
            AssertionOperation operation = AssertionOperation.fromValue(parts[0]);
            ClientAssertionClaims minted = operation == AssertionOperation.AUTHENTICATE
                    ? mintedForResource(URI.create(resource))
                    : mintedForCommand(command(parts[0]));
            if (minted == null || minted.operation() != operation) return false;
            boolean atResource = "protected-resource".equals(parts[1]);
            if (atResource != resource.equals(minted.resource())) return false;
            if (!atResource && minted.resource() != null) return false;
        }
        return true;
    }

    private static ClientAssertionClaims mintedForCommand(AepCommand command) {
        AtomicReference<ClientAssertionClaims> minted = new AtomicReference<>();
        QueueTransport inspect = new QueueTransport(aepResponse(
                200,
                document(
                        List.of("enroll", GRANT, REVOKE, STATUS, INSPECT),
                        List.of(Aep.AUTHENTICATION_METHOD_JWT),
                        List.of())));
        AssertionOperation wanted = operationOf(command);
        AgentIdentity identity = new AgentIdentity(AGENT_DID, claims -> {
            // grant mints a status assertion first; the one under test is the one for this command.
            if (claims.operation() == wanted) minted.compareAndSet(null, claims);
            return completed(COMPACT_JWS);
        });
        String path = AepHttp.commandPath(command, null);
        AepServiceSession session = agent(
                        inspect,
                        outgoing -> completed(aepResponse(
                                200,
                                commandResponse(outgoing.uri().getPath().equals(path) ? command : AepCommand.STATUS))))
                .identityProvider((origin, serviceDid) -> completed(identity))
                .build()
                .service(ORIGIN);
        try {
            switch (command) {
                case ENROLL -> session.enroll(null).join();
                case GRANT ->
                    session.grant(new GrantRequest(CUSTOM_GRANT, List.of())).join();
                case REVOKE ->
                    session.revoke(new foundation.aep.core.RevokeRequest(CUSTOM_GRANT, null, null))
                            .join();
                case STATUS -> session.status().join();
                default -> {
                    return null;
                }
            }
        } catch (CompletionException rejectedResponse) {
            // The assertion is minted before the response is read, so a rejected response is fine.
            assert rejectedResponse != null;
        }
        return minted.get();
    }

    private static ClientAssertionClaims mintedForResource(URI resource) {
        AtomicReference<ClientAssertionClaims> minted = new AtomicReference<>();
        AgentIdentity identity = new AgentIdentity(AGENT_DID, claims -> {
            minted.compareAndSet(null, claims);
            return completed(COMPACT_JWS);
        });
        QueueTransport inspect = new QueueTransport(
                aepResponse(200, document(List.of(INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        agent(inspect, outgoing -> failed(COMMAND_TRANSPORT_PROHIBITED))
                .identityProvider((origin, serviceDid) -> completed(identity))
                .build()
                .service(ORIGIN)
                .authenticate(resource)
                .join();
        return minted.get();
    }

    // The application owns redirect handling. This checks the headers it can request from one
    // Service session, not whether an application forwards or strips them on the wire.
    private static boolean redirectSafety(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        JsonNode sameOrigin = ConformanceSupport.required(expected, "same_origin");
        if (ConformanceSupport.required(sameOrigin, "credential_forwarded").asBoolean()) return false;
        URI source = URI.create(ConformanceSupport.text(request.testCase().input(), "source"));
        String target = ConformanceSupport.text(sameOrigin, "new_authenticate_assertion_resource");
        List<ClientAssertionClaims> minted = new java.util.ArrayList<>();
        AtomicInteger jwtIds = new AtomicInteger();
        var inspect = new QueueTransport(
                aepResponse(200, document(List.of(INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        JsonNode crossOrigin = ConformanceSupport.required(expected, "cross_origin");
        var session = agent(inspect, outgoing -> failed(COMMAND_TRANSPORT_PROHIBITED))
                .jwtIdSupplier(() -> "redirect-" + jwtIds.incrementAndGet())
                .identityProvider((origin, did) -> completed(new AgentIdentity(AGENT_DID, claims -> {
                    minted.add(claims);
                    return completed("signed-" + claims.jwtId());
                })))
                .build()
                .service(ORIGIN);
        var firstHeaders = session.authenticate(source).join().headers();
        var secondHeaders = session.authenticate(
                        URI.create(ConformanceSupport.text(request.testCase().input(), "same_origin")))
                .join()
                .headers();
        try {
            session.authenticate(URI.create(
                            ConformanceSupport.text(request.testCase().input(), "cross_origin")))
                    .join();
            return false;
        } catch (CompletionException rejected) {
            if (!(rejected.getCause() instanceof AepAgentException failure)
                    || !"origin_mismatch".equals(failure.code())) return false;
        }
        return minted.size() == 2
                && inspect.requests.size() == 1
                && source.toString().equals(minted.get(0).resource())
                && target.equals(minted.get(1).resource())
                && !minted.get(0).jwtId().equals(minted.get(1).jwtId())
                && !firstHeaders.equals(secondHeaders)
                && crossOrigin.path("anonymous_restart").asBoolean()
                && !crossOrigin.path("assertion_forwarded").asBoolean()
                && !crossOrigin.path("session_credential_forwarded").asBoolean()
                && !crossOrigin.path("api_key_header_forwarded").asBoolean();
    }

    private static boolean failClosed(AdapterRequest request) {
        return switch (request.vector().id()) {
            // The carrier utility renders this field; the application's HTTP client owns stripping
            // old headers and selecting the carrier when it follows a protected-resource redirect.
            case "authorization-field-safety" -> {
                String carrier =
                        ConformanceSupport.text(request.testCase().expected(), "redirect_new_assertion_carrier");
                Map<String, String> rendered = AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                        AuthorizationCarrier.DEDICATED, AuthorizationScheme.AEP, COMPACT_JWS));
                yield rendered.containsKey(carrier)
                        && carrier.equalsIgnoreCase(
                                ConformanceSupport.text(request.testCase().input(), "field_name"));
            }
            case "authorization-ambiguity" -> authorizationAmbiguity(request);
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
            default -> credentialFailures(request);
        };
    }

    /**
     * expected maps each failure mode to the code the Agent must surface. Only the modes this SDK
     * decides locally are exercised here; the rest are the Service's to report, and the Agent's job
     * is to carry the Service's code through unchanged, which is what the last case checks.
     */
    private static boolean credentialFailures(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        QueueTransport inspect = new QueueTransport(aepResponse(200, document(List.of(INSPECT), List.of(), List.of())));
        try {
            agent(inspect, requestValue -> failed(COMMAND_TRANSPORT_PROHIBITED))
                    .build()
                    .service(ORIGIN)
                    .authenticate(URI.create("https://api.example.com/private"))
                    .join();
            return false;
        } catch (CompletionException exception) {
            // The codes in this vector are the ones a Service reports. What the Agent owns locally is
            // failing closed when no advertised method is usable, under its own failure identifier.
            if (!(exception.getCause() instanceof AepAgentException)) return false;
        }
        // Every other mode is the Service's to detect; the Agent's part is to surface the code it
        // was given rather than collapsing them all into one.
        java.util.Set<String> codes = new java.util.LinkedHashSet<>();
        expected.fields().forEachRemaining(mode -> codes.add(mode.getValue().asText()));
        return codes.stream().allMatch(AgentConformance::surfacesCommandCode);
    }

    private static boolean surfacesCommandCode(String code) {
        QueueTransport inspect = new QueueTransport(aepResponse(
                200, document(List.of(STATUS, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT), List.of())));
        QueueTransport command = new QueueTransport(problemResponse(401, code));
        try {
            agent(inspect, command).build().service(ORIGIN).status().join();
            return false;
        } catch (CompletionException exception) {
            return exception.getCause() instanceof AepAgentException failure && code.equals(failure.code());
        }
    }

    /**
     * input.cases names four ambiguous presentations and expected names one outcome for all of them:
     * the published code, with no fallback to a second carrier and no credential selected. Every case
     * is driven and every member of expected is read.
     */
    private static boolean authorizationAmbiguity(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        if (ConformanceSupport.required(expected, "fallback").asBoolean()
                || !ConformanceSupport.required(expected, "selected_credential").isNull()) return false;
        String code = ConformanceSupport.text(expected, "code");
        for (JsonNode value : ConformanceSupport.required(request.testCase().input(), "cases")) {
            if (!ambiguous(value.asText(), code)) return false;
        }
        return true;
    }

    private static boolean ambiguous(String name, String code) {
        return switch (name) {
            // An Agent renders one presentation into one field, so it can never be the party that
            // puts an AEP credential in both carriers at once.
            case "both-aep-recognized" ->
                AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                                        AuthorizationCarrier.DEDICATED, AuthorizationScheme.AEP, COMPACT_JWS))
                                .size()
                        == SINGLE_FIELD;
            // A malformed dedicated field is rejected outright; the valid standard field alongside it
            // is not a fallback the Agent may quietly use instead.
            case "invalid-dedicated-plus-valid-standard" ->
                rejects("AEP", AuthorizationCarrier.DEDICATED, code)
                        && AepHttp.parseAuthorization("Bearer opaque", AuthorizationCarrier.STANDARD)
                                        .carrier()
                                == AuthorizationCarrier.STANDARD;
            case "duplicate-dedicated-lines" -> rejects("AEP first,AEP second", AuthorizationCarrier.DEDICATED, code);
            // Two schemes packed into one field value are not two credentials to choose between.
            case "combined-dedicated-values" ->
                rejects("AEP first Bearer second", AuthorizationCarrier.DEDICATED, code);
            default -> throw new IllegalArgumentException("Unknown authorization ambiguity case: " + name);
        };
    }

    private static boolean rejects(String value, AuthorizationCarrier carrier, String code) {
        try {
            AepHttp.parseAuthorization(value, carrier);
            return false;
        } catch (AepAuthorizationException exception) {
            return code.equals(exception.code());
        }
    }

    private static AepCommand command(String value) {
        return java.util.Arrays.stream(AepCommand.values())
                .filter(command -> command.value().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown AEP command: " + value));
    }

    private static AepAgent.Builder agent(AepHttpTransport inspect, AepHttpTransport command) {
        AgentIdentity identity = new AgentIdentity(AGENT_DID, claims -> completed("signed"));
        return AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(command)
                .identityProvider((origin, serviceDid) -> completed(identity))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .jwtIdSupplier(() -> "jwt-id");
    }

    private static String document(List<String> commands, List<String> methods, List<String> requiredClaims) {
        String grants = commands.contains(GRANT) || commands.contains(REVOKE) ? "[\"custom-grant\"]" : "[]";
        String config =
                commands.contains(GRANT) ? "{\"custom-grant\":{\"supports_per_credential_revoke\":\"true\"}}" : "{}";
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
