package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AepJson;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.CommandOptions;
import foundation.aep.service.EnrollmentDecision;
import foundation.aep.service.EnrollmentRecord;
import foundation.aep.service.EnrollmentStore;
import foundation.aep.service.GrantContext;
import foundation.aep.service.GrantResult;
import foundation.aep.service.GrantTypeDefinition;
import foundation.aep.service.GrantTypeHandler;
import foundation.aep.service.IdempotencyInput;
import foundation.aep.service.IdempotencyResult;
import foundation.aep.service.IdempotencyStore;
import foundation.aep.service.ProtectedResourceRequest;
import foundation.aep.service.ProtectedResourceResult;
import foundation.aep.service.RevokeContext;
import foundation.aep.service.ServiceCredentialStore;
import foundation.aep.service.ServiceResponse;
import foundation.aep.service.StoredCredentialGrantTypes;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

final class ServiceConformance {
    private static final String REVOKE = "revoke";
    private static final int HTTP_OK = 200;
    private static final String GRANT_REVOKE = "grant-revoke";
    private static final String AUTHORIZATION = "Authorization";
    private static final String SUPPORTED = "true";
    private static final String ENROLLMENT_ID = "enrollment-1";
    private static final String AUTHORIZATION_AMBIGUITY = "authorization-ambiguity";
    private static final String AUTHORIZATION_FIELD_SAFETY = "authorization-field-safety";
    private static final String CUSTOM_SESSION = "custom-session";
    private static final String ENROLL = "enroll";
    private static final String GRANT = "grant";
    private static final String INSPECT = "inspect";
    private static final String CREDENTIAL_ID = "credential-1";
    private static final String GET_METHOD = "GET";
    private static final Instant NOW = Instant.parse("2026-08-30T12:00:00Z");
    private static final URI PROTECTED_RESOURCE = URI.create("https://service.example/private");
    private static final String AGENT_DID = "did:web:agent.example";
    private static final String SERVICE_DID = "did:web:service.example";
    private static final String VALIDATION_REQUIREMENTS = "validation-requirements";
    private static final String RESOURCE = "resource";
    private static final String STATUS = "status";
    private static final String CODE = "code";
    private static final String CONTENT_TYPE = "content_type";
    private static final String BODY = "body";
    private static final String SERVICE_DOCUMENTS = "service-documents";

    private ServiceConformance() {}

    static boolean evaluate(AdapterRequest request) {
        if (SERVICE_DOCUMENTS.equals(request.vector().category())) return DocumentConformance.evaluate(request);
        if (GRANT_REVOKE.equals(request.vector().category())
                && request.testCase().expected().has("authorization_scheme")) return commandWire(request);
        if (VALIDATION_REQUIREMENTS.equals(request.vector().id())) return assertionValidation(request);
        Boolean shared = SharedConformance.evaluate(request);
        if (shared != null) return shared;
        return switch (request.vector().id()) {
            case "repeated-existing" -> repeatedEnrollment(request);
            case "grant-before-enroll-rejected" -> grantBeforeEnrollment(request);
            case "command-header" -> commandHeaders(request);
            case "command-replay-conflict" -> commandReplay(request);
            case "enroll-conflict" -> idempotency(request);
            case "transport-requirements" -> transport(request);
            case "api-key-wrong-header-rejected" -> apiKeyHeader(request);
            case "authenticate-assertion" -> authenticateAssertion();
            case "authorization-payment-composition" -> paymentComposition(request);
            case "operation-substitution-rejected" -> operationBinding(request);
            case "assertion-and-credential-failures", AUTHORIZATION_AMBIGUITY, AUTHORIZATION_FIELD_SAFETY ->
                protectedFailure(request);
            case "redirect-safety" -> redirectSafety(request);
            default -> throw ConformanceSupport.unmapped(request);
        };
    }

    private static boolean commandWire(AdapterRequest vector) {
        if (!Boolean.TRUE.equals(SharedConformance.evaluate(vector))) return false;
        JsonNode expected = vector.testCase().expected();
        var command = AepCommand.valueOf(
                ConformanceSupport.text(expected, "client_assertion_op").toUpperCase(java.util.Locale.ROOT));
        String credentialId = vector.testCase().input().path("credential_id").asText(CREDENTIAL_ID);
        var config = new InspectDocument.GrantTypeConfig(SUPPORTED);
        AepService service = serviceBuilder(bearerDocument(config))
                .storedCredentialGrantType(StoredCredentialGrantTypes.oauthBearer(
                        config,
                        (request, context) -> completed(new GrantResponses.OAuthBearer(
                                "token",
                                credentialId,
                                NOW.plusSeconds(3600).toString(),
                                List.of(),
                                "opaque",
                                "Bearer")),
                        ServiceCredentialStore.inMemory()))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        if (command == AepCommand.REVOKE) {
            service.grant(new GrantRequest(Aep.GRANT_TYPE_OAUTH_BEARER, List.of()), options("seed", "seed"))
                    .toCompletableFuture()
                    .join();
            if (!service.authenticate(new ProtectedResourceRequest(
                            Map.of(AUTHORIZATION, List.of("Bearer token")), GET_METHOD, PROTECTED_RESOURCE))
                    .toCompletableFuture()
                    .join()
                    .authenticated()) return false;
        }
        var request = new AepHttpRequest(
                ConformanceSupport.text(expected, "method"),
                URI.create("https://service.example" + ConformanceSupport.text(expected, "path")),
                Map.of(
                        "Content-Type",
                        List.of(ConformanceSupport.text(expected, CONTENT_TYPE)),
                        AUTHORIZATION,
                        List.of(ConformanceSupport.text(expected, "authorization_scheme") + " wire"),
                        "Idempotency-Key",
                        List.of("wire")),
                vector.testCase().input().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var handler = new AepServiceHttpHandler(service);
        if (!handler.routes().get(command).equals(request.url().getPath())) return false;
        var response = handler.handle(command, request).toCompletableFuture().join();
        if (response.status() != HTTP_OK) return false;
        boolean authenticated = service.authenticate(new ProtectedResourceRequest(
                        Map.of(AUTHORIZATION, List.of("Bearer token")), GET_METHOD, PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join()
                .authenticated();
        return authenticated == (command == AepCommand.GRANT);
    }

    private static boolean assertionValidation(AdapterRequest vector) {
        JsonNode expected = vector.testCase().expected();
        try {
            var key = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate();
            var verifier = foundation.aep.service.ClientAssertionVerifier.withKeyResolver(
                    (assertion, claims, context) -> completed(key.toPublicJWK()));
            var originalClaims = (com.fasterxml.jackson.databind.node.ObjectNode) expected.get("claims");
            var originalHeader = (com.fasterxml.jackson.databind.node.ObjectNode) expected.get("header");
            var clock =
                    Clock.fixed(Instant.ofEpochSecond(originalClaims.path("iat").asLong()), ZoneOffset.UTC);
            var context = new foundation.aep.service.AssertionVerificationContext(
                    originalClaims.path("aud").asText(),
                    AssertionOperation.ENROLL,
                    null,
                    null,
                    List.of("ES256"),
                    clock,
                    Duration.ZERO,
                    false);
            String valid = signedAssertion(originalHeader, originalClaims, key);
            if (!ConformanceSupport.jsonEquals(
                    verifier.verify(valid, context).toCompletableFuture().join(), originalClaims)) {
                return false;
            }
            for (String rejection : ConformanceSupport.strings(expected, "reject")) {
                var header = originalHeader.deepCopy();
                var claims = originalClaims.deepCopy();
                String resource = "https://api.example.com/private";
                boolean authenticate = List.of("fragmented_resource", "insecure_resource", "missing_resource")
                        .contains(rejection);
                if (authenticate) {
                    claims.put("op", "authenticate");
                    claims.put(RESOURCE, resource);
                }
                switch (rejection) {
                    case "excessive_lifetime" ->
                        claims.put("exp", claims.path("iat").asLong() + 301);
                    case "nonpositive_lifetime" ->
                        claims.put("exp", claims.path("iat").asLong());
                    case "fragmented_resource" -> claims.put(RESOURCE, resource + "#fragment");
                    case "insecure_resource" -> claims.put(RESOURCE, "http://api.example.com/private");
                    case "missing_resource" -> claims.remove(RESOURCE);
                    case "unexpected_resource" -> claims.put(RESOURCE, resource);
                    case "mismatched_kid" -> header.put("kid", "did:web:other.example");
                    case "missing_kid" -> header.remove("kid");
                    case "wrong_typ" -> header.put("typ", "not-jwt");
                    case "mismatched_subject" -> claims.put("sub", "did:web:other.example");
                    default -> {
                        return false;
                    }
                }
                String assertion = signedAssertion(header, claims, key);
                var rejectionContext = new foundation.aep.service.AssertionVerificationContext(
                        context.serviceDid(),
                        authenticate ? AssertionOperation.AUTHENTICATE : AssertionOperation.ENROLL,
                        authenticate ? resource : null,
                        null,
                        List.of("ES256"),
                        clock,
                        Duration.ZERO,
                        false);
                try {
                    verifier.verify(assertion, rejectionContext)
                            .toCompletableFuture()
                            .join();
                    return false;
                } catch (IllegalArgumentException rejected) {
                    if (rejected.getMessage() == null) throw rejected;
                } catch (java.util.concurrent.CompletionException rejected) {
                    if (!(rejected.getCause() instanceof IllegalArgumentException)) throw rejected;
                }
            }
            return true;
        } catch (com.nimbusds.jose.JOSEException | java.text.ParseException failure) {
            throw new IllegalArgumentException("Unable to sign conformance assertion", failure);
        }
    }

    private static String signedAssertion(JsonNode header, JsonNode claims, com.nimbusds.jose.jwk.ECKey key)
            throws java.text.ParseException, com.nimbusds.jose.JOSEException {
        var token = new com.nimbusds.jwt.SignedJWT(
                com.nimbusds.jose.JWSHeader.parse(header.toString()),
                com.nimbusds.jwt.JWTClaimsSet.parse(claims.toString()));
        token.sign(new com.nimbusds.jose.crypto.ECDSASigner(key));
        return token.serialize();
    }

    private static boolean repeatedEnrollment(AdapterRequest vector) {
        JsonNode input = vector.testCase().input();
        JsonNode expected = vector.testCase().expected();
        JsonNode existing = ConformanceSupport.required(input, "existing");
        String agentDid = ConformanceSupport.text(existing, "agent_did");
        Instant since = Instant.parse(ConformanceSupport.text(existing, "since"));
        AgentStatus status =
                AgentStatus.valueOf(ConformanceSupport.text(existing, "status").toUpperCase(java.util.Locale.ROOT));
        EnrollmentStore store = EnrollmentStore.inMemory();
        EnrollmentRecord original =
                EnrollmentRecord.builder(agentDid, ENROLLMENT_ID, status, since).build();
        store.save(original).toCompletableFuture().join();
        AtomicInteger decisions = new AtomicInteger();
        AepService service = AepService.builder(
                        document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                agentDid,
                                agentDid,
                                context.serviceDid(),
                                context.operation(),
                                NOW.getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                null)))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentStore(store)
                .enrollmentPolicy((request, now) -> {
                    decisions.incrementAndGet();
                    return completed(new EnrollmentDecision(AgentStatus.ACTIVE, null, null, null, false));
                })
                .build();
        EnrollRequest request = AepJson.parseEnrollRequest(
                ConformanceSupport.required(input, "request").toString());
        var response = service.enroll(request, options("repeat", request.idempotencyKey()))
                .toCompletableFuture()
                .join();
        EnrollmentRecord saved =
                store.find(agentDid).toCompletableFuture().join().orElseThrow();
        JsonNode expectedResponse = ConformanceSupport.required(expected, "response");
        return response.status()
                        == ConformanceSupport.required(expectedResponse, "status")
                                .asInt()
                && response.contentType().equals(ConformanceSupport.text(expectedResponse, CONTENT_TYPE))
                && ConformanceSupport.jsonEquals(response.body(), ConformanceSupport.required(expectedResponse, BODY))
                && (decisions.get() == 1)
                        == ConformanceSupport.required(expected, "policy_evaluated")
                                .asBoolean()
                && !saved.equals(original)
                        == ConformanceSupport.required(expected, "record_replaced")
                                .asBoolean();
    }

    private static boolean grantBeforeEnrollment(AdapterRequest request) {
        AepService service = serviceBuilder(
                        document(List.of(GRANT, INSPECT, STATUS), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .grantType(new GrantTypeDefinition(CUSTOM_SESSION, new Handler()))
                .build();
        var response = service.grant(new GrantRequest(CUSTOM_SESSION, List.of()), options("grant", "grant"))
                .toCompletableFuture()
                .join();
        return response.status()
                        == ConformanceSupport.required(request.testCase().expected(), STATUS)
                                .asInt()
                && response.problem()
                        .code()
                        .equals(ConformanceSupport.text(request.testCase().expected(), CODE));
    }

    private static boolean commandHeaders(AdapterRequest vector) {
        JsonNode expected = vector.testCase().expected();
        String key = ConformanceSupport.text(vector.testCase().input(), "idempotency_key");
        AepService service = serviceBuilder(
                        document(List.of(ENROLL, GRANT, REVOKE, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .grantType(new GrantTypeDefinition(CUSTOM_SESSION, new Handler()))
                .build();
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service);
        for (String name : ConformanceSupport.strings(vector.testCase().input(), "commands")) {
            AepCommand command = AepCommand.valueOf(name.toUpperCase(java.util.Locale.ROOT));
            Object body = command == AepCommand.ENROLL
                    ? new EnrollRequest(AGENT_DID, null, null)
                    : Map.of("grant_type", CUSTOM_SESSION);
            for (List<String> values : List.of(List.<String>of(), List.of(""))) {
                var headers = new java.util.LinkedHashMap<String, List<String>>();
                headers.put("Content-Type", List.of(Aep.MEDIA_TYPE));
                headers.put(AUTHORIZATION, List.of("AEP " + name + values.size()));
                if (!values.isEmpty()) headers.put("Idempotency-Key", values);
                var result = handler.handle(
                                command,
                                new AepHttpRequest(
                                        "POST",
                                        URI.create("https://service.example/aep/" + name),
                                        headers,
                                        AepJson.write(body).getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                        .toCompletableFuture()
                        .join();
                if (result.status() != expected.path("missing_or_empty_status").asInt()
                        || !ConformanceSupport.json(result.bodyText())
                                .path(CODE)
                                .asText()
                                .equals(ConformanceSupport.text(expected, "missing_or_empty_code"))) return false;
            }
        }
        var omitted = service.enroll(new EnrollRequest(AGENT_DID, null, null), options("omitted", key))
                .toCompletableFuture()
                .join();
        var matching = service.enroll(
                        new EnrollRequest(AGENT_DID, null, key + "-matching"), options("matching", key + "-matching"))
                .toCompletableFuture()
                .join();
        var mismatched = service.enroll(new EnrollRequest(AGENT_DID, null, "different"), options("mismatch", key))
                .toCompletableFuture()
                .join();
        return expected.path("header_required").asBoolean()
                && "optional".equals(ConformanceSupport.text(expected, "enroll_body_key"))
                && omitted.status() == 200
                && matching.status() == 200
                && mismatched.status()
                        == expected.path("mismatched_enroll_body_status").asInt();
    }

    private static boolean commandReplay(AdapterRequest vector) {
        JsonNode input = vector.testCase().input();
        JsonNode expected = vector.testCase().expected();
        String key = ConformanceSupport.text(input, "idempotency_key");
        AepService service = serviceBuilder(
                        document(List.of(ENROLL, GRANT, REVOKE, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .grantType(new GrantTypeDefinition(CUSTOM_SESSION, new Handler()))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        var grant = new GrantRequest(CUSTOM_SESSION, List.of());
        var first = service.grant(grant, options("grant-first", key))
                .toCompletableFuture()
                .join();
        var replay = service.grant(grant, options("grant-replay", key))
                .toCompletableFuture()
                .join();
        var changedBody = service.grant(
                        new GrantRequest(CUSTOM_SESSION, List.of("other")), options("grant-conflict", key))
                .toCompletableFuture()
                .join();
        var changedCommand = service.revoke(
                        foundation.aep.core.RevokeRequest.grantType(CUSTOM_SESSION), options("revoke-conflict", key))
                .toCompletableFuture()
                .join();
        if (first.status() != 200
                || replay.status() != 200
                || !ConformanceSupport.jsonEquals(first.body(), ConformanceSupport.json(AepJson.write(replay.body())))
                || !conflictMatches(changedBody, expected.path("changed_body"))
                || !conflictMatches(changedCommand, expected.path("changed_command"))) return false;

        MovableClock clock = new MovableClock(NOW);
        IdempotencyStore store = IdempotencyStore.inMemory(clock);
        AtomicInteger executions = new AtomicInteger();
        java.util.function.Supplier<CompletionStage<ServiceResponse<Integer>>> operation =
                () -> completed(ServiceResponse.success(executions.incrementAndGet()));
        var original = new IdempotencyInput(
                ConformanceSupport.text(input, "agent_did"),
                key,
                ConformanceSupport.text(input, "first_command"),
                ConformanceSupport.text(input, "first_body_hash"));
        var created = store.execute(original, operation).toCompletableFuture().join();
        clock.advance(
                Duration.ofSeconds(expected.path("retention_seconds_minimum").asLong()));
        var retained = store.execute(original, operation).toCompletableFuture().join();
        var otherAgent = store.execute(
                        new IdempotencyInput("did:web:other.example", key, original.command(), original.requestHash()),
                        operation)
                .toCompletableFuture()
                .join();
        var otherKey = store.execute(
                        new IdempotencyInput(
                                original.agentDid(), key + "-other", original.command(), original.requestHash()),
                        operation)
                .toCompletableFuture()
                .join();
        return created.state() == IdempotencyResult.State.CREATED
                && retained.state() == IdempotencyResult.State.REPLAYED
                && created.response().equals(retained.response())
                && otherAgent.state() == IdempotencyResult.State.CREATED
                && otherKey.state() == IdempotencyResult.State.CREATED
                && executions.get() == 3
                && ConformanceSupport.strings(expected, "scope").equals(List.of("agent_did", "idempotency_key"))
                && "cached_or_equivalent_success".equals(ConformanceSupport.text(expected, "exact_retry"));
    }

    private static boolean conflictMatches(ServiceResponse<?> response, JsonNode expected) {
        return response.status() == expected.path(STATUS).asInt()
                && response.problem() != null
                && response.problem().code().equals(ConformanceSupport.text(expected, CODE));
    }

    private static boolean idempotency(AdapterRequest vector) {
        AepService service = serviceBuilder(document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .build();
        EnrollRequest request = new EnrollRequest(AGENT_DID, null, null);
        var first = service.enroll(request, options("one", "shared"))
                .toCompletableFuture()
                .join();
        var replay = service.enroll(request, options("two", "shared"))
                .toCompletableFuture()
                .join();
        var conflict = service.enroll(
                        new EnrollRequest(
                                AGENT_DID,
                                foundation.aep.core.ClaimValues.builder()
                                        .contactEmail("agent@example.com")
                                        .build(),
                                null),
                        options("three", "shared"))
                .toCompletableFuture()
                .join();
        return ConformanceSupport.jsonEquals(first.body(), ConformanceSupport.json(AepJson.write(replay.body())))
                && conflict.status()
                        == vector.testCase().expected().path(STATUS).asInt()
                && conflict.contentType()
                        .equals(ConformanceSupport.text(vector.testCase().expected(), CONTENT_TYPE))
                && conflictMatches(conflict, vector.testCase().expected().path(BODY))
                && conflict.problem()
                        .type()
                        .equals(ConformanceSupport.text(
                                vector.testCase().expected().path(BODY), "type"))
                && conflict.problem()
                        .title()
                        .equals(ConformanceSupport.text(
                                vector.testCase().expected().path(BODY), "title"));
    }

    // CORE-CACHE-008: the media-type essence is compared case-insensitively and valid parameters are
    // ignored. The HTTP binding is driven with input.content_type verbatim, and must accept that
    // field value while refusing application/json.
    private static boolean transport(AdapterRequest request) {
        String contentType = ConformanceSupport.text(request.testCase().input(), CONTENT_TYPE);
        String essence = ConformanceSupport.text(request.testCase().expected(), "media_type_essence");
        AepServiceHttpHandler handler = new AepServiceHttpHandler(
                serviceBuilder(document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                        .build());
        AepHttpResponse inspect = handler.handle(AepCommand.INSPECT, get(Aep.WELL_KNOWN_PATH))
                .toCompletableFuture()
                .join();
        AepHttpResponse accepted = handler.handle(AepCommand.ENROLL, enrollPost(contentType))
                .toCompletableFuture()
                .join();
        AepHttpResponse refused = handler.handle(AepCommand.ENROLL, enrollPost("application/json"))
                .toCompletableFuture()
                .join();
        return essence.equals(inspect.contentType())
                && inspect.status() == 200
                && accepted.status() == 200
                && refused.status() == 415;
    }

    private static boolean apiKeyHeader(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        String issued = ConformanceSupport.text(input, "issued_header");
        String presented = ConformanceSupport.text(input, "presented_header");
        String apiKey = ConformanceSupport.text(input, "api_key");
        InspectDocument.GrantTypeConfig config = new InspectDocument.GrantTypeConfig(
                null, null, List.of(issued), null, List.of(), SUPPORTED, null, null);
        var stored = StoredCredentialGrantTypes.apiKey(
                config,
                (grant, context) -> completed(new GrantResponses.ApiKey(
                        apiKey, CREDENTIAL_ID, NOW.plusSeconds(3600).toString(), issued, List.of())),
                ServiceCredentialStore.inMemory());
        AepService service = serviceBuilder(apiKeyDocument(config))
                .storedCredentialGrantType(stored)
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        service.grant(new GrantRequest(Aep.GRANT_TYPE_API_KEY, List.of()), options(GRANT, GRANT))
                .toCompletableFuture()
                .join();
        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(
                        Map.of(presented, List.of(apiKey)), GET_METHOD, PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return !result.authenticated()
                && ConformanceSupport.text(request.testCase().expected(), CODE)
                        .equals(result.response().problem().code());
    }

    private static boolean authenticateAssertion() {
        AepService service = serviceBuilder(document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(
                        Map.of(AUTHORIZATION, List.of("AEP authenticate")), GET_METHOD, PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return result.authenticated()
                && AGENT_DID.equals(result.principal().agentDid())
                && Aep.AUTHENTICATION_METHOD_JWT.equals(result.principal().authenticationMethod());
    }

    // An AEP credential on the dedicated carrier composes with an unrelated payment credential on
    // Authorization without either becoming ambiguous. Each composition expected describes is
    // presented to the Service, which must authenticate the Agent from it.
    private static boolean paymentComposition(AdapterRequest request) {
        var compositions = request.testCase().expected().fields();
        while (compositions.hasNext()) {
            var composition = compositions.next();
            JsonNode value = composition.getValue();
            if (!value.isObject() || !value.has(Aep.AUTHORIZATION_HEADER)) continue;
            if (value.path("ambiguous").asBoolean()) return false;
            String carried = ConformanceSupport.text(value, Aep.AUTHORIZATION_HEADER);
            Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
            value.fields().forEachRemaining(field -> {
                if (field.getValue().isTextual())
                    headers.put(field.getKey(), List.of(field.getValue().asText()));
            });
            // The AEP credential on the dedicated carrier is an assertion in one composition and a
            // bearer session credential in the other; the Service under test has to accept whichever
            // the composition carries while leaving the payment credential beside it alone.
            AepService service =
                    carried.startsWith(Aep.AUTHENTICATION_SCHEME + " ") ? enrolledService() : bearerService(carried);
            ProtectedResourceResult result = service.authenticate(
                            new ProtectedResourceRequest(headers, GET_METHOD, PROTECTED_RESOURCE))
                    .toCompletableFuture()
                    .join();
            if (!result.authenticated() || !AGENT_DID.equals(result.principal().agentDid())) return false;
        }
        return true;
    }

    /** A Service that has issued the bearer session credential a composition presents. */
    private static AepService bearerService(String carried) {
        String token = carried.substring(carried.indexOf(' ') + 1);
        InspectDocument.GrantTypeConfig config = new InspectDocument.GrantTypeConfig(SUPPORTED);
        AepService service = serviceBuilder(bearerDocument(config))
                .storedCredentialGrantType(StoredCredentialGrantTypes.oauthBearer(
                        config,
                        (grant, context) -> completed(new GrantResponses.OAuthBearer(
                                token, CREDENTIAL_ID, NOW.plusSeconds(3600).toString(), List.of(), "opaque", "Bearer")),
                        ServiceCredentialStore.inMemory()))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        service.grant(new GrantRequest(Aep.GRANT_TYPE_OAUTH_BEARER, List.of()), options(GRANT, GRANT))
                .toCompletableFuture()
                .join();
        return service;
    }

    private static InspectDocument bearerDocument(InspectDocument.GrantTypeConfig config) {
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(
                        List.of(Aep.AUTHENTICATION_METHOD_JWT, Aep.GRANT_TYPE_OAUTH_BEARER)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        List.of(ENROLL, GRANT, REVOKE, INSPECT),
                        List.of(Aep.GRANT_TYPE_OAUTH_BEARER),
                        Map.of(Aep.GRANT_TYPE_OAUTH_BEARER, config)))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .extensions(new InspectDocument.Extensions(List.of()))
                .http(new InspectDocument.Http(Aep.DEFAULT_ENDPOINT_BASE, null))
                .identity(new InspectDocument.Identity(List.of(Aep.IDENTITY_METHOD_DID_WEB)))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
    }

    // expected.all_other_pairs is "not_recognized": only an authenticate assertion opens a protected
    // resource, and only a command's own assertion reaches that command. A well-formed assertion
    // carrying any other operation is substituted, and the Service must refuse it under that code.
    private static boolean operationBinding(AdapterRequest request) {
        String substituted = ConformanceSupport.text(request.testCase().expected(), "all_other_pairs");
        for (JsonNode value : ConformanceSupport.required(request.testCase().input(), "operations")) {
            AssertionOperation minted = AssertionOperation.fromValue(value.asText());
            for (String endpoint : ConformanceSupport.strings(request.testCase().input(), "command_endpoints")) {
                AepService commandService = substitutingService(minted);
                CommandOptions options = options("substitution-" + endpoint, "substitution-" + endpoint);
                ServiceResponse<?> response =
                        switch (endpoint) {
                            case ENROLL ->
                                commandService
                                        .enroll(new EnrollRequest(AGENT_DID, null, null), options)
                                        .toCompletableFuture()
                                        .join();
                            case GRANT ->
                                commandService
                                        .grant(new GrantRequest(CUSTOM_SESSION, List.of()), options)
                                        .toCompletableFuture()
                                        .join();
                            case REVOKE ->
                                commandService
                                        .revoke(foundation.aep.core.RevokeRequest.grantType(CUSTOM_SESSION), options)
                                        .toCompletableFuture()
                                        .join();
                            case STATUS ->
                                commandService
                                        .status(options)
                                        .toCompletableFuture()
                                        .join();
                            default -> throw new IllegalArgumentException("Unknown command endpoint: " + endpoint);
                        };
                boolean allowed = ConformanceSupport.strings(request.testCase().expected(), "allowed")
                        .contains(minted.value() + ":" + endpoint);
                if (allowed
                        ? response.status() != HTTP_OK
                        : response.problem() == null
                                || !substituted.equals(response.problem().code())) return false;
            }
            AepService service = substitutingService(minted);
            ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(
                            Map.of(AUTHORIZATION, List.of("AEP substituted")), GET_METHOD, PROTECTED_RESOURCE))
                    .toCompletableFuture()
                    .join();
            if (minted == AssertionOperation.AUTHENTICATE) {
                if (result.authenticated()) continue;
                return false;
            }
            if (result.authenticated()
                    || !substituted.equals(result.response().problem().code())) return false;
        }
        return true;
    }

    private static boolean protectedFailure(AdapterRequest request) {
        if (AUTHORIZATION_FIELD_SAFETY.equals(request.vector().id())) return fieldNameSafety(request);
        if (AUTHORIZATION_AMBIGUITY.equals(request.vector().id())) return authorizationAmbiguity(request);
        return credentialFailures(request);
    }

    /**
     * expected maps each of the vector's seven failure modes to the code the Service must report.
     * Every mode the SDK decides is driven against its own code, so the three distinct codes stay
     * distinguishable rather than collapsing into one.
     */
    private static boolean credentialFailures(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        for (JsonNode value : ConformanceSupport.required(request.testCase().input(), "cases")) {
            String mode = value.asText();
            Boolean outcome = failureMode(mode, ConformanceSupport.text(expected, mode));
            // insufficient_scope is reported by the application that owns the scope, from the scopes
            // the match carries; the SDK has no scope policy of its own to exercise here.
            if (outcome != null && !outcome) return false;
        }
        return true;
    }

    private static Boolean failureMode(String mode, String code) {
        return switch (mode) {
            // A field value carrying a scheme and no credentials is not a presentation at all.
            case "malformed_credential" -> rejected(Map.of(AUTHORIZATION, List.of("AEP")), code);
            // Bearer against a document advertising only aep-jwt names a method the Service does not
            // offer, which is a different answer from "the credential was not recognized".
            case "unsupported_method" -> rejected(Map.of(AUTHORIZATION, List.of("Bearer opaque")), code);
            case "wrong_audience" -> corrupted(claims -> withAudience(claims, "did:web:elsewhere.example"), code);
            case "expired_assertion" -> corrupted(claims -> withExpiry(claims, NOW.minusSeconds(600)), code);
            case "replayed_assertion" -> replayed(code);
            case "expired_credential" -> expiredCredential(code);
            case "insufficient_scope" -> null;
            default -> throw new IllegalArgumentException("Unknown protected-resource failure mode: " + mode);
        };
    }

    /** A Service whose verifier returns claims the protected-resource path must refuse to accept. */
    private static boolean corrupted(java.util.function.UnaryOperator<ClientAssertionClaims> corrupt, String code) {
        AtomicReference<java.util.function.UnaryOperator<ClientAssertionClaims>> active = new AtomicReference<>();
        AepService service = AepService.builder(
                        document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)),
                        (assertion, context) -> {
                            ClientAssertionClaims issued = claims(context.operation(), assertion, context.resource());
                            var mutate = active.get();
                            return completed(mutate == null ? issued : mutate.apply(issued));
                        })
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identifierSupplier(() -> ENROLLMENT_ID)
                .build();
        // Enrollment runs through the same verifier, so the corruption starts once the Agent is
        // ACTIVE and the protected-resource path is the thing under test.
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        active.set(corrupt);
        return rejectedBy(service, Map.of(AUTHORIZATION, List.of("AEP assertion")), code);
    }

    /** The same assertion presented twice: the second presentation is a replay the Service consumes once. */
    private static boolean replayed(String code) {
        AepService service = enrolledService();
        Map<String, List<String>> headers = Map.of(AUTHORIZATION, List.of("AEP replayed-assertion"));
        ProtectedResourceResult first = service.authenticate(
                        new ProtectedResourceRequest(headers, GET_METHOD, PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return first.authenticated() && rejectedBy(service, headers, code);
    }

    /**
     * A stored session credential past its expiry no longer authenticates. The credential is minted
     * with a lifetime the Service accepts and the clock is then moved past it, because issuing one
     * that has already expired is refused at the Grant, which would test the wrong thing.
     */
    private static boolean expiredCredential(String code) {
        InspectDocument.GrantTypeConfig config = new InspectDocument.GrantTypeConfig(SUPPORTED);
        MovableClock clock = new MovableClock(NOW);
        AepService service = AepService.builder(
                        bearerDocument(config),
                        (assertion, context) -> completed(claims(context.operation(), assertion, context.resource())))
                .clock(clock)
                .identifierSupplier(() -> ENROLLMENT_ID)
                .storedCredentialGrantType(StoredCredentialGrantTypes.oauthBearer(
                        config,
                        (grant, context) -> completed(new GrantResponses.OAuthBearer(
                                "stale-token",
                                CREDENTIAL_ID,
                                NOW.plusSeconds(60).toString(),
                                List.of(),
                                "opaque",
                                "Bearer")),
                        ServiceCredentialStore.inMemory()))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        service.grant(new GrantRequest(Aep.GRANT_TYPE_OAUTH_BEARER, List.of()), options(GRANT, GRANT))
                .toCompletableFuture()
                .join();
        clock.advance(Duration.ofSeconds(120));
        return rejectedBy(service, Map.of(AUTHORIZATION, List.of("Bearer stale-token")), code);
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

    private static ClientAssertionClaims withAudience(ClientAssertionClaims claims, String audience) {
        return new ClientAssertionClaims(
                claims.issuer(),
                claims.subject(),
                audience,
                claims.operation(),
                claims.issuedAt(),
                claims.expiresAt(),
                claims.jwtId(),
                claims.resource());
    }

    private static ClientAssertionClaims withExpiry(ClientAssertionClaims claims, Instant expiresAt) {
        return new ClientAssertionClaims(
                claims.issuer(),
                claims.subject(),
                claims.audience(),
                claims.operation(),
                expiresAt.minusSeconds(60).getEpochSecond(),
                expiresAt.getEpochSecond(),
                claims.jwtId(),
                claims.resource());
    }

    /**
     * input.cases names four ambiguous presentations and expected names one outcome for all of them:
     * the published code, with no fallback to the standard field and no credential selected. Every
     * case is driven and every member of expected is read.
     */
    private static boolean authorizationAmbiguity(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        if (ConformanceSupport.required(expected, "fallback").asBoolean()
                || !ConformanceSupport.required(expected, "selected_credential").isNull()) return false;
        String code = ConformanceSupport.text(expected, CODE);
        for (JsonNode value : ConformanceSupport.required(request.testCase().input(), "cases")) {
            if (!rejected(ambiguousHeaders(value.asText()), code)) return false;
        }
        return true;
    }

    private static Map<String, List<String>> ambiguousHeaders(String name) {
        return switch (name) {
            // An AEP credential in both carriers at once names no single presentation to verify.
            case "both-aep-recognized" ->
                Map.of(Aep.AUTHORIZATION_HEADER, List.of("AEP dedicated"), AUTHORIZATION, List.of("AEP standard"));
            // The malformed dedicated field is the presentation; the valid standard one beside it is
            // not a fallback the Service may authenticate instead.
            case "invalid-dedicated-plus-valid-standard" ->
                Map.of(Aep.AUTHORIZATION_HEADER, List.of("AEP"), AUTHORIZATION, List.of("Bearer opaque"));
            case "duplicate-dedicated-lines" -> Map.of(Aep.AUTHORIZATION_HEADER, List.of("AEP first", "AEP second"));
            // Two schemes packed into one field value are not two credentials to choose between.
            case "combined-dedicated-values" -> Map.of(Aep.AUTHORIZATION_HEADER, List.of("AEP first Bearer second"));
            default -> throw new IllegalArgumentException("Unknown authorization ambiguity case: " + name);
        };
    }

    private static boolean rejected(Map<String, List<String>> headers, String code) {
        return rejectedBy(
                serviceBuilder(document(List.of(INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                        .build(),
                headers,
                code);
    }

    private static boolean rejectedBy(AepService service, Map<String, List<String>> headers, String code) {
        ProtectedResourceResult result = service.authenticate(
                        new ProtectedResourceRequest(headers, GET_METHOD, PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return !result.authenticated()
                && code.equals(result.response().problem().code());
    }

    // expected.field_name_match is "case-insensitive", so the credential is presented in
    // input.field_name exactly as the vector spells it and the Service must find it there.
    private static boolean fieldNameSafety(AdapterRequest request) {
        if (!"case-insensitive"
                .equals(ConformanceSupport.text(request.testCase().expected(), "field_name_match"))) return false;
        String fieldName = ConformanceSupport.text(request.testCase().input(), "field_name");
        ProtectedResourceResult result = enrolledService()
                .authenticate(new ProtectedResourceRequest(
                        Map.of(fieldName, List.of("AEP assertion")), GET_METHOD, PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return result.authenticated() && AGENT_DID.equals(result.principal().agentDid());
    }

    // expected.same_origin.credential_forwarded is false: an assertion bound to one resource must not
    // open another, even on the same origin. The Service is given an assertion pinned to the source
    // and asked to authenticate the redirect target with it.
    private static boolean redirectSafety(AdapterRequest request) {
        JsonNode expected = request.testCase().expected();
        if (ConformanceSupport.required(expected.get("same_origin"), "credential_forwarded")
                .asBoolean()) return false;
        URI source = URI.create(ConformanceSupport.text(request.testCase().input(), "source"));
        URI sameOrigin = URI.create(ConformanceSupport.text(request.testCase().input(), "same_origin"));
        AepService service = boundToResource(source);
        ProtectedResourceResult bound = service.authenticate(new ProtectedResourceRequest(
                        Map.of(AUTHORIZATION, List.of("AEP assertion")), GET_METHOD, source))
                .toCompletableFuture()
                .join();
        ProtectedResourceResult forwarded = service.authenticate(new ProtectedResourceRequest(
                        Map.of(AUTHORIZATION, List.of("AEP forwarded")), GET_METHOD, sameOrigin))
                .toCompletableFuture()
                .join();
        return bound.authenticated()
                && !forwarded.authenticated()
                && "not_recognized".equals(forwarded.response().problem().code());
    }

    /**
     * A Service holding an ACTIVE enrollment whose verifier then returns an assertion bound to
     * {@code resource} however the request is addressed. Carrying that credential to another URL is
     * what "credential_forwarded" means, and the Service has to refuse it.
     */
    private static AepService boundToResource(URI resource) {
        AtomicReference<String> pinned = new AtomicReference<>();
        AepService service = AepService.builder(
                        document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)),
                        (assertion, context) -> completed(claims(
                                context.operation(),
                                assertion,
                                pinned.get() == null ? context.resource() : pinned.get())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identifierSupplier(() -> ENROLLMENT_ID)
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        pinned.set(resource.toString());
        return service;
    }

    /** A Service with one ACTIVE enrollment, ready to answer a protected-resource request. */
    private static AepService enrolledService() {
        AepService service = serviceBuilder(document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        return service;
    }

    /**
     * A Service holding an ACTIVE enrollment whose verifier then returns an assertion minted for
     * {@code minted} whatever operation the Service is checking. That is what an operation
     * substitution looks like on the wire: a well-formed assertion carrying the wrong operation.
     */
    private static AepService substitutingService(AssertionOperation minted) {
        AtomicReference<AssertionOperation> substitution = new AtomicReference<>();
        AepService service = AepService.builder(
                        document(
                                List.of(ENROLL, GRANT, REVOKE, STATUS, INSPECT),
                                List.of(Aep.AUTHENTICATION_METHOD_JWT)),
                        (assertion, context) -> {
                            AssertionOperation operation = substitution.get();
                            if (operation == null) return completed(claims(context.operation(), assertion, null));
                            String resource =
                                    operation == AssertionOperation.AUTHENTICATE ? PROTECTED_RESOURCE.toString() : null;
                            return completed(claims(operation, assertion, resource));
                        })
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identifierSupplier(() -> ENROLLMENT_ID)
                .grantType(new GrantTypeDefinition(CUSTOM_SESSION, new Handler()))
                .build();
        // Enrollment runs through the same verifier, so the substitution only starts once the Agent
        // is ACTIVE and the protected-resource path is the thing under test.
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        substitution.set(minted);
        return service;
    }

    private static AepHttpRequest get(String path) {
        return new AepHttpRequest(GET_METHOD, URI.create("https://service.example" + path), Map.of(), new byte[0]);
    }

    private static AepHttpRequest enrollPost(String contentType) {
        return new AepHttpRequest(
                "POST",
                URI.create("https://service.example/aep/enroll"),
                Map.of(
                        "Content-Type",
                        List.of(contentType),
                        AUTHORIZATION,
                        List.of("AEP " + java.util.UUID.randomUUID()),
                        "Idempotency-Key",
                        List.of(java.util.UUID.randomUUID().toString())),
                ("{\"agent_did\":\"" + AGENT_DID + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static AepService.Builder serviceBuilder(InspectDocument document) {
        return AepService.builder(
                        document,
                        (assertion, context) -> completed(claims(context.operation(), assertion, context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identifierSupplier(() -> ENROLLMENT_ID);
    }

    private static ClientAssertionClaims claims(AssertionOperation operation, String jwtId, String resource) {
        return new ClientAssertionClaims(
                AGENT_DID,
                AGENT_DID,
                SERVICE_DID,
                operation,
                NOW.getEpochSecond(),
                NOW.plusSeconds(60).getEpochSecond(),
                jwtId,
                resource);
    }

    private static CommandOptions options(String assertion, String idempotencyKey) {
        return new CommandOptions(assertion, idempotencyKey);
    }

    private static InspectDocument document(List<String> commands, List<String> methods) {
        List<String> grants = commands.contains(GRANT) ? List.of(CUSTOM_SESSION) : List.of();
        Map<String, InspectDocument.GrantTypeConfig> config = commands.contains(GRANT)
                ? Map.of(CUSTOM_SESSION, new InspectDocument.GrantTypeConfig(SUPPORTED))
                : Map.of();
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(methods.isEmpty() ? null : new InspectDocument.Authentication(methods))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(commands, grants, config))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .extensions(new InspectDocument.Extensions(List.of()))
                .http(new InspectDocument.Http(Aep.DEFAULT_ENDPOINT_BASE, null))
                .identity(new InspectDocument.Identity(List.of(Aep.IDENTITY_METHOD_DID_WEB)))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
    }

    private static InspectDocument apiKeyDocument(InspectDocument.GrantTypeConfig config) {
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.GRANT_TYPE_API_KEY)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        List.of(ENROLL, GRANT, INSPECT),
                        List.of(Aep.GRANT_TYPE_API_KEY),
                        Map.of(Aep.GRANT_TYPE_API_KEY, config)))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .extensions(new InspectDocument.Extensions(List.of()))
                .http(new InspectDocument.Http(Aep.DEFAULT_ENDPOINT_BASE, null))
                .identity(new InspectDocument.Identity(List.of(Aep.IDENTITY_METHOD_DID_WEB)))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
    }

    private static <T> CompletableFuture<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private static final class Handler implements GrantTypeHandler {
        @Override
        public CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context) {
            return completed(new GrantResult(CREDENTIAL_ID, Map.of("credential_id", CREDENTIAL_ID)));
        }

        @Override
        public CompletionStage<Void> revoke(foundation.aep.core.RevokeRequest request, RevokeContext context) {
            return completed(null);
        }
    }
}
