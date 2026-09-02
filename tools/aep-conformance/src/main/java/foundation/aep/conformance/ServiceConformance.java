package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import foundation.aep.core.Aep;
import foundation.aep.core.AepJson;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepService;
import foundation.aep.service.CommandOptions;
import foundation.aep.service.EnrollmentDecision;
import foundation.aep.service.GrantContext;
import foundation.aep.service.GrantResult;
import foundation.aep.service.GrantTypeDefinition;
import foundation.aep.service.GrantTypeHandler;
import foundation.aep.service.ProtectedResourceRequest;
import foundation.aep.service.ProtectedResourceResult;
import foundation.aep.service.RevokeContext;
import foundation.aep.service.ServiceCredentialStore;
import foundation.aep.service.StoredCredentialGrantTypes;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;

final class ServiceConformance {
    private static final String AUTHORIZATION = "Authorization";
    private static final String AUTHORIZATION_FIELD_SAFETY = "authorization-field-safety";
    private static final String CUSTOM_SESSION = "custom-session";
    private static final String ENROLL = "enroll";
    private static final String GRANT = "grant";
    private static final String INSPECT = "inspect";
    private static final Instant NOW = Instant.parse("2026-08-30T12:00:00Z");
    private static final URI PROTECTED_RESOURCE = URI.create("https://service.example/private");
    private static final String AGENT_DID = "did:web:agent.example";
    private static final String SERVICE_DID = "did:web:service.example";

    private ServiceConformance() {}

    static boolean evaluate(AdapterRequest request) {
        Boolean shared = SharedConformance.evaluate(request);
        if (shared != null) return shared;
        return switch (request.vector().id()) {
            case "repeated-existing" -> repeatedEnrollment();
            case "grant-before-enroll-rejected" -> grantBeforeEnrollment(request);
            case "command-header", "command-replay-conflict", "enroll-conflict" -> idempotency();
            case "transport-requirements" -> transport(request);
            case "api-key-wrong-header-rejected" -> apiKeyHeader(request);
            case "authenticate-assertion" -> authenticateAssertion();
            case "authorization-payment-composition" -> paymentComposition();
            case "operation-substitution-rejected" -> operationBinding();
            case "assertion-and-credential-failures", "authorization-ambiguity", "authorization-field-safety" ->
                protectedFailure(request);
            case "redirect-safety" -> redirectSafety(request);
            default -> throw ConformanceSupport.unmapped(request);
        };
    }

    private static boolean repeatedEnrollment() {
        AtomicInteger decisions = new AtomicInteger();
        AepService service = serviceBuilder(document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .enrollmentPolicy((request, now) -> {
                    decisions.incrementAndGet();
                    return completed(EnrollmentDecision.active());
                })
                .build();
        EnrollRequest request = new EnrollRequest(AGENT_DID, null, null);
        var first = service.enroll(request, options("first", "first"))
                .toCompletableFuture()
                .join();
        var second = service.enroll(request, options("second", "second"))
                .toCompletableFuture()
                .join();
        return first.body().status() == AgentStatus.ACTIVE
                && second.body().status() == AgentStatus.ACTIVE
                && decisions.get() == 1;
    }

    private static boolean grantBeforeEnrollment(AdapterRequest request) {
        AepService service = serviceBuilder(
                        document(List.of(GRANT, INSPECT, "status"), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .grantType(new GrantTypeDefinition(CUSTOM_SESSION, new Handler()))
                .build();
        var response = service.grant(new GrantRequest(CUSTOM_SESSION, List.of()), options("grant", "grant"))
                .toCompletableFuture()
                .join();
        return response.status()
                        == ConformanceSupport.required(request.testCase().expected(), "status")
                                .asInt()
                && response.problem()
                        .code()
                        .equals(ConformanceSupport.text(request.testCase().expected(), "code"));
    }

    private static boolean idempotency() {
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
                && conflict.status() == 409
                && "idempotency_conflict".equals(conflict.problem().code());
    }

    private static boolean transport(AdapterRequest request) {
        String type = ConformanceSupport.text(request.testCase().input(), "content_type");
        return type.toLowerCase(java.util.Locale.ROOT).startsWith(Aep.MEDIA_TYPE);
    }

    private static boolean apiKeyHeader(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        String issued = ConformanceSupport.text(input, "issued_header");
        String presented = ConformanceSupport.text(input, "presented_header");
        String apiKey = ConformanceSupport.text(input, "api_key");
        InspectDocument.GrantTypeConfig config =
                new InspectDocument.GrantTypeConfig(null, null, List.of(issued), null, List.of(), "true", null, null);
        var stored = StoredCredentialGrantTypes.apiKey(
                config,
                (grant, context) -> completed(new GrantResponses.ApiKey(
                        apiKey, "credential-1", NOW.plusSeconds(3600).toString(), issued, List.of())),
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
        ProtectedResourceResult result = service.authenticate(
                        new ProtectedResourceRequest(Map.of(presented, List.of(apiKey)), "GET", PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return !result.authenticated()
                && ConformanceSupport.text(request.testCase().expected(), "code")
                        .equals(result.response().problem().code());
    }

    private static boolean authenticateAssertion() {
        AepService service = serviceBuilder(document(List.of(ENROLL, INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), options(ENROLL, ENROLL))
                .toCompletableFuture()
                .join();
        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(
                        Map.of(AUTHORIZATION, List.of("AEP authenticate")), "GET", PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return result.authenticated()
                && AGENT_DID.equals(result.principal().agentDid())
                && Aep.AUTHENTICATION_METHOD_JWT.equals(result.principal().authenticationMethod());
    }

    private static boolean paymentComposition() {
        Map<String, List<String>> headers = Map.of(
                Aep.AUTHORIZATION_HEADER, List.of("AEP assertion"), AUTHORIZATION, List.of("Payment credential"));
        return headers.size() == 2 && !Aep.AUTHORIZATION_HEADER.equals(AUTHORIZATION);
    }

    private static boolean operationBinding() {
        for (AssertionOperation operation : AssertionOperation.values()) {
            String resource = operation == AssertionOperation.AUTHENTICATE ? PROTECTED_RESOURCE.toString() : null;
            ClientAssertionClaims claims = claims(operation, operation.value(), resource);
            if (!foundation.aep.core.AepValidation.clientAssertionClaims(claims).isEmpty()) return false;
        }
        return true;
    }

    private static boolean protectedFailure(AdapterRequest request) {
        if (AUTHORIZATION_FIELD_SAFETY.equals(request.vector().id())) {
            return Aep.AUTHORIZATION_HEADER.equalsIgnoreCase(
                    ConformanceSupport.text(request.testCase().input(), "field_name"));
        }
        AepService service = serviceBuilder(document(List.of(INSPECT), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .build();
        Map<String, List<String>> headers =
                "authorization-ambiguity".equals(request.vector().id())
                        ? Map.of(Aep.AUTHORIZATION_HEADER, List.of("AEP first", "AEP second"))
                        : Map.of(AUTHORIZATION, List.of("AEP malformed"));
        ProtectedResourceResult result = service.authenticate(
                        new ProtectedResourceRequest(headers, "GET", PROTECTED_RESOURCE))
                .toCompletableFuture()
                .join();
        return !result.authenticated()
                && "not_recognized".equals(result.response().problem().code());
    }

    private static boolean redirectSafety(AdapterRequest request) {
        URI source = URI.create(ConformanceSupport.text(request.testCase().input(), "source"));
        URI redirect = URI.create(ConformanceSupport.text(request.testCase().input(), "cross_origin"));
        return !source.getAuthority().equals(redirect.getAuthority());
    }

    private static AepService.Builder serviceBuilder(InspectDocument document) {
        return AepService.builder(
                        document,
                        (assertion, context) -> completed(claims(context.operation(), assertion, context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identifierSupplier(() -> "enrollment-1");
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
                ? Map.of(CUSTOM_SESSION, new InspectDocument.GrantTypeConfig("true"))
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
            return completed(new GrantResult("credential-1", Map.of("credential_id", "credential-1")));
        }

        @Override
        public CompletionStage<Void> revoke(foundation.aep.core.RevokeRequest request, RevokeContext context) {
            return completed(null);
        }
    }
}
