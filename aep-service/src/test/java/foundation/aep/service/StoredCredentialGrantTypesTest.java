package foundation.aep.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

final class StoredCredentialGrantTypesTest {
    private static final String AGENT_DID = "did:web:agent.example";
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final URI RESOURCE = URI.create("https://service.example/private");

    @Test
    void issuesAuthenticatesAndRevokesEveryBuiltInCredential() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        InspectDocument.GrantTypeConfig apiConfig = config(List.of("x-service-key"));
        StoredCredentialGrantType oauth = StoredCredentialGrantTypes.oauthBearer(
                config(List.of()),
                (request, context) -> completed(new GrantResponses.OAuthBearer(
                        "oauth-secret",
                        "oauth-1",
                        NOW.plusSeconds(600).toString(),
                        List.of("read"),
                        "opaque",
                        "Bearer")),
                store);
        StoredCredentialGrantType apiKey = StoredCredentialGrantTypes.apiKey(
                apiConfig,
                (request, context) -> completed(new GrantResponses.ApiKey(
                        "api-secret", "api-1", NOW.plusSeconds(600).toString(), "X-Service-Key", List.of("read"))),
                store);
        StoredCredentialGrantType basic = StoredCredentialGrantTypes.basic(
                config(List.of()),
                (request, context) -> completed(new GrantResponses.Basic(
                        "basic-1",
                        NOW.plusSeconds(600).toString(),
                        "basic-secret",
                        "service",
                        List.of("read"),
                        "agent")),
                store);
        AepService service = service(oauth, apiKey, basic);
        enroll(service);

        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER, "grant-oauth");
        grant(service, Aep.GRANT_TYPE_API_KEY, "grant-api");
        grant(service, Aep.GRANT_TYPE_BASIC, "grant-basic");

        assertAuthenticated(service, Map.of("Authorization", List.of("Bearer oauth-secret")), "oauth-1");
        assertAuthenticated(service, Map.of("X-Service-Key", List.of("api-secret")), "api-1");
        assertAuthenticated(service, Map.of("Authorization", List.of("Basic YWdlbnQ6YmFzaWMtc2VjcmV0")), "basic-1");

        service.revoke(
                        RevokeRequest.credential(Aep.GRANT_TYPE_API_KEY, "api-1"),
                        CommandOptions.idempotent("revoke-api", "revoke-api-key"))
                .toCompletableFuture()
                .join();
        assertRejected(service, Map.of("X-Service-Key", List.of("api-secret")), "not_recognized");
    }

    @Test
    void distinguishesMissingWrongHeaderAndInvalidSelectedApiKey() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        StoredCredentialGrantType apiKey = StoredCredentialGrantTypes.apiKey(
                config(List.of("x-service-key")),
                (request, context) -> completed(new GrantResponses.ApiKey(
                        "api-secret", "api-1", NOW.plusSeconds(600).toString(), "X-Service-Key", List.of())),
                store);
        AepService service = service(apiKey);
        enroll(service);
        grant(service, Aep.GRANT_TYPE_API_KEY, "grant-api");

        assertRejected(service, Map.of(), "authentication_required");
        assertRejected(service, Map.of("X-Other-Key", List.of("api-secret")), "authentication_required");
        assertRejected(service, Map.of("X-Service-Key", List.of("wrong")), "not_recognized");
    }

    @Test
    void doesNotFallThroughFromAnInvalidSelectedBearerToAValidApiKey() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        StoredCredentialGrantType oauth = StoredCredentialGrantTypes.oauthBearer(
                config(List.of()),
                (request, context) -> completed(new GrantResponses.OAuthBearer(
                        "oauth-secret", "oauth-1", NOW.plusSeconds(600).toString(), List.of(), "Bearer")),
                store);
        StoredCredentialGrantType apiKey = StoredCredentialGrantTypes.apiKey(
                config(List.of("x-service-key")),
                (request, context) -> completed(new GrantResponses.ApiKey(
                        "api-secret", "api-1", NOW.plusSeconds(600).toString(), "X-Service-Key", List.of())),
                store);
        AepService service = service(oauth, apiKey);
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER, "grant-oauth");
        grant(service, Aep.GRANT_TYPE_API_KEY, "grant-api");

        assertRejected(
                service,
                Map.of(
                        "AEP-Authorization", List.of("Bearer wrong"),
                        "X-Service-Key", List.of("api-secret")),
                "not_recognized");
        assertRejected(
                service,
                Map.of(
                        "AEP-Authorization", List.of("Bearer oauth-secret"),
                        "X-Service-Key", List.of("api-secret")),
                "not_recognized");
    }

    @Test
    void rejectsUnadvertisedApiKeyHeaderAndCredentialIdentifierReuse() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        StoredCredentialGrantType wrongHeader = StoredCredentialGrantTypes.apiKey(
                config(List.of("x-service-key")),
                (request, context) -> completed(new GrantResponses.ApiKey(
                        "api-secret", "api-1", NOW.plusSeconds(600).toString(), "X-Other-Key", List.of())),
                store);
        AepService service = service(wrongHeader);
        enroll(service);

        assertThrows(
                CompletionException.class,
                () -> service.grant(
                                new GrantRequest(Aep.GRANT_TYPE_API_KEY, List.of()),
                                CommandOptions.idempotent("grant-invalid", "grant-invalid-key"))
                        .toCompletableFuture()
                        .join());

        StoredCredentialGrantType valid = StoredCredentialGrantTypes.apiKey(
                config(List.of("x-service-key")),
                (request, context) -> completed(new GrantResponses.ApiKey(
                        "api-secret", "api-1", NOW.plusSeconds(600).toString(), "X-Service-Key", List.of())),
                store);
        AepService validService = service(valid);
        enroll(validService);
        grant(validService, Aep.GRANT_TYPE_API_KEY, "grant-first");
        assertThrows(CompletionException.class, () -> grant(validService, Aep.GRANT_TYPE_API_KEY, "grant-second"));
    }

    @Test
    void enforcesConfiguredClaimValueLimits() {
        AepService service = baseBuilder(document(List.of(), Map.of()))
                .claimValueLimits(new ClaimValueLimits(1_024, 1, 4, 100))
                .build();
        foundation.aep.core.ClaimValues claims = foundation.aep.core.ClaimValues.builder()
                .contactEmail("agent@example.com")
                .personFirstName("Agent")
                .build();

        ServiceResponse<?> response = service.enroll(
                        new EnrollRequest(AGENT_DID, claims, null),
                        CommandOptions.idempotent("enroll-limited", "enroll-limited-key"))
                .toCompletableFuture()
                .join();

        assertEquals(422, response.status());
        assertEquals("requirements_unmet", response.problem().code());
    }

    private static AepService service(StoredCredentialGrantType... grantTypes) {
        List<String> names = java.util.Arrays.stream(grantTypes)
                .map(StoredCredentialGrantType::grantType)
                .toList();
        Map<String, InspectDocument.GrantTypeConfig> configs = new LinkedHashMap<>();
        for (StoredCredentialGrantType grantType : grantTypes) {
            List<String> headers =
                    Aep.GRANT_TYPE_API_KEY.equals(grantType.grantType()) ? List.of("x-service-key") : List.of();
            configs.put(grantType.grantType(), config(headers));
        }
        AepService.Builder builder = baseBuilder(document(names, configs));
        for (StoredCredentialGrantType grantType : grantTypes) builder.storedCredentialGrantType(grantType);
        return builder.build();
    }

    private static AepService.Builder baseBuilder(InspectDocument document) {
        return AepService.builder(
                        document,
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.operation() == foundation.aep.core.AssertionOperation.AUTHENTICATE
                                        ? context.resource()
                                        : null)))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .identifierSupplier(() -> "enrollment-1");
    }

    private static InspectDocument document(
            List<String> grantTypes, Map<String, InspectDocument.GrantTypeConfig> configs) {
        List<String> commands = grantTypes.isEmpty()
                ? List.of("enroll", "inspect", "status")
                : List.of("enroll", "grant", "inspect", "revoke", "status");
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(grantTypes.isEmpty() ? null : new InspectDocument.Authentication(grantTypes))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(commands, grantTypes, configs))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
    }

    private static InspectDocument.GrantTypeConfig config(List<String> headerNames) {
        return new InspectDocument.GrantTypeConfig(
                List.of("opaque", "jwt"),
                "600",
                headerNames,
                "service",
                List.of("read"),
                "true",
                "https://service.example/introspect",
                "https://service.example/revoke");
    }

    private static void enroll(AepService service) {
        ServiceResponse<?> response = service.enroll(
                        new EnrollRequest(AGENT_DID, null, null), CommandOptions.idempotent("enroll", "enroll-key"))
                .toCompletableFuture()
                .join();
        assertEquals(AgentStatus.ACTIVE, ((foundation.aep.core.EnrollResponse) response.body()).status());
    }

    private static void grant(AepService service, String grantType, String assertion) {
        ServiceResponse<Map<String, Object>> response = service.grant(
                        new GrantRequest(grantType, List.of("read")),
                        CommandOptions.idempotent(assertion, assertion + "-key"))
                .toCompletableFuture()
                .join();
        assertEquals(200, response.status());
    }

    private static void assertAuthenticated(
            AepService service, Map<String, List<String>> headers, String credentialId) {
        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(headers, "GET", RESOURCE))
                .toCompletableFuture()
                .join();
        assertTrue(result.authenticated());
        assertEquals(credentialId, result.principal().credentialId());
        assertFalse(result.principal().toString().contains("secret"));
    }

    private static void assertRejected(AepService service, Map<String, List<String>> headers, String code) {
        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(headers, "GET", RESOURCE))
                .toCompletableFuture()
                .join();
        assertFalse(result.authenticated());
        assertEquals(code, result.response().problem().code());
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }
}
