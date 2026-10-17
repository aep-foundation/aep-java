package foundation.aep.service;

import foundation.aep.core.Aep;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Shared construction helpers for the AEP Service tests. */
final class ServiceFixtures {
    static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final String AGENT_DID = "did:web:agent.example";
    static final String SERVICE_DID = "did:web:service.example";
    static final String API_KEY_HEADER = "X-Service-Key";
    static final String AUTHORIZATION = "Authorization";
    static final URI RESOURCE = URI.create("https://service.example/private");
    static final List<String> ALL_COMMANDS = List.of("enroll", "grant", "inspect", "revoke", "status");

    private ServiceFixtures() {}

    static InspectDocument document(List<String> grantTypes, Map<String, InspectDocument.GrantTypeConfig> configs) {
        return document(grantTypes, configs, grantTypes);
    }

    static InspectDocument document(
            List<String> grantTypes,
            Map<String, InspectDocument.GrantTypeConfig> configs,
            List<String> authenticationMethods) {
        List<String> commands = grantTypes.isEmpty() ? List.of("enroll", "inspect", "status") : ALL_COMMANDS;
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(
                        authenticationMethods.isEmpty()
                                ? null
                                : new InspectDocument.Authentication(authenticationMethods))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(commands, grantTypes, configs))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
    }

    static InspectDocument.GrantTypeConfig config(List<String> headerNames) {
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

    static AepService.Builder serviceBuilder(InspectDocument document) {
        return AepService.builder(document, verifier()).clock(CLOCK).identifierSupplier(() -> "enrollment-1");
    }

    static ClientAssertionVerifier verifier() {
        return (assertion, context) -> completed(new ClientAssertionClaims(
                AGENT_DID,
                AGENT_DID,
                context.serviceDid(),
                context.operation(),
                NOW.minusSeconds(1).getEpochSecond(),
                NOW.plusSeconds(60).getEpochSecond(),
                assertion,
                context.operation() == AssertionOperation.AUTHENTICATE ? context.resource() : null));
    }

    /** A Service advertising all three built-in stored-credential Grant Types over one store. */
    static AepService storedCredentialService(ServiceCredentialStore store) {
        return storedCredentialService(store, EnrollmentStore.inMemory());
    }

    static AepService storedCredentialService(ServiceCredentialStore store, EnrollmentStore enrollmentStore) {
        Map<String, InspectDocument.GrantTypeConfig> configs = new LinkedHashMap<>();
        configs.put(Aep.GRANT_TYPE_OAUTH_BEARER, config(List.of()));
        configs.put(Aep.GRANT_TYPE_API_KEY, config(List.of(API_KEY_HEADER)));
        configs.put(Aep.GRANT_TYPE_BASIC, config(List.of()));
        List<String> grantTypes = List.of(Aep.GRANT_TYPE_OAUTH_BEARER, Aep.GRANT_TYPE_API_KEY, Aep.GRANT_TYPE_BASIC);
        return serviceBuilder(document(grantTypes, configs))
                .enrollmentStore(enrollmentStore)
                .storedCredentialGrantType(StoredCredentialGrantTypes.oauthBearer(
                        config(List.of()),
                        (request, context) -> completed(new GrantResponses.OAuthBearer(
                                "oauth-secret",
                                "oauth-1",
                                NOW.plusSeconds(600).toString(),
                                List.of("read"),
                                "opaque",
                                "Bearer")),
                        store))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)),
                        (request, context) -> completed(new GrantResponses.ApiKey(
                                "api-secret",
                                "api-1",
                                NOW.plusSeconds(600).toString(),
                                API_KEY_HEADER,
                                List.of("read"))),
                        store))
                .storedCredentialGrantType(StoredCredentialGrantTypes.basic(
                        config(List.of()),
                        (request, context) -> completed(new GrantResponses.Basic(
                                "basic-1",
                                NOW.plusSeconds(600).toString(),
                                "basic-secret",
                                "service",
                                List.of("read"),
                                "agent")),
                        store))
                .build();
    }

    static String basicCredentials() {
        return java.util.Base64.getEncoder()
                .encodeToString("agent:basic-secret".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    static void enroll(AepService service) {
        service.enroll(new EnrollRequest(AGENT_DID, null, null), CommandOptions.idempotent("enroll", "enroll-key"))
                .toCompletableFuture()
                .join();
    }

    static void grant(AepService service, String grantType) {
        service.grant(
                        new GrantRequest(grantType, List.of("read")),
                        CommandOptions.idempotent(grantType, grantType + "-key"))
                .toCompletableFuture()
                .join();
    }

    static ProtectedResourceResult authenticate(AepService service, Map<String, List<String>> headers) {
        return service.authenticate(new ProtectedResourceRequest(headers, "GET", RESOURCE))
                .toCompletableFuture()
                .join();
    }

    static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }
}
