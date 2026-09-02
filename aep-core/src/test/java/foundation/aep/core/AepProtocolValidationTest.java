package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AepProtocolValidationTest {
    @Test
    void validatesLifecycleMessages() {
        EnrollRequest enrollRequest = new EnrollRequest(
                "did:web:agent.example",
                ClaimValues.builder().contactEmail("agent@example.com").build(),
                "enroll-1");
        EnrollResponse enrollResponse =
                new EnrollResponse(AgentStatus.PENDING, "true", List.of("email"), List.of("profile"));
        StatusResponse statusResponse =
                new StatusResponse(AgentStatus.ACTIVE, null, null, null, "2026-09-01T12:00:00Z");

        assertTrue(AepValidation.enrollRequest(enrollRequest).isEmpty());
        assertTrue(AepValidation.enrollResponse(enrollResponse).isEmpty());
        assertTrue(AepValidation.statusResponse(statusResponse).isEmpty());
        assertEquals(
                "$.agent_did",
                AepValidation.enrollRequest(new EnrollRequest("", null, null))
                        .get(0)
                        .path());
        assertFalse(AepValidation.enrollResponse(new EnrollResponse(AgentStatus.ACTIVE, "true", List.of(), List.of()))
                .isEmpty());
        assertFalse(
                AepValidation.statusResponse(new StatusResponse(AgentStatus.ACTIVE, "false", null, null, "not-a-date"))
                        .isEmpty());
    }

    @Test
    void validatesGrantAndRevokeMessages() {
        GrantRequest grantRequest = new GrantRequest("oauth-bearer", "production", List.of("read"), "opaque");

        assertTrue(AepValidation.grantRequest(grantRequest).isEmpty());
        assertTrue(AepValidation.revokeRequest(RevokeRequest.forAllGrantTypes()).isEmpty());
        assertTrue(
                AepValidation.revokeRequest(RevokeRequest.grantType("api-key")).isEmpty());
        assertTrue(AepValidation.revokeRequest(RevokeRequest.credential("api-key", "credential-1"))
                .isEmpty());
        assertFalse(AepValidation.grantRequest(new GrantRequest("", List.of("read")))
                .isEmpty());
        assertFalse(AepValidation.grantRequest(new GrantRequest("oauth-bearer", null, List.of(), "invalid"))
                .isEmpty());
        assertFalse(AepValidation.revokeRequest(new RevokeRequest(null, "credential-1", null))
                .isEmpty());
        assertFalse(AepValidation.revokeRequest(new RevokeRequest("api-key", null, "true"))
                .isEmpty());
    }

    @Test
    void validatesBuiltInGrantConfigurationAndProfileFields() {
        InspectDocument.GrantTypeConfig config = new InspectDocument.GrantTypeConfig(
                List.of(), "600", List.of("x-service-key"), null, List.of("read"), "true", null, null);

        assertEquals("600", config.defaultLifetimeSeconds());
        assertEquals(List.of("x-service-key"), config.headerNames());
        assertEquals(List.of("read"), config.scopesSupported());
        assertEquals("true", config.supportsPerCredentialRevoke());

        GrantRequest request = new GrantRequest("oauth-bearer", "prod", List.of(), "jwt");
        GrantResponses.OAuthBearer response = new GrantResponses.OAuthBearer(
                "secret", "credential-1", "2027-01-01T00:00:00Z", List.of(), "jwt", "Bearer");
        assertEquals("prod", request.label());
        assertEquals("jwt", request.tokenFormat());
        assertEquals("jwt", response.tokenFormat());
    }

    @Test
    void rejectsNonJsonAdditionalClaimValues() {
        ClaimValues values = ClaimValues.builder()
                .additional("example.invalid", URI.create("https://example.com"))
                .build();

        assertFalse(AepValidation.claimValues(values).isEmpty());
    }

    @Test
    void validatesBuiltInGrantResponses() {
        String expiration = "2026-09-01T12:00:00Z";

        assertTrue(AepValidation.grantResponse(
                        new GrantResponses.OAuthBearer("token", "credential-1", expiration, null, "Bearer"))
                .isEmpty());
        assertTrue(AepValidation.grantResponse(
                        new GrantResponses.ApiKey("secret", "credential-1", expiration, "X-Key", List.of("read")))
                .isEmpty());
        assertTrue(AepValidation.grantResponse(
                        new GrantResponses.Basic("credential-1", expiration, "secret", null, List.of(), "agent"))
                .isEmpty());
        assertFalse(new GrantResponses.OAuthBearer("raw-oauth-secret", "credential-1", expiration, null, "Bearer")
                .toString()
                .contains("raw-oauth-secret"));
        assertFalse(new GrantResponses.ApiKey("secret", "credential-1", expiration, "X-Key", null)
                .toString()
                .contains("secret"));
        assertFalse(new GrantResponses.Basic("credential-1", expiration, "secret", null, null, "agent")
                .toString()
                .contains("secret"));
        assertFalse(new GrantResponses.Basic("credential-1", expiration, "secret", null, null, "agent")
                .toString()
                .contains("agent"));
        assertFalse(AepValidation.grantResponse(new GrantResponses.OAuthBearer("", "", "later", List.of(), "bearer"))
                .isEmpty());
        assertFalse(AepValidation.grantResponse(
                        new GrantResponses.ApiKey("", "credential-1", expiration, "", List.of("read", "read")))
                .isEmpty());
        assertFalse(AepValidation.grantResponse(
                        new GrantResponses.ApiKey("secret value", "credential-1", expiration, "invalid header", null))
                .isEmpty());
        assertFalse(
                AepValidation.grantResponse(new GrantResponses.Basic("credential-1", expiration, "", "", List.of(), ""))
                        .isEmpty());
        assertFalse(AepValidation.grantResponse(
                        new GrantResponses.Basic("credential-1", expiration, "secret\n", null, null, "agent:name"))
                .isEmpty());
    }

    @Test
    void validatesIdempotencyAndProblemDetails() {
        String hash = "sha256:" + "a".repeat(64);
        IdempotencyMetadata metadata = new IdempotencyMetadata("did:web:agent.example", "request-1", hash, hash);
        ProblemDetails problem = ProblemDetails.of("invalid_request", "Invalid request", 400);

        assertTrue(AepValidation.idempotencyMetadata(metadata).isEmpty());
        assertTrue(AepValidation.problemDetails(problem).isEmpty());
        assertFalse(AepValidation.idempotencyMetadata(new IdempotencyMetadata(null, "", "one", "two"))
                .isEmpty());
        assertFalse(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:wrong",
                        "",
                        99,
                        null,
                        "relative",
                        "not_recognized",
                        "true",
                        List.of("secret"),
                        null))
                .isEmpty());
    }

    @Test
    void validatesAuthorizationContracts() {
        ProtectedResourceAuthorization authorization = new ProtectedResourceAuthorization(
                AuthorizationCarrier.STANDARD, AuthorizationScheme.BEARER, "credential");
        OpenApiAepSecurityScheme scheme = new OpenApiAepSecurityScheme("api-key");

        assertTrue(AepValidation.protectedResourceAuthorization(authorization).isEmpty());
        assertTrue(AepValidation.openApiSecurityScheme(scheme).isEmpty());
        assertFalse(AepValidation.protectedResourceAuthorization(new ProtectedResourceAuthorization(null, null, ""))
                .isEmpty());
        assertFalse(AepValidation.openApiSecurityScheme(new OpenApiAepSecurityScheme("Bad Value"))
                .isEmpty());
        assertEquals(AuthorizationCarrier.STANDARD, AuthorizationCarrier.fromValue("Authorization"));
        assertEquals(AuthorizationScheme.BASIC, AuthorizationScheme.fromValue("Basic"));
        assertThrows(IllegalArgumentException.class, () -> AuthorizationCarrier.fromValue("authorization"));
        assertThrows(IllegalArgumentException.class, () -> AuthorizationScheme.fromValue("Unknown"));
    }

    @Test
    void validatesCompleteInspectDocumentAndInvalidBranches() {
        InspectDocument valid = completeInspectDocument();
        assertTrue(AepValidation.inspectDocument(valid).isEmpty());

        InspectDocument invalid = InspectDocument.builder()
                .version("2.0")
                .authentication(new InspectDocument.Authentication(List.of("Bad", "Bad")))
                .bindings(new InspectDocument.Bindings(List.of("other")))
                .claims(new InspectDocument.Claims(List.of("Bad"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        List.of("authenticate", "grant"),
                        List.of(),
                        Map.of("Bad", new InspectDocument.GrantTypeConfig("maybe"))))
                .core(new InspectDocument.Core(List.of("ES384")))
                .extensions(new InspectDocument.Extensions(List.of("relative")))
                .http(new InspectDocument.Http(
                        "relative", new InspectDocument.OpenApi("", new InspectDocument.PathMatching("loose"))))
                .identity(new InspectDocument.Identity(List.of()))
                .service(new InspectDocument.Service("service"))
                .build();

        List<ValidationIssue> issues = AepValidation.inspectDocument(invalid);
        assertTrue(issues.size() > 10);
        assertTrue(issues.stream().anyMatch(issue -> "$.commands.supported".equals(issue.path())));
        assertTrue(issues.stream().anyMatch(issue -> "$.core.signing_algorithms".equals(issue.path())));
        assertTrue(issues.stream().anyMatch(issue -> "$.http.endpoint_base".equals(issue.path())));
    }

    @Test
    void validatesAssertionClaimsAndVerificationConfiguration() {
        ClientAssertionClaims claims = new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.ENROLL,
                1_788_264_000L,
                1_788_264_300L,
                "assertion-1",
                null);

        assertTrue(AepValidation.clientAssertionClaims(claims).isEmpty());
        assertFalse(AepValidation.clientAssertionClaims(new ClientAssertionClaims(
                        "did:web:agent.example",
                        "did:web:agent.example",
                        "did:web:service.example",
                        AssertionOperation.ENROLL,
                        Long.MIN_VALUE,
                        Long.MAX_VALUE,
                        "assertion-overflow",
                        null))
                .isEmpty());
        assertThrows(
                AepValidationException.class,
                () -> AepValidation.requireClientAssertionClaims(
                        new ClientAssertionClaims("agent", "different", "relative", null, 0, 0, "", "relative"),
                        false));
        assertEquals(AssertionOperation.AUTHENTICATE, AssertionOperation.fromValue("authenticate"));
        assertThrows(IllegalArgumentException.class, () -> AssertionOperation.fromValue("unknown"));

        ClientAssertionVerification verification = ClientAssertionVerification.builder(
                        claims.audience(), claims.issuer(), claims.operation())
                .resource("https://service.example/resource")
                .clockSkew(Duration.ofSeconds(10))
                .allowInsecureLoopback(true)
                .build();
        assertEquals(Duration.ofSeconds(10), verification.clockSkew());
        assertTrue(verification.allowInsecureLoopback());
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertionVerification.builder(claims.audience(), claims.issuer(), claims.operation())
                        .clockSkew(Duration.ofSeconds(-1))
                        .build());
    }

    @Test
    void rejectsUnsafeHttpComposition() {
        assertEquals("/aep/", AepHttp.normalizeEndpointBase(null));
        assertEquals("/custom/", AepHttp.normalizeEndpointBase("/custom"));
        assertThrows(IllegalArgumentException.class, () -> AepHttp.normalizeEndpointBase("//evil.example"));
        assertThrows(IllegalArgumentException.class, () -> AepHttp.normalizeEndpointBase("/aep?query"));
        assertEquals(
                URI.create("https://service.example/aep/status"),
                AepHttp.commandUri(URI.create("https://service.example"), AepCommand.STATUS, "/aep"));
    }

    @Test
    void validatesDidWebBoundaryCases() {
        assertEquals(
                URI.create("http://localhost:8080/.well-known/did.json"),
                DidWeb.documentUri("did:web:localhost%3A8080", true));
        assertEquals(
                URI.create("https://localhost:8080/.well-known/did.json"),
                DidWeb.documentUri("did:web:localhost%3A8080"));
        assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri("did:web:user@example.com"));
        assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri("did:web:example.com:"));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com", URI.create("http://example.com")));
    }

    private static InspectDocument completeInspectDocument() {
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of("api-key")))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(
                        List.of("contact.email"), List.of("person.first_name"), List.of("contact.mobile")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "enroll", "grant", "revoke", "status"),
                        List.of("api-key"),
                        Map.of("api-key", new InspectDocument.GrantTypeConfig("true"))))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .extensions(new InspectDocument.Extensions(List.of("https://example.com/aep-extension")))
                .http(new InspectDocument.Http(
                        "/aep",
                        new InspectDocument.OpenApi("/openapi.json", new InspectDocument.PathMatching("strict"))))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
    }
}
