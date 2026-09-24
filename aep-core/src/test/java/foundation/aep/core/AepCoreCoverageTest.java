package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Edge and failure paths across the Core contracts. */
final class AepCoreCoverageTest {

    private static List<String> paths(List<ValidationIssue> issues) {
        return issues.stream().map(ValidationIssue::path).toList();
    }

    @Test
    void rejectsAbsentDocumentsAcrossEveryValidator() {
        List<List<ValidationIssue>> results = List.of(
                AepValidation.inspectDocument(null),
                AepValidation.claimValues(null),
                AepValidation.enrollRequest(null),
                AepValidation.enrollResponse(null),
                AepValidation.statusResponse(null),
                AepValidation.grantRequest(null),
                AepValidation.revokeRequest(null),
                AepValidation.clientAssertionClaims(null),
                AepValidation.idempotencyMetadata(null),
                AepValidation.problemDetails(null),
                AepValidation.platformDiscoveryDocument(null),
                AepValidation.platformAgentIdentity(null),
                AepValidation.platformAgentIdentityListResponse(null),
                AepValidation.platformProvisionRequest(null),
                AepValidation.platformLifecycleRequest(null),
                AepValidation.platformSignRequest(null),
                AepValidation.platformSignResponse(null),
                AepValidation.platformVerificationRequest(null),
                AepValidation.platformVerificationResponse(null),
                AepValidation.grantResponse(null),
                AepValidation.protectedResourceAuthorization(null),
                AepValidation.openApiSecurityScheme(null));
        for (List<ValidationIssue> issues : results) {
            assertEquals(List.of("$"), paths(issues));
        }
    }

    @Test
    void requireHelpersRaiseTypedFailures() {
        AepValidationException failure =
                assertThrows(AepValidationException.class, () -> AepValidation.requireInspectDocument(null));
        assertEquals("Inspect document", failure.documentType());
        assertEquals(List.of("$"), paths(failure.issues()));
        assertNull(failure.getCause());
        assertTrue(failure.getMessage().contains("Inspect document"));

        assertThrows(AepValidationException.class, () -> AepValidation.requireClaimValues(null));
        assertThrows(AepValidationException.class, () -> AepValidation.requireClientAssertionClaims(null, false));
        assertThrows(AepValidationException.class, () -> AepValidation.requirePlatformDiscoveryDocument(null));
        assertThrows(AepValidationException.class, () -> AepValidation.requirePlatformAgentIdentity(null));
        assertThrows(AepValidationException.class, () -> AepValidation.requirePlatformSignResponse(null));

        AepValidationException wrapped = new AepValidationException(
                "thing", List.of(new ValidationIssue("$", "bad")), new IllegalStateException());
        assertNotNull(wrapped.getCause());

        AepAuthorizationException authorization = new AepAuthorizationException("not_recognized", "message");
        assertEquals("not_recognized", authorization.code());
        assertEquals("message", authorization.getMessage());
    }

    @Test
    void acceptsAFullyPopulatedInspectDocument() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of("aep-jwt", "api-key")))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(
                        List.of("contact.email"), List.of("person.first_name"), List.of("person.username")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "enroll", "grant", "revoke", "status"),
                        List.of("api-key", "oauth-bearer"),
                        Map.of(
                                "api-key",
                                        new InspectDocument.GrantTypeConfig(
                                                null,
                                                "300",
                                                List.of("x-api-key"),
                                                null,
                                                List.of("read"),
                                                "true",
                                                null,
                                                null),
                                "oauth-bearer",
                                        new InspectDocument.GrantTypeConfig(
                                                List.of("opaque", "jwt"),
                                                "60",
                                                null,
                                                null,
                                                List.of("read"),
                                                "false",
                                                "https://api.example/introspect",
                                                "https://api.example/revoke"))))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .extensions(new InspectDocument.Extensions(List.of("https://example.com/aep-extension")))
                .http(new InspectDocument.Http(
                        "/v1/aep",
                        new InspectDocument.OpenApi(
                                "https://api.example/openapi.json", new InspectDocument.PathMatching("equivalent"))))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        assertTrue(AepValidation.inspectDocument(document).isEmpty());
        assertSame(document, AepValidation.requireInspectDocument(document));
    }

    @Test
    void reportsEveryInspectDocumentDefect() {
        InspectDocument document = InspectDocument.builder()
                .version("2.0")
                .authentication(new InspectDocument.Authentication(List.of("Bad Method", "api-key", "api-key")))
                .bindings(new InspectDocument.Bindings(List.of("grpc")))
                .claims(new InspectDocument.Claims(List.of("Contact.Email"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "grant"),
                        List.of("api-key"),
                        Map.of(
                                "Not A Grant Type",
                                new InspectDocument.GrantTypeConfig(
                                        List.of("saml"),
                                        "0",
                                        List.of("bad header", "X-Api-Key", "x-api-key"),
                                        null,
                                        List.of(),
                                        "maybe",
                                        "http://api.example/introspect",
                                        null))))
                .core(new InspectDocument.Core(List.of()))
                .extensions(new InspectDocument.Extensions(List.of("not-a-uri")))
                .http(new InspectDocument.Http(
                        "relative", new InspectDocument.OpenApi("", new InspectDocument.PathMatching("loose"))))
                .identity(new InspectDocument.Identity(List.of("BadMethod")))
                .service(new InspectDocument.Service("service.example"))
                .build();
        List<String> reported = paths(AepValidation.inspectDocument(document));
        for (String expected : List.of(
                "$.aep_version",
                "$.authentication.methods[0]",
                "$.bindings.supported",
                "$.claims.required[0]",
                "$.core.signing_algorithms",
                "$.extensions.supported[0]",
                "$.http.endpoint_base",
                "$.http.openapi.url",
                "$.http.openapi.path_matching.trailing_slash",
                "$.identity.methods[0]",
                "$.service.did")) {
            assertTrue(reported.contains(expected), expected + " in " + reported);
        }
    }

    @Test
    void reportsGrantTypeConfigurationDefects() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "grant", "revoke"),
                        List.of("api-key", "oauth-bearer"),
                        Map.of(
                                "api-key",
                                        new InspectDocument.GrantTypeConfig(
                                                null,
                                                null,
                                                List.of("X-Api-Key", "x-api-key"),
                                                null,
                                                null,
                                                "yes",
                                                null,
                                                null),
                                "oauth-bearer",
                                        new InspectDocument.GrantTypeConfig(
                                                List.of("saml"),
                                                null,
                                                null,
                                                null,
                                                null,
                                                null,
                                                "http://api.example/introspect",
                                                null))))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        List<String> reported = paths(AepValidation.inspectDocument(document));
        assertTrue(reported.contains("$.commands.grant_types_config.api-key.header_names[1]"), reported.toString());
        assertTrue(
                reported.contains("$.commands.grant_types_config.api-key.supports_per_credential_revoke"),
                reported.toString());
        assertTrue(
                reported.contains("$.commands.grant_types_config.oauth-bearer.access_token_formats[0]"),
                reported.toString());
        assertTrue(
                reported.contains("$.commands.grant_types_config.oauth-bearer.introspection_endpoint"),
                reported.toString());
    }

    @Test
    void reportsUnadvertisedGrantTypeConfiguration() {
        Map<String, InspectDocument.GrantTypeConfig> configs = new LinkedHashMap<>();
        configs.put("basic", new InspectDocument.GrantTypeConfig("true"));
        configs.put("Not A Grant Type", new InspectDocument.GrantTypeConfig("true"));
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "grant", "revoke"), List.of("api-key"), configs))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        List<String> reported = paths(AepValidation.inspectDocument(document));
        assertTrue(reported.contains("$.commands.grant_types_config.basic"), reported.toString());
        assertTrue(reported.contains("$.commands.grant_types_config.Not A Grant Type"), reported.toString());
    }

    @Test
    void recognizesCompatibleAndIncompatibleVersions() {
        assertTrue(AepValidation.isCompatibleVersion("1.0"));
        assertTrue(AepValidation.isCompatibleVersion("1.7"));
        assertFalse(AepValidation.isCompatibleVersion("2.0"));
        assertFalse(AepValidation.isCompatibleVersion("1"));
        assertFalse(AepValidation.isCompatibleVersion("1.0.0"));
        assertFalse(AepValidation.isCompatibleVersion("01.0"));
        assertFalse(AepValidation.isCompatibleVersion(null));
    }

    @Test
    void validatesClaimValueShapes() {
        ClaimValues values = ClaimValues.builder()
                .contactAddressPrimary(new ContactAddressPrimary(
                        "Springfield", "US", "Ada", "Lovelace", "1 Main Street", "Apt 2", "Floor 3", "12345", "IL"))
                .contactEmail("agent@example.com")
                .contactMobile("+14155550123")
                .personBirthdate("1815-12-10")
                .personFirstName("Ada")
                .personLastName("Lovelace")
                .personUsername("ada")
                .additional("example.list", java.util.Arrays.asList(1, "two", true, null))
                .additional("example.nested", Map.of("inner", Map.of("deep", 1.5)))
                .build();
        assertTrue(AepValidation.claimValues(values).isEmpty());
        assertTrue(values.contains(Aep.CLAIM_CONTACT_EMAIL));
        assertTrue(values.contains("example.list"));
        assertFalse(values.contains("example.absent"));
        assertSame(values, AepValidation.requireClaimValues(values));

        ClaimValues invalidAddress = ClaimValues.builder()
                .contactAddressPrimary(new ContactAddressPrimary("", "USA", "", "", "", null, null, null, null))
                .build();
        List<String> reported = paths(AepValidation.claimValues(invalidAddress));
        assertTrue(reported.contains("$.contact.address.primary.city"), reported.toString());
        assertTrue(reported.contains("$.contact.address.primary.country"), reported.toString());
        assertTrue(reported.contains("$.contact.address.primary.first_name"), reported.toString());
        assertTrue(reported.contains("$.contact.address.primary.last_name"), reported.toString());
        assertTrue(reported.contains("$.contact.address.primary.line1"), reported.toString());
    }

    @Test
    void rejectsClaimValuesThatAreNotJson() {
        ClaimValues values =
                ClaimValues.builder().additional("example.object", new Object()).build();
        assertEquals(List.of("$.example.object"), paths(AepValidation.claimValues(values)));

        ClaimValues infinite = ClaimValues.builder()
                .additional("example.number", Double.POSITIVE_INFINITY)
                .build();
        assertEquals(List.of("$.example.number"), paths(AepValidation.claimValues(infinite)));

        ClaimValues infiniteFloat =
                ClaimValues.builder().additional("example.float", Float.NaN).build();
        assertEquals(List.of("$.example.float"), paths(AepValidation.claimValues(infiniteFloat)));

        ClaimValues nestedBad = ClaimValues.builder()
                .additional("example.list", List.of(List.of(new Object())))
                .build();
        assertEquals(List.of("$.example.list[0][0]"), paths(AepValidation.claimValues(nestedBad)));

        Map<Object, Object> nonStringKey = new LinkedHashMap<>();
        nonStringKey.put(1, "value");
        ClaimValues badKey =
                ClaimValues.builder().additional("example.map", nonStringKey).build();
        assertEquals(List.of("$.example.map"), paths(AepValidation.claimValues(badKey)));
    }

    @Test
    void validatesDateAndTimeFormats() {
        assertTrue(AepValidation.statusResponse(
                        new StatusResponse(AgentStatus.ACTIVE, null, null, null, "2026-09-01T12:00:00Z"))
                .isEmpty());
        assertTrue(AepValidation.statusResponse(
                        new StatusResponse(AgentStatus.ACTIVE, null, null, null, "2026-09-01T12:00:00.123+01:00"))
                .isEmpty());
        assertTrue(AepValidation.statusResponse(new StatusResponse(AgentStatus.ACTIVE, null, null, null, null))
                .isEmpty());
        for (String value : List.of("2026-09-01", "2026-09-01T12:00:00", "", "not-a-date")) {
            assertFalse(
                    AepValidation.statusResponse(new StatusResponse(AgentStatus.ACTIVE, null, null, null, value))
                            .isEmpty(),
                    value);
        }
        for (String birthdate : List.of("1815-12-10")) {
            assertTrue(AepValidation.claimValues(
                            ClaimValues.builder().personBirthdate(birthdate).build())
                    .isEmpty());
        }
        for (String birthdate : List.of("1815-12-10T00:00:00Z", "815-12-10", "2025-02-29", "1815-1-1", "")) {
            assertFalse(
                    AepValidation.claimValues(ClaimValues.builder()
                                    .personBirthdate(birthdate)
                                    .build())
                            .isEmpty(),
                    birthdate);
        }
    }

    @Test
    void validatesLifecycleMetadataAndStatusMessages() {
        assertTrue(paths(AepValidation.enrollResponse(new EnrollResponse(null, null, null, null)))
                .contains("$.status"));
        assertTrue(paths(AepValidation.enrollResponse(new EnrollResponse(AgentStatus.ACTIVE, "maybe", null, null)))
                .contains("$.owner_action_required"));
        assertTrue(AepValidation.enrollResponse(new EnrollResponse(AgentStatus.ACTIVE, "false", null, null))
                .isEmpty());
        assertTrue(paths(AepValidation.statusResponse(new StatusResponse(null, null, null, null, null)))
                .contains("$.status"));
        assertTrue(paths(AepValidation.enrollResponse(
                        new EnrollResponse(AgentStatus.ACTIVE, null, List.of("a", "a"), null)))
                .contains("$.verification_pending[1]"));
        assertTrue(paths(AepValidation.enrollResponse(
                        new EnrollResponse(AgentStatus.ACTIVE, null, null, List.of("", "b"))))
                .contains("$.requirements_pending[0]"));
    }

    @Test
    void validatesEnrollAndGrantRequests() {
        assertTrue(paths(AepValidation.enrollRequest(new EnrollRequest("did:web:agent.example", null, "")))
                .contains("$.idempotency_key"));
        assertTrue(paths(AepValidation.enrollRequest(new EnrollRequest(
                        "did:web:agent.example",
                        ClaimValues.builder().contactEmail("bad").build(),
                        null)))
                .contains("$.claims.contact.email"));
        assertTrue(paths(AepValidation.grantRequest(new GrantRequest("", null, null, null)))
                .contains("$.grant_type"));
        assertTrue(paths(AepValidation.grantRequest(new GrantRequest("oauth-bearer", null, null, "saml")))
                .contains("$.token_format"));
        assertTrue(paths(AepValidation.grantRequest(new GrantRequest("api-key", null, null, "")))
                .contains("$.token_format"));
        // The Grant request schema puts no minimum length on a requested scope, so an empty entry is
        // the Service's business rather than a wire-shape defect.
        assertTrue(AepValidation.grantRequest(new GrantRequest("api-key", null, List.of("", "read"), null))
                .isEmpty());
        assertTrue(AepValidation.grantRequest(new GrantRequest("oauth-bearer", null, List.of(), "opaque"))
                .isEmpty());
    }

    @Test
    void validatesIdempotencyMetadata() {
        assertTrue(AepValidation.idempotencyMetadata(new IdempotencyMetadata(
                        "did:web:agent.example", "key-1", "sha256:" + "a".repeat(64), "sha256:" + "b".repeat(64)))
                .isEmpty());
        assertTrue(AepValidation.idempotencyMetadata(new IdempotencyMetadata(null, "key-1", null, null))
                .isEmpty());
        List<String> reported = paths(AepValidation.idempotencyMetadata(
                new IdempotencyMetadata("", "", "sha256:short", "md5:" + "a".repeat(64))));
        assertTrue(reported.contains("$.agent_did"), reported.toString());
        assertTrue(reported.contains("$.idempotency_key"), reported.toString());
        assertTrue(reported.contains("$.first_body_hash"), reported.toString());
        assertTrue(reported.contains("$.second_body_hash"), reported.toString());
    }

    @Test
    void validatesPlatformDiscoveryDocuments() {
        PlatformDiscoveryDocument valid = new PlatformDiscoveryDocument(
                Aep.VERSION,
                new PlatformDiscoveryDocument.Endpoints(
                        "/v1/aep/verifications",
                        "/v1/aep/identities/{agent_identity_id}",
                        "/v1/aep/identities",
                        "/v1/aep/identities",
                        "/v1/aep/identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep"),
                new PlatformDiscoveryDocument.Identity(
                        List.of("did:web"), "https://platform.example/agents/{agent_did_id}/did.json"),
                new PlatformDiscoveryDocument.Platform("did:web:platform.example", true, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("EdDSA", "ES256"), "300"));
        assertTrue(AepValidation.platformDiscoveryDocument(valid).isEmpty());
        assertSame(valid, AepValidation.requirePlatformDiscoveryDocument(valid));

        PlatformDiscoveryDocument missing = new PlatformDiscoveryDocument("2.0", null, null, null, null, null);
        List<String> reported = paths(AepValidation.platformDiscoveryDocument(missing));
        for (String expected :
                List.of("$.aep_version", "$.endpoints", "$.http", "$.identity", "$.platform", "$.signing")) {
            assertTrue(reported.contains(expected), expected + " in " + reported);
        }

        PlatformDiscoveryDocument invalid = new PlatformDiscoveryDocument(
                Aep.VERSION,
                new PlatformDiscoveryDocument.Endpoints("relative", "/no-template", "", "/list?x=1", "/sign#y"),
                new PlatformDiscoveryDocument.Http("//attacker.example"),
                new PlatformDiscoveryDocument.Identity(List.of(), "https://platform.example/did.json"),
                new PlatformDiscoveryDocument.Platform("platform.example", false, ""),
                new PlatformDiscoveryDocument.Signing(List.of("HS256"), "0"));
        List<String> invalidPaths = paths(AepValidation.platformDiscoveryDocument(invalid));
        for (String expected : List.of(
                "$.endpoints.hosted_verification",
                "$.endpoints.lifecycle",
                "$.endpoints.list",
                "$.endpoints.provision",
                "$.endpoints.sign",
                "$.http.endpoint_base",
                "$.identity.did_methods",
                "$.identity.did_url_template",
                "$.platform.did",
                "$.platform.name",
                "$.signing.algorithms",
                "$.signing.default_lifetime_seconds")) {
            assertTrue(invalidPaths.contains(expected), expected + " in " + invalidPaths);
        }
    }

    @Test
    void validatesPlatformIdentityMessages() {
        PlatformAgentIdentity identity = new PlatformAgentIdentity(
                "did:web:platform.example:agents:one",
                "pai_1",
                "2026-09-01T12:00:00Z",
                "https://platform.example/agents/one/did.json",
                "did:web:platform.example:agents:one",
                "did:web:service.example",
                List.of("ES256"),
                ManagedAgentStatus.ACTIVE,
                "2026-09-01T12:00:00Z");
        assertTrue(AepValidation.platformAgentIdentity(identity).isEmpty());
        assertSame(identity, AepValidation.requirePlatformAgentIdentity(identity));

        PlatformAgentIdentity broken = new PlatformAgentIdentity(
                "agent", "", "not-a-date", "http://platform.example/did.json", "", "service", List.of(), null, "");
        List<String> reported = paths(AepValidation.platformAgentIdentity(broken));
        for (String expected : List.of(
                "$.agent_did",
                "$.agent_identity_id",
                "$.created_at",
                "$.did_document_url",
                "$.key_id",
                "$.service_did",
                "$.signing_algorithms",
                "$.status",
                "$.updated_at")) {
            assertTrue(reported.contains(expected), expected + " in " + reported);
        }

        assertTrue(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse("1", List.of(identity), "4"))
                .isEmpty());
        assertTrue(paths(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse("2", List.of(identity), "4")))
                .contains("$.count"));
        assertTrue(paths(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse("1", List.of(identity), "0")))
                .contains("$.total"));
        assertTrue(paths(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse("-1", List.of(), "x")))
                .contains("$.count"));
        // The record copies an absent list to an empty one, so an absent data member surfaces as a
        // count that disagrees with the entries rather than as a missing array.
        assertTrue(paths(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse(null, null, null)))
                .contains("$.count"));
        assertTrue(paths(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse("1", List.of(broken), "1")))
                .contains("$.data[0].agent_did"));
    }

    @Test
    void validatesPlatformRequestsAndResponses() {
        assertTrue(AepValidation.platformProvisionRequest(new PlatformProvisionRequest("did:web:service.example"))
                .isEmpty());
        assertTrue(paths(AepValidation.platformProvisionRequest(new PlatformProvisionRequest("service.example")))
                .contains("$.service_did"));

        assertTrue(AepValidation.platformLifecycleRequest(new PlatformLifecycleRequest(ManagedAgentStatus.REVOKED))
                .isEmpty());
        assertTrue(paths(AepValidation.platformLifecycleRequest(new PlatformLifecycleRequest(null)))
                .contains("$.status"));

        assertTrue(AepValidation.platformSignRequest(new PlatformSignRequest(
                        "jti-1",
                        "60",
                        AssertionOperation.STATUS,
                        Map.of("tenant", "acme"),
                        null,
                        "did:web:service.example"))
                .isEmpty());
        List<String> signPaths = paths(AepValidation.platformSignRequest(
                new PlatformSignRequest("", "0", null, null, "https://api.example/x", "service.example")));
        for (String expected : List.of("$.jti", "$.lifetime_seconds", "$.op", "$.service_did")) {
            assertTrue(signPaths.contains(expected), expected + " in " + signPaths);
        }
        assertTrue(paths(AepValidation.platformSignRequest(new PlatformSignRequest(
                        "jti-1", null, AssertionOperation.AUTHENTICATE, null, null, "did:web:service.example")))
                .contains("$.resource"));

        assertTrue(AepValidation.platformVerificationRequest(new PlatformVerificationRequest(
                        "assertion", AssertionOperation.STATUS, null, "did:web:service.example"))
                .isEmpty());
        assertTrue(paths(AepValidation.platformVerificationRequest(
                        new PlatformVerificationRequest("", null, "https://api.example/x", "service.example")))
                .contains("$.client_assertion"));
    }

    @Test
    void validatesPlatformSignResponses() {
        PlatformSignResponses.Completed completed = new PlatformSignResponses.Completed(
                "completed",
                "did:web:platform.example:agents:one",
                "assertion",
                "2026-09-01T12:05:00Z",
                "2026-09-01T12:00:00Z",
                "jti-1",
                Map.of("tenant", "acme"),
                "did:web:service.example");
        assertTrue(AepValidation.platformSignResponse(completed).isEmpty());
        assertSame(completed, AepValidation.requirePlatformSignResponse(completed));
        assertEquals("completed", completed.status());
        assertEquals(Map.of("tenant", "acme"), completed.platformContext());

        List<String> reported = paths(AepValidation.platformSignResponse(new PlatformSignResponses.Completed(
                "pending", "agent", "", "not-a-date", "not-a-date", "", null, "service")));
        for (String expected : List.of(
                "$.status",
                "$.agent_did",
                "$.client_assertion",
                "$.expires_at",
                "$.issued_at",
                "$.jti",
                "$.service_did")) {
            assertTrue(reported.contains(expected), expected + " in " + reported);
        }

        PlatformSignResponses.Pending pending = new PlatformSignResponses.Pending("pending", null, "5");
        assertTrue(AepValidation.platformSignResponse(pending).isEmpty());
        assertNull(pending.platformContext());
        assertEquals("pending", pending.status());
        List<String> pendingPaths =
                paths(AepValidation.platformSignResponse(new PlatformSignResponses.Pending("done", null, "301")));
        assertTrue(pendingPaths.contains("$.status"), pendingPaths.toString());
        assertTrue(pendingPaths.contains("$.retry_after_seconds"), pendingPaths.toString());
        for (String retry : List.of("0", "+5", "05", "", "abc", "5.0")) {
            assertFalse(
                    AepValidation.platformSignResponse(new PlatformSignResponses.Pending("pending", null, retry))
                            .isEmpty(),
                    retry);
        }
    }

    @Test
    void validatesAuthorizationAndSecuritySchemeDocuments() {
        assertTrue(AepValidation.protectedResourceAuthorization(new ProtectedResourceAuthorization(
                        AuthorizationCarrier.STANDARD, AuthorizationScheme.AEP, "token"))
                .isEmpty());
        List<String> reported =
                paths(AepValidation.protectedResourceAuthorization(new ProtectedResourceAuthorization(null, null, "")));
        assertTrue(reported.contains("$.carrier"), reported.toString());
        assertTrue(reported.contains("$.scheme"), reported.toString());
        assertTrue(reported.contains("$.credentials"), reported.toString());

        assertTrue(AepValidation.openApiSecurityScheme(new OpenApiAepSecurityScheme("aep-jwt"))
                .isEmpty());
        assertTrue(paths(AepValidation.openApiSecurityScheme(new OpenApiAepSecurityScheme("Not A Method")))
                .contains("$.x-aep-authentication-method"));
        assertTrue(paths(AepValidation.openApiSecurityScheme(new OpenApiAepSecurityScheme(null)))
                .contains("$.x-aep-authentication-method"));
    }

    @Test
    void resolvesAndRejectsOpenApiReferences() {
        URI inspect = URI.create("https://api.example/.well-known/aep");
        assertEquals(
                URI.create("https://api.example/openapi.json"),
                AepOpenApi.resolveDocumentUri(inspect, "/openapi.json"));
        assertEquals(
                URI.create("https://docs.example/openapi.json"),
                AepOpenApi.resolveDocumentUri(inspect, "https://docs.example/openapi.json"));
        assertThrows(NullPointerException.class, () -> AepOpenApi.resolveDocumentUri(null, "/openapi.json"));
        for (String reference : List.of("", "  ")) {
            assertThrows(IllegalArgumentException.class, () -> AepOpenApi.resolveDocumentUri(inspect, reference));
        }
        assertThrows(IllegalArgumentException.class, () -> AepOpenApi.resolveDocumentUri(inspect, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(inspect, "http://docs.example/openapi.json"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(inspect, "https://user:pw@docs.example/openapi.json"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(inspect, "https://docs.example/openapi.json#section"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(URI.create("/relative"), "/openapi.json"));
        assertEquals(
                URI.create("http://localhost:8080/openapi.json"),
                AepOpenApi.resolveDocumentUri(
                        URI.create("http://localhost:8080/.well-known/aep"), "/openapi.json", true));
        assertEquals(
                URI.create("http://[::1]/openapi.json"),
                AepOpenApi.resolveDocumentUri(URI.create("http://[::1]/.well-known/aep"), "/openapi.json", true));
        assertEquals(
                URI.create("http://127.0.0.1/openapi.json"),
                AepOpenApi.resolveDocumentUri(URI.create("http://127.0.0.1/.well-known/aep"), "/openapi.json", true));
    }

    @Test
    void matchesOpenApiPathTemplates() {
        List<String> templates = List.of("/items", "/items/{id}", "/items/latest", "?bad", "/deep/{a}/{b}");
        assertEquals(
                "/items",
                AepOpenApi.matchPath(templates, "get", "/items", AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
        assertEquals(
                "GET",
                AepOpenApi.matchPath(templates, "get", "/items", AepOpenApi.TrailingSlashMode.STRICT)
                        .method());
        assertEquals(
                "/items/latest",
                AepOpenApi.matchPath(templates, "GET", "/items/latest", AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
        assertEquals(
                "/items/{id}",
                AepOpenApi.matchPath(templates, "GET", "/items/7", AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
        assertEquals(
                "/deep/{a}/{b}",
                AepOpenApi.matchPath(templates, "GET", "/deep/one/two?q=1", AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(templates, "GET", "/items/", AepOpenApi.TrailingSlashMode.STRICT));
        assertEquals(
                "/items",
                AepOpenApi.matchPath(templates, "GET", "/items/", AepOpenApi.TrailingSlashMode.EQUIVALENT)
                        .template());
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(templates, "GET", "/absent", AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(
                        List.of("/items/{id}", "/items/{name}"),
                        "GET",
                        "/items/7",
                        AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(templates, " ", "/items", AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(templates, null, "/items", AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(templates, "GET", "relative", AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(templates, "GET", " ", AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(
                NullPointerException.class,
                () -> AepOpenApi.matchPath(null, "GET", "/items", AepOpenApi.TrailingSlashMode.STRICT));
        assertThrows(NullPointerException.class, () -> AepOpenApi.matchPath(templates, "GET", "/items", null));
        // A template segment that is only braces is a literal, not a parameter.
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(List.of("/{}"), "GET", "/value", AepOpenApi.TrailingSlashMode.STRICT));
        // An empty request segment never satisfies a parameter.
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(
                        List.of("/items/{id}"), "GET", "/items//", AepOpenApi.TrailingSlashMode.STRICT));
    }

    @Test
    void resolvesDidWebDocumentsAndOrigins() {
        assertEquals(URI.create("https://example.com/.well-known/did.json"), DidWeb.documentUri("did:web:example.com"));
        assertEquals(
                URI.create("http://localhost:8080/.well-known/did.json"),
                DidWeb.documentUri("did:web:localhost%3A8080", true));
        assertEquals(
                URI.create("http://127.0.0.1/.well-known/did.json"), DidWeb.documentUri("did:web:127.0.0.1", true));
        assertEquals(
                URI.create("https://127.0.0.1/.well-known/did.json"), DidWeb.documentUri("did:web:127.0.0.1", false));
        for (String did : List.of("", "did:key:z6Mk", "did:web:", "web:example.com")) {
            assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri(did), did);
        }
        assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri(null));
        assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri("did:web:example.com:%ZZ"));

        assertTrue(DidWeb.bindsOrigin("did:web:example.com", URI.create("https://example.com/x")));
        assertTrue(DidWeb.bindsOrigin("did:web:EXAMPLE.com", URI.create("https://example.com:443/x")));
        assertTrue(DidWeb.bindsOrigin("did:web:example.com%3A8443", URI.create("https://example.com:8443/x")));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com", URI.create("https://other.example/x")));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com", URI.create("http://example.com/x")));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com%3A8443", URI.create("https://example.com/x")));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com", URI.create("/relative")));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com", null));
    }

    @Test
    void copiesAndRedactsTransportMessages() {
        byte[] body = "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Authorization", new ArrayList<>(List.of("AEP token")));
        AepHttpTransport.Request request = new AepHttpTransport.Request(
                "POST", URI.create("https://api.example/aep/enroll"), headers, body, Duration.ofSeconds(5));
        body[0] = 'X';
        assertEquals("payload", new String(request.body(), java.nio.charset.StandardCharsets.UTF_8));
        assertFalse(request.toString().contains("api.example"));
        assertFalse(request.toString().contains("AEP token"));
        assertTrue(request.toString().contains("bodyLength=7"));

        AepHttpTransport.Request empty =
                new AepHttpTransport.Request("GET", URI.create("https://api.example/"), null, null, null);
        assertEquals(0, empty.body().length);
        assertEquals(Map.of(), empty.headers());

        AepHttpTransport.Response response = new AepHttpTransport.Response(200, headers, null);
        assertEquals(0, response.body().length);
        assertFalse(response.toString().contains("AEP token"));
        assertTrue(response.toString().contains("status=200"));
        assertEquals(
                7,
                new AepHttpTransport.Response(200, null, "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                        .body()
                        .length);
    }

    @Test
    void redactsIssuedCredentialsFromDiagnostics() {
        assertFalse(new GrantResponses.OAuthBearer("secret", "credential-1", "2026-09-01T12:00:00Z", null, "Bearer")
                .toString()
                .contains("secret"));
        assertFalse(new GrantResponses.ApiKey("secret", "credential-1", "2026-09-01T12:00:00Z", "x-api-key", null)
                .toString()
                .contains("secret"));
        assertFalse(new GrantResponses.Basic("credential-1", "2026-09-01T12:00:00Z", "secret", null, null, "user")
                .toString()
                .contains("secret"));
    }

    @Test
    void evaluatesClaimSupport() {
        InspectDocument.Claims requested = new InspectDocument.Claims(
                List.of("contact.email", "person.birthdate"), List.of("person.first_name"), List.of("person.username"));
        ClaimSupport.Evaluation evaluation =
                ClaimSupport.evaluate(requested, List.of("contact.email", "person.first_name"));
        assertFalse(evaluation.canSatisfyRequired());
        assertEquals(List.of("person.birthdate"), evaluation.unsupportedRequired());
        assertEquals(List.of("person.first_name"), evaluation.supportedPreferred());
        assertEquals(List.of(), evaluation.supportedOptional());

        ClaimSupport.Evaluation none = ClaimSupport.evaluate(null, List.of("contact.email"));
        assertTrue(none.canSatisfyRequired());

        ClaimValues values =
                ClaimValues.builder().contactEmail("agent@example.com").build();
        assertEquals(
                List.of("person.birthdate"),
                ClaimSupport.missingRequired(List.of("contact.email", "person.birthdate"), values));
        assertEquals(List.of("contact.email"), ClaimSupport.missingRequired(List.of("contact.email"), null));
    }

    @Test
    void translatesRegisteredEnumValues() {
        assertEquals(AgentStatus.ACTIVE, AgentStatus.fromValue("active"));
        assertEquals("unavailable", AgentStatus.UNAVAILABLE.value());
        assertThrows(IllegalArgumentException.class, () -> AgentStatus.fromValue("archived"));
        assertEquals(ManagedAgentStatus.TERMINATED, ManagedAgentStatus.fromValue("terminated"));
        assertEquals("revoked", ManagedAgentStatus.REVOKED.value());
        assertThrows(IllegalArgumentException.class, () -> ManagedAgentStatus.fromValue("archived"));
        assertEquals(AssertionOperation.AUTHENTICATE, AssertionOperation.fromValue("authenticate"));
        assertEquals("revoke", AssertionOperation.REVOKE.value());
        assertThrows(IllegalArgumentException.class, () -> AssertionOperation.fromValue("inspect"));
        assertEquals("status", AepCommand.STATUS.value());
        assertEquals("inspect", AepCommand.INSPECT.value());
        assertEquals("Authorization", AuthorizationCarrier.STANDARD.value());
        assertEquals(Aep.AUTHORIZATION_HEADER, AuthorizationCarrier.DEDICATED.value());
        assertEquals("AEP", AuthorizationScheme.AEP.value());
    }

    @Test
    void buildsVerificationConfiguration() {
        Clock clock = Clock.fixed(Instant.parse("2026-09-01T12:00:00Z"), ZoneOffset.UTC);
        ClientAssertionVerification verification = ClientAssertionVerification.builder(
                        "did:web:service.example", "did:web:agent.example", AssertionOperation.AUTHENTICATE)
                .resource("https://api.example/x")
                .clock(clock)
                .clockSkew(Duration.ofSeconds(10))
                .allowInsecureLoopback(true)
                .build();
        assertEquals("did:web:service.example", verification.audience());
        assertEquals("did:web:agent.example", verification.issuer());
        assertEquals(AssertionOperation.AUTHENTICATE, verification.operation());
        assertEquals("https://api.example/x", verification.resource());
        assertSame(clock, verification.clock());
        assertEquals(Duration.ofSeconds(10), verification.clockSkew());
        assertTrue(verification.allowInsecureLoopback());

        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertionVerification.builder(null, "did:web:agent.example", AssertionOperation.STATUS)
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertionVerification.builder("did:web:service.example", null, AssertionOperation.STATUS)
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertionVerification.builder("did:web:service.example", "did:web:agent.example", null)
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertionVerification.builder(
                                "did:web:service.example", "did:web:agent.example", AssertionOperation.STATUS)
                        .clockSkew(Duration.ofSeconds(-1))
                        .build());
        assertThrows(
                NullPointerException.class,
                () -> ClientAssertionVerification.builder(
                                "did:web:service.example", "did:web:agent.example", AssertionOperation.STATUS)
                        .clock(null));
        assertThrows(
                NullPointerException.class,
                () -> ClientAssertionVerification.builder(
                                "did:web:service.example", "did:web:agent.example", AssertionOperation.STATUS)
                        .clockSkew(null));
    }
}
