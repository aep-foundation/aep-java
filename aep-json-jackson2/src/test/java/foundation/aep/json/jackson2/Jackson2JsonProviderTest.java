package foundation.aep.json.jackson2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.AuthorizationScheme;
import java.util.List;
import org.junit.jupiter.api.Test;

final class Jackson2JsonProviderTest {
    @Test
    void validatesNestedEnrollmentClaimsBeforeConversion() {
        for (String claims : List.of(
                "{\"person.first_name\":42}",
                "{\"person.first_name\":null}",
                "{\"contact.address.primary\":null}",
                "{\"contact.address.primary\":{\"first_name\":\"Ada\",\"last_name\":\"Lovelace\",\"line1\":\"1 Main Street\",\"country\":\"GB\",\"postal_code\":\"123\"}}",
                "{\"contact.address.primary\":{\"first_name\":\"Ada\",\"last_name\":\"Lovelace\",\"line1\":\"1 Main Street\",\"country\":\"GB\",\"line2\":null}}")) {
            String json = "{\"agent_did\":\"did:web:agent.example\",\"claims\":" + claims + "}";
            assertThrows(AepValidationException.class, () -> AepJson.parseEnrollRequest(json));
        }
        String json = """
                {"agent_did":"did:web:agent.example","claims":{"person.first_name":"Ada",
                "custom.claim":null,"contact.address.primary":{"first_name":"Ada","last_name":"Lovelace",
                "line1":"1 Main Street","country":"GB","line2":""}}}
                """;
        var claims = AepJson.parseEnrollRequest(json).claims();
        assertEquals("Ada", claims.personFirstName());
        assertEquals("", claims.contactAddressPrimary().line2());
        assertTrue(claims.additional().containsKey("custom.claim"));
        assertNull(claims.additional().get("custom.claim"));
    }

    @Test
    void rejectsCoercionAndTrailingJson() {
        String valid = """
                {"jti":"request-1","op":"status","service_did":"did:web:service.example","lifetime_seconds":"60"}
                """;
        assertEquals("60", AepJson.parsePlatformSignRequest(valid).lifetimeSeconds());
        for (String value : List.of("60", "60.0", "true")) {
            assertThrows(
                    AepValidationException.class,
                    () -> AepJson.parsePlatformSignRequest(valid.replace("\"60\"", value)));
        }
        for (String suffix : List.of(" garbage", " {}", " null")) {
            assertThrows(AepValidationException.class, () -> AepJson.parsePlatformSignRequest(valid + suffix));
        }
        assertEquals("60", AepJson.parsePlatformSignRequest(valid + " \n\t").lifetimeSeconds());
    }

    @Test
    void parsesAndWritesInspectDocument() {
        String json = """
                {
                  "aep_version":"1.0",
                  "authentication":{"methods":["api-key"]},
                  "bindings":{"supported":["http"]},
                  "commands":{"supported":["inspect","enroll","grant","revoke","status"],
                    "grant_types":["api-key"],
                    "grant_types_config":{"api-key":{"header_names":["x-service-key"],
                      "supports_per_credential_revoke":"true"}},"future":true},
                  "core":{"signing_algorithms":["EdDSA","ES256"]},
                  "http":{"endpoint_base":"/aep"},
                  "identity":{"methods":["did:web"]},
                  "service":{"did":"did:web:service.example"},
                  "future":{"value":true}
                }
                """;

        assertEquals(
                "did:web:service.example",
                AepJson.parseInspectDocument(json).service().did());
        assertEquals(
                List.of("x-service-key"),
                AepJson.parseInspectDocument(json)
                        .commands()
                        .grantTypesConfig()
                        .get("api-key")
                        .headerNames());
        assertEquals(
                "1.0",
                AepJson.parseInspectDocument(AepJson.write(AepJson.parseInspectDocument(json)))
                        .version());
    }

    @Test
    void validatesOpenApiObjectsAndUriReferencesWithoutRejectingTopLevelExtensions() {
        String template = """
                {"aep_version":"1.0","bindings":{"supported":["http"]},
                 "commands":{"supported":["inspect"]},"core":{"signing_algorithms":["EdDSA","ES256"]},
                 "http":{"endpoint_base":"/aep","openapi":%s},
                 "identity":{"methods":["did:web"]},"service":{"did":"did:web:service.example"},
                 "example.extension":{"enabled":true}}
                """;
        String valid = """
                {"url":"/openapi.json","path_matching":{"trailing_slash":"strict"}}
                """;
        assertEquals(
                "strict",
                AepJson.parseInspectDocument(template.formatted(valid))
                        .http()
                        .openapi()
                        .pathMatching()
                        .trailingSlash());
        String document = template.formatted(valid);
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseInspectDocument(document.replace("/aep", "/bad path")));
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseInspectDocument(document.replace(
                        "\"example.extension\":",
                        "\"extensions\":{\"supported\":[\"not a URI\"]},\"example.extension\":")));
        for (String openapi : List.of(
                "{\"url\":null,\"path_matching\":{\"trailing_slash\":\"strict\"}}",
                "{\"url\":\"/openapi.json\",\"future\":true,\"path_matching\":{\"trailing_slash\":\"strict\"}}",
                "{\"url\":\"/openapi.json\",\"path_matching\":{\"trailing_slash\":null}}",
                "{\"url\":\"/openapi.json\",\"path_matching\":{\"trailing_slash\":\"strict\",\"future\":true}}")) {
            assertThrows(
                    AepValidationException.class,
                    () -> AepJson.parseInspectDocument(template.formatted(openapi)),
                    openapi);
        }
    }

    @Test
    void appliesGrantResponseNullability() {
        String valid = """
                {"api_key":"secret","credential_id":"credential-1","expires_at":"2026-09-01T12:00:00Z","header":"X-Key","scopes":null}
                """;

        assertEquals(List.of(), AepJson.parseApiKeyGrantResponse(valid).scopes());
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseApiKeyGrantResponse(
                        "{\"api_key\":\"secret\",\"expires_at\":\"2026-09-01T12:00:00Z\",\"header\":\"X-Key\"}"));
    }

    @Test
    void validatesClaimsBeforeReturningTypedValues() {
        assertEquals(
                "\"quoted local\"@example.com",
                AepJson.parseClaimValues("{\"contact.email\":\"\\\"quoted local\\\"@example.com\"}")
                        .contactEmail());
        assertEquals(
                null,
                AepJson.parseClaimValues("{\"example.nullable\":null}")
                        .additional()
                        .get("example.nullable"));
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseClaimValues(
                        "{\"contact.address.primary\":{\"country\":\"US\",\"first_name\":\"Ada\",\"last_name\":\"Lovelace\",\"line1\":\"1 Main\",\"postal_code\":\"94105\"}}"));
        assertThrows(AepValidationException.class, () -> AepJson.parseClaimValues("{\"person.first_name\":42}"));
    }

    @Test
    void parsesWireAuthorizationValues() {
        var authorization = AepJson.parseProtectedResourceAuthorization(
                "{\"carrier\":\"AEP-Authorization\",\"scheme\":\"AEP\",\"credentials\":\"assertion\"}");

        assertEquals(AuthorizationCarrier.DEDICATED, authorization.carrier());
        assertEquals(AuthorizationScheme.AEP, authorization.scheme());
        assertEquals(
                "false",
                AepJson.parseEnrollResponse("{\"status\":\"active\",\"owner_action_required\":\"false\"}")
                        .ownerActionRequired());
        assertEquals(
                "{\"status\":\"active\"}",
                AepJson.write(new foundation.aep.core.EnrollResponse(
                        foundation.aep.core.AgentStatus.ACTIVE, "false", List.of(), List.of())));
        assertEquals(
                "{\"type\":\"urn:aep:error:invalid_request\",\"title\":\"Invalid request\",\"status\":400,\"code\":\"invalid_request\"}",
                AepJson.write(foundation.aep.core.ProblemDetails.of("invalid_request", "Invalid request", 400)));
    }

    @Test
    void rejectsNumericPlatformPaginationFields() {
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parsePlatformAgentIdentityListResponse("{\"count\":0,\"data\":[],\"total\":\"0\"}"));
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parsePlatformAgentIdentityListResponse("{\"count\":\"0\",\"data\":[],\"total\":0}"));
    }

    @Test
    void parsesEveryCoreWireDocument() {
        assertEquals(
                "did:web:agent.example",
                AepJson.parseEnrollRequest("{\"agent_did\":\"did:web:agent.example\"}")
                        .agentDid());
        assertEquals(
                "2026-09-01T12:00:00Z",
                AepJson.parseStatusResponse("{\"status\":\"active\",\"since\":\"2026-09-01T12:00:00Z\"}")
                        .since());
        assertEquals(
                "api-key",
                AepJson.parseGrantRequest("{\"grant_type\":\"api-key\",\"requested_scopes\":[]}")
                        .grantType());
        assertEquals(
                "jwt",
                AepJson.parseGrantRequest(
                                "{\"grant_type\":\"oauth-bearer\",\"label\":\"prod\",\"token_format\":\"jwt\"}")
                        .tokenFormat());
        assertEquals(
                "true",
                AepJson.parseRevokeRequest("{\"all_grant_types\":\"true\"}").allGrantTypes());
        assertEquals(new foundation.aep.core.RevokeResponse(), AepJson.parseRevokeResponse("{}"));
        assertEquals(
                foundation.aep.core.AssertionOperation.ENROLL,
                AepJson.parseClientAssertionClaims(
                                "{\"iss\":\"did:web:agent.example\",\"sub\":\"did:web:agent.example\",\"aud\":\"did:web:service.example\",\"op\":\"enroll\",\"iat\":1788264000,\"exp\":1788264300,\"jti\":\"assertion-1\"}")
                        .operation());
        assertEquals(
                "request-1",
                AepJson.parseIdempotencyMetadata("{\"idempotency_key\":\"request-1\"}")
                        .idempotencyKey());
        assertEquals(
                "invalid_request",
                AepJson.parseProblemDetails(
                                "{\"type\":\"urn:aep:error:invalid_request\",\"title\":\"Invalid request\",\"status\":400,\"code\":\"invalid_request\"}")
                        .code());
        assertEquals(
                "Bearer",
                AepJson.parseOAuthBearerGrantResponse(
                                "{\"access_token\":\"token\",\"credential_id\":\"credential-1\",\"expires_at\":\"2026-09-01T12:00:00Z\",\"token_type\":\"Bearer\"}")
                        .tokenType());
        assertEquals(
                "jwt",
                AepJson.parseOAuthBearerGrantResponse(
                                "{\"access_token\":\"token\",\"credential_id\":\"credential-1\",\"expires_at\":\"2026-09-01T12:00:00Z\",\"token_format\":\"jwt\",\"token_type\":\"Bearer\"}")
                        .tokenFormat());
        assertEquals(
                "credential-1",
                AepJson.parseBuiltInGrantResponse(
                                foundation.aep.core.Aep.GRANT_TYPE_OAUTH_BEARER,
                                "{\"access_token\":\"token\",\"credential_id\":\"credential-1\",\"expires_at\":\"2026-09-01T12:00:00Z\",\"token_type\":\"Bearer\"}")
                        .credentialId());
        assertEquals(
                "agent",
                AepJson.parseBasicGrantResponse(
                                "{\"credential_id\":\"credential-1\",\"expires_at\":\"2026-09-01T12:00:00Z\",\"password\":\"secret\",\"username\":\"agent\"}")
                        .username());
        assertThrows(IllegalArgumentException.class, () -> AepJson.parseBuiltInGrantResponse("future", "{}"));
        assertEquals(
                "api-key",
                AepJson.parseOpenApiSecurityScheme("{\"x-aep-authentication-method\":\"api-key\"}")
                        .authenticationMethod());
    }

    @Test
    void rejectsMalformedAndClosedWireDocuments() {
        assertThrows(AepValidationException.class, () -> AepJson.parseInspectDocument("[]"));
        assertThrows(AepValidationException.class, () -> AepJson.parseInspectDocument("{\"aep_version\":null}"));
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseInspectDocument(
                        "{\"aep_version\":\"1.0\",\"authentication\":{\"methods\":[\"api-key\"],\"future\":true},\"bindings\":{\"supported\":[\"http\"]},\"commands\":{\"supported\":[\"inspect\"]},\"core\":{\"signing_algorithms\":[\"EdDSA\",\"ES256\"]},\"http\":{},\"identity\":{\"methods\":[]},\"service\":{\"did\":\"did:web:service.example\"}}"));
        assertThrows(AepValidationException.class, () -> AepJson.parseRevokeResponse("{\"future\":true}"));
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseProtectedResourceAuthorization(
                        "{\"carrier\":\"Authorization\",\"scheme\":\"Bearer\",\"credentials\":\"token\",\"future\":true}"));
    }

    @Test
    void parsesPlatformWireDocuments() {
        assertEquals(
                "Example Platform",
                AepJson.parsePlatformDiscoveryDocument(
                                "{\"aep_version\":\"1.0\",\"endpoints\":{\"lifecycle\":\"/v1/aep/agent-identities/{agent_identity_id}\",\"list\":\"/v1/aep/agent-identities\",\"provision\":\"/v1/aep/agent-identities\",\"sign\":\"/v1/aep/agent-identities/{agent_identity_id}/sign\"},\"http\":{\"endpoint_base\":\"/v1/aep\"},\"identity\":{\"did_methods\":[\"did:web\"],\"did_url_template\":\"https://p.example/a/{agent_did_id}/did.json\"},\"platform\":{\"hosted_verification\":false,\"name\":\"Example Platform\"},\"signing\":{\"algorithms\":[\"ES256\"],\"default_lifetime_seconds\":\"300\"}}")
                        .platform()
                        .name());
        assertEquals(
                foundation.aep.core.AssertionOperation.ENROLL,
                AepJson.parsePlatformSignRequest(
                                "{\"jti\":\"assertion-1\",\"op\":\"enroll\",\"service_did\":\"did:web:service.example\"}")
                        .operation());
        assertEquals(
                "5",
                ((foundation.aep.core.PlatformSignResponses.Pending) AepJson.parsePlatformSignResponse(
                                "{\"status\":\"pending\",\"retry_after_seconds\":\"5\"}"))
                        .retryAfterSeconds());
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parsePlatformProvisionRequest(
                        "{\"service_did\":\"did:web:service.example\",\"extra\":true}"));
    }

    @Test
    void parsesProvisioningAndLifecycleWithoutAcceptingUnknownMembers() {
        assertEquals(
                "did:web:service.example",
                AepJson.parsePlatformProvisionRequest("{\"service_did\":\"did:web:service.example\"}")
                        .serviceDid());
        for (String status : List.of("active", "revoked", "suspended", "terminated")) {
            assertEquals(
                    status,
                    AepJson.parsePlatformLifecycleRequest("{\"status\":\"" + status + "\"}")
                            .status()
                            .value());
        }
        for (String json : List.of(
                "{}", "{\"status\":null}", "{\"status\":\"pending\"}", "{\"status\":\"active\",\"extra\":true}")) {
            assertThrows(AepValidationException.class, () -> AepJson.parsePlatformLifecycleRequest(json), json);
        }
        assertThrows(AepValidationException.class, () -> AepJson.parsePlatformSignResponse("{\"status\":\"unknown\"}"));
    }

    @Test
    void serializesStatusWithoutEmptyLifecycleMetadata() {
        var status = new foundation.aep.core.StatusResponse(
                foundation.aep.core.AgentStatus.ACTIVE, "false", List.of(), List.of(), null);
        assertEquals("{\"status\":\"active\"}", AepJson.write(status));
        var pending = new foundation.aep.core.StatusResponse(
                foundation.aep.core.AgentStatus.PENDING,
                "true",
                List.of("contact.email"),
                List.of("contact.mobile"),
                null);
        assertEquals(pending, AepJson.parseStatusResponse(AepJson.write(pending)));
        AepJson.requireObject("{}", "example");
        assertThrows(AepValidationException.class, () -> AepJson.requireObject("[]", "example"));
    }

    @Test
    void rejectsAddressTypeCoercion() {
        for (String address : List.of(
                "42",
                "[]",
                "\"address\"",
                "{\"country\":\"US\",\"first_name\":\"Ada\",\"last_name\":\"Lovelace\",\"line1\":42}")) {
            assertThrows(
                    AepValidationException.class,
                    () -> AepJson.parseClaimValues("{\"contact.address.primary\":" + address + "}"),
                    address);
        }
    }
}
