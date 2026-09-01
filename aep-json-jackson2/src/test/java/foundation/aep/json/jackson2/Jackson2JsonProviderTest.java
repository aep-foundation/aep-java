package foundation.aep.json.jackson2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.AuthorizationScheme;
import java.util.List;
import org.junit.jupiter.api.Test;

final class Jackson2JsonProviderTest {
    @Test
    void parsesAndWritesInspectDocument() {
        String json = """
                {
                  "aep_version":"1.0",
                  "bindings":{"supported":["http"]},
                  "commands":{"supported":["inspect","enroll"],"future":true},
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
                "1.0",
                AepJson.parseInspectDocument(AepJson.write(AepJson.parseInspectDocument(json)))
                        .version());
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
}
