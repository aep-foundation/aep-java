package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class PlatformProtocolTest {
    @Test
    void validatesThePlatformDiscoveryVector() {
        PlatformDiscoveryDocument document = discovery();

        assertTrue(AepValidation.platformDiscoveryDocument(document).isEmpty());
    }

    @Test
    void validatesPlatformRequestAndResponseVectors() {
        PlatformProvisionRequest provision = new PlatformProvisionRequest("did:web:api.service.example");
        PlatformSignRequest sign = new PlatformSignRequest(
                "assertion-1", null, AssertionOperation.ENROLL, null, null, "did:web:api.service.example");
        PlatformSignResponses.Response pending = new PlatformSignResponses.Pending("pending", null, "5");
        PlatformVerificationResponse unrecognized = new PlatformVerificationResponse(
                null, null, null, "not_recognized", "did:web:api.service.example", null, false);

        assertTrue(AepValidation.platformProvisionRequest(provision).isEmpty());
        assertTrue(AepValidation.platformSignRequest(sign).isEmpty());
        assertTrue(AepValidation.platformSignResponse(pending).isEmpty());
        assertTrue(AepValidation.platformVerificationResponse(unrecognized).isEmpty());
    }

    @Test
    void rejectsClosedRequestExtensionsAndInvalidResponseDisclosure() {
        PlatformVerificationResponse response = new PlatformVerificationResponse(
                "did:web:agent.example", null, null, "not_recognized", "did:web:service.example", null, false);
        assertEquals(1, AepValidation.platformVerificationResponse(response).size());
    }

    @Test
    void rejectsOperationResourceMismatchesAndInvalidNumericStrings() {
        PlatformSignRequest missingResource = new PlatformSignRequest(
                "assertion-1", "301", AssertionOperation.AUTHENTICATE, Map.of(), null, "did:web:service.example");

        assertEquals(2, AepValidation.platformSignRequest(missingResource).size());
        assertThrows(
                AepValidationException.class,
                () -> AepValidation.requirePlatformSignResponse(
                        new PlatformSignResponses.Pending("pending", null, "0")));
    }

    @Test
    void rejectsMalformedPlatformDiscoveryTemplatesWithoutThrowing() {
        PlatformDiscoveryDocument malformed = new PlatformDiscoveryDocument(
                "1.0",
                new PlatformDiscoveryDocument.Endpoints(
                        null,
                        "/v1/aep/agent-identities/fixed",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep"),
                new PlatformDiscoveryDocument.Identity(List.of("did:web"), null),
                new PlatformDiscoveryDocument.Platform(null, false, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));

        assertEquals(2, AepValidation.platformDiscoveryDocument(malformed).size());
    }

    @Test
    void validatesPlatformIdentityListPagination() {
        PlatformAgentIdentity identity = new PlatformAgentIdentity(
                "did:web:p.example:a:4Yf7p2xQd9",
                "pai_01J0AEPPLATFORM000000000001",
                "2026-07-06T12:00:00Z",
                "https://p.example/a/4Yf7p2xQd9/did.json",
                "did:web:p.example:a:4Yf7p2xQd9",
                "did:web:api.service.example",
                List.of("ES256"),
                ManagedAgentStatus.ACTIVE,
                "2026-07-06T12:00:00Z");

        assertTrue(AepValidation.platformAgentIdentityListResponse(
                        new PlatformAgentIdentityListResponse("1", List.of(identity), "999999999999999999999999"))
                .isEmpty());
        assertEquals(
                "$.count",
                AepValidation.platformAgentIdentityListResponse(
                                new PlatformAgentIdentityListResponse("0", List.of(identity), "1"))
                        .get(0)
                        .path());
        assertEquals(
                "$.total",
                AepValidation.platformAgentIdentityListResponse(
                                new PlatformAgentIdentityListResponse("1", List.of(identity), "0"))
                        .get(0)
                        .path());
    }

    private static PlatformDiscoveryDocument discovery() {
        return new PlatformDiscoveryDocument(
                "1.0",
                new PlatformDiscoveryDocument.Endpoints(
                        "/v1/aep/verifications",
                        "/v1/aep/agent-identities/{agent_identity_id}",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep"),
                new PlatformDiscoveryDocument.Identity(
                        List.of("did:web"), "https://p.example/agents/{agent_did_id}/did.json"),
                new PlatformDiscoveryDocument.Platform("did:web:p.example", true, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));
    }
}
