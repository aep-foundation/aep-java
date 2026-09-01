package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

final class AepValidationTest {
    @Test
    void validatesInspectDocument() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "enroll", "grant", "revoke", "status"),
                        List.of("api-key"),
                        java.util.Map.of("api-key", new InspectDocument.GrantTypeConfig("true"))))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();

        assertTrue(AepValidation.inspectDocument(document).isEmpty());
    }

    @Test
    void validatesClaimFormatsAndForwardCompatibleClaims() {
        ClaimValues values = ClaimValues.builder()
                .contactAddressPrimary(
                        new ContactAddressPrimary(null, "US", "Ada", "Lovelace", "1 Main Street", "", null, null, null))
                .contactEmail("\"quoted local\"@example.com")
                .contactMobile("+14155550123")
                .personBirthdate("1815-12-10")
                .additional("example.future", java.util.Map.of("value", true))
                .build();

        assertTrue(AepValidation.claimValues(values).isEmpty());
        assertEquals(java.util.Map.of("value", true), values.additional().get("example.future"));
    }

    @Test
    void rejectsInvalidClaimFormats() {
        ClaimValues values = ClaimValues.builder()
                .contactEmail("owner..name@example.com")
                .contactMobile("4155550123")
                .personBirthdate("2025-02-29")
                .build();

        List<String> paths = AepValidation.claimValues(values).stream()
                .map(ValidationIssue::path)
                .toList();
        assertEquals(List.of("$.contact.email", "$.contact.mobile", "$.person.birthdate"), paths);
    }

    @Test
    void recognizesCompatibleVersions() {
        assertTrue(AepValidation.isCompatibleVersion("1.99"));
        assertFalse(AepValidation.isCompatibleVersion("0.4"));
        assertFalse(AepValidation.isCompatibleVersion("00.1"));
    }

    @Test
    void evaluatesClaimSupportAndMissingValues() {
        InspectDocument.Claims requested = new InspectDocument.Claims(
                List.of("contact.email", "example.required"), List.of("person.first_name"), List.of("contact.mobile"));
        ClaimSupport.Evaluation evaluation =
                ClaimSupport.evaluate(requested, List.of("contact.email", "person.first_name"));

        assertFalse(evaluation.canSatisfyRequired());
        assertEquals(List.of("person.first_name"), evaluation.supportedPreferred());
        assertEquals(List.of("example.required"), evaluation.unsupportedRequired());
        assertEquals(
                List.of("contact.mobile"),
                ClaimSupport.missingRequired(
                        List.of("contact.email", "contact.mobile"),
                        ClaimValues.builder().contactEmail("a@b").build()));
    }

    @Test
    void rejectsMissingTypedDocuments() {
        assertFalse(AepValidation.inspectDocument(null).isEmpty());
        assertFalse(AepValidation.claimValues(null).isEmpty());
        assertFalse(AepValidation.enrollRequest(null).isEmpty());
        assertFalse(AepValidation.enrollResponse(null).isEmpty());
        assertFalse(AepValidation.statusResponse(null).isEmpty());
        assertFalse(AepValidation.grantRequest(null).isEmpty());
        assertFalse(AepValidation.revokeRequest(null).isEmpty());
        assertFalse(AepValidation.clientAssertionClaims(null).isEmpty());
        assertFalse(AepValidation.idempotencyMetadata(null).isEmpty());
        assertFalse(AepValidation.problemDetails(null).isEmpty());
        assertFalse(AepValidation.grantResponse(null).isEmpty());
        assertFalse(AepValidation.protectedResourceAuthorization(null).isEmpty());
        assertFalse(AepValidation.openApiSecurityScheme(null).isEmpty());
        assertThrows(AepValidationException.class, () -> AepValidation.requireInspectDocument(null));
        assertThrows(AepValidationException.class, () -> AepValidation.requireClaimValues(null));
    }

    @Test
    void validatesAddressRequirementsAndAdditionalValueCopies() {
        java.util.ArrayList<String> nested = new java.util.ArrayList<>(List.of("one"));
        ClaimValues copied =
                ClaimValues.builder().additional("example.values", nested).build();
        nested.add("two");

        assertEquals(List.of("one"), copied.additional().get("example.values"));
        List<?> copiedValues = (List<?>) copied.additional().get("example.values");
        assertThrows(UnsupportedOperationException.class, copiedValues::clear);

        ClaimValues invalid = ClaimValues.builder()
                .contactAddressPrimary(new ContactAddressPrimary(null, "USA", "", "", "", null, null, null, null))
                .build();
        List<String> paths = AepValidation.claimValues(invalid).stream()
                .map(ValidationIssue::path)
                .toList();
        assertTrue(paths.contains("$.contact.address.primary.country"));
        assertTrue(paths.contains("$.contact.address.primary.first_name"));
        assertTrue(paths.contains("$.contact.address.primary.last_name"));
        assertTrue(paths.contains("$.contact.address.primary.line1"));
    }

    @Test
    void parsesRegisteredEnumsWithoutPermissiveFallbacks() {
        for (AgentStatus status : AgentStatus.values()) {
            assertEquals(status, AgentStatus.fromValue(status.value()));
        }
        for (AepCommand command : AepCommand.values()) {
            assertFalse(command.value().isEmpty());
        }
        assertThrows(IllegalArgumentException.class, () -> AgentStatus.fromValue("future"));
    }
}
