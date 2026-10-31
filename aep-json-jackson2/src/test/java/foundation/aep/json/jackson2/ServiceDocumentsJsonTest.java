package foundation.aep.json.jackson2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidationException;
import java.util.List;
import org.junit.jupiter.api.Test;

final class ServiceDocumentsJsonTest {
    private static final String PORTABLE = """
            {"format":"aep-service-document","version":"1.0","id":"terms",
             "content":[{"type":"paragraph","text":"Full terms"}],"future":true}
            """;

    @Test
    void retainsAbsentVersusEmptyAndRejectsMalformedAcknowledgements() {
        String request = "{\"agent_did\":\"did:example:agent\"";
        assertNull(AepJson.parseEnrollRequest(request + "}").acknowledgedDocumentIds());
        assertEquals(
                List.of(),
                AepJson.parseEnrollRequest(request + ",\"acknowledged_document_ids\":[]}")
                        .acknowledgedDocumentIds());
        var response = AepJson.parseEnrollResponse("{\"status\":\"active\",\"acknowledged_document_ids\":[]}");
        assertEquals(
                List.of(), AepJson.parseEnrollResponse(AepJson.write(response)).acknowledgedDocumentIds());
        for (String invalid : List.of("null", "42", "[42]", "\"terms\"", "[\"terms\",\"terms\"]")) {
            assertThrows(
                    AepValidationException.class,
                    () -> AepJson.parseEnrollRequest(request + ",\"acknowledged_document_ids\":" + invalid + "}"));
        }
    }

    @Test
    void requiresDocumentIdsInScopedRequirementErrorsAndPreservesThemOnWrite() {
        String problem = """
                {"type":"urn:aep:error:requirements_unmet","title":"Required","code":"requirements_unmet",
                 "status":422,"requirements_pending":["service_documents"],"required_document_ids":["terms"]}
                """;
        var parsed = AepJson.parseProblemDetails(problem);
        assertEquals(
                List.of("terms"),
                AepJson.parseProblemDetails(AepJson.write(parsed)).requiredDocumentIds());
        for (String invalid : List.of(
                problem.replace(",\"required_document_ids\":[\"terms\"]", ""),
                problem.replace("[\"terms\"]", "[]"),
                problem.replace("[\"terms\"]", "null"),
                problem.replace("requirements_unmet", "not_recognized"),
                problem.replace("422", "400"),
                problem.replace("[\"service_documents\"]", "[\"contact.email\"]"))) {
            assertThrows(AepValidationException.class, () -> AepJson.parseProblemDetails(invalid));
        }
    }

    @Test
    void validatesPortableContentWithoutCoercionOrPartialAcceptance() {
        assertEquals(
                "Full terms",
                AepJson.parsePortableServiceDocument(PORTABLE, "terms")
                        .content()
                        .get(0)
                        .text());
        for (String invalid : List.of(
                PORTABLE.replace("\"Full terms\"", "42"),
                PORTABLE.replace("\"paragraph\"", "\"table\""),
                PORTABLE.replace("\"future\":true", "\"summary\":null"),
                PORTABLE.replace("\"future\":true", "\"summary\":[]"),
                PORTABLE + "{}",
                " ".repeat(1048577))) {
            assertThrows(AepValidationException.class, () -> AepJson.parsePortableServiceDocument(invalid, "terms"));
        }
        assertThrows(AepValidationException.class, () -> AepJson.parsePortableServiceDocument(PORTABLE, "other"));
        String descriptor = """
                {"id":"terms","type":"custom_terms","title":"Terms","enrollment":"required",
                "representations":[{"media_type":"text/html","url":"https://example.com/terms"}],"future":true}
                """;
        assertEquals("custom_terms", AepJson.parseServiceDocument(descriptor).type());
        assertThrows(
                AepValidationException.class,
                () -> AepJson.parseServiceDocument(descriptor.replace("\"Terms\"", "42")));
        assertTrue(AepJson.write(AepJson.parseServiceDocument(descriptor)).contains("\"media_type\""));
    }
}
