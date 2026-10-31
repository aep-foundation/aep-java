package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

final class ServiceDocumentsTest {
    private static ServiceDocument descriptor(String id) {
        return new ServiceDocument(
                id,
                "custom_terms",
                "Terms",
                "required",
                List.of(new ServiceDocument.Representation("text/html", "https://example.com/terms")));
    }

    private static PortableServiceDocument.Block paragraph(String text) {
        return new PortableServiceDocument.Block("paragraph", text, null, null, null);
    }

    private static PortableServiceDocument portable(List<PortableServiceDocument.Block> content) {
        return new PortableServiceDocument("aep-service-document", "1.0", "terms", null, content);
    }

    @Test
    void validatesBoundedCaseSensitiveIdsAndOpenTypes() {
        assertTrue(ServiceDocuments.identifiers(null).isEmpty());
        assertTrue(ServiceDocuments.identifiers(List.of()).isEmpty());
        assertTrue(ServiceDocuments.identifiers(List.of("Terms", "terms", "a".repeat(32)))
                .isEmpty());
        for (List<String> ids : List.of(
                List.of(""),
                List.of("a".repeat(33)),
                List.of("é"),
                List.of("a\n"),
                List.of("a", "a"),
                IntStream.range(0, 8).mapToObj(Integer::toString).toList())) {
            assertFalse(ServiceDocuments.identifiers(ids).isEmpty(), ids.toString());
        }
        assertTrue(ServiceDocuments.catalog(IntStream.range(0, 7)
                        .mapToObj(i -> descriptor("id-" + i))
                        .toList())
                .isEmpty());
        assertFalse(ServiceDocuments.catalog(IntStream.range(0, 8)
                        .mapToObj(i -> descriptor("id-" + i))
                        .toList())
                .isEmpty());
        assertFalse(ServiceDocuments.catalog(List.of()).isEmpty());
        assertFalse(ServiceDocuments.catalog(List.of(descriptor("terms"), descriptor("terms")))
                .isEmpty());
        assertTrue(ServiceDocuments.catalog(null).isEmpty());
        assertFalse(ServiceDocuments.descriptor(null).isEmpty());
        assertEquals(ServiceDocuments.preferredTypes().stream().sorted().toList(), ServiceDocuments.preferredTypes());
    }

    @Test
    void rejectsUnsafeUrlsAndInvalidDescriptors() {
        for (String url : List.of(
                "http://example.com",
                "http://localhost.example.com",
                "http://192.168.1.10",
                "http://user@localhost",
                "https://user@example.com",
                "/relative",
                "https://example.com/é",
                "https://example.com/a b",
                "https://example.com\\@localhost/",
                "https://example.com/" + "x".repeat(2048))) {
            assertFalse(ServiceDocuments.validUrl(url), url);
        }
        assertFalse(ServiceDocuments.validUrl(null));
        for (String url : List.of(
                "http://localhost:8080/terms",
                "http://127.0.0.1/terms",
                "http://[::1]/terms",
                "https://192.168.1.10/terms")) {
            assertTrue(ServiceDocuments.validUrl(url), url);
        }
        assertTrue(ServiceDocuments.validUrl("https://example.com/" + "x".repeat(2028)));
        ServiceDocument original = descriptor("terms");
        for (ServiceDocument value : List.of(
                new ServiceDocument("bad id", "custom_terms", "Terms", "required", original.representations()),
                new ServiceDocument("terms", "bad-type", "Terms", "required", original.representations()),
                new ServiceDocument("terms", "custom_terms", "x".repeat(257), "required", original.representations()),
                new ServiceDocument("terms", "custom_terms", "Terms", "optional", original.representations()),
                new ServiceDocument("terms", "custom_terms", "Terms", "required", List.of()),
                new ServiceDocument("terms", "custom_terms", "Terms", "required", null),
                new ServiceDocument(
                        "terms",
                        "custom_terms",
                        "Terms",
                        "required",
                        List.of(
                                original.representations().get(0),
                                original.representations().get(0))),
                new ServiceDocument(
                        "terms",
                        "custom_terms",
                        "Terms",
                        "required",
                        List.of(new ServiceDocument.Representation(
                                "application/json", "https://example.com/legal"))))) {
            assertFalse(ServiceDocuments.descriptor(value).isEmpty());
        }
        assertTrue(ServiceDocuments.descriptor(new ServiceDocument(
                        "terms", "custom_terms", "😀".repeat(256), "not-required", original.representations()))
                .isEmpty());
    }

    @Test
    void enforcesPortableStructureAndBoundariesAcrossSummaryAndContent() {
        var text = paragraph("Full terms");
        assertTrue(ServiceDocuments.portable(portable(List.of(text)), "terms").isEmpty());
        assertFalse(ServiceDocuments.portable(portable(List.of(text)), "other").isEmpty());
        assertFalse(ServiceDocuments.portable(null, "terms").isEmpty());
        assertFalse(ServiceDocuments.portable(portable(null), "terms").isEmpty());
        assertFalse(ServiceDocuments.portable(portable(List.of()), "terms").isEmpty());
        for (String value : List.of("", "x".repeat(16385), "\ud800")) {
            assertFalse(ServiceDocuments.portable(portable(List.of(paragraph(value))), "terms")
                    .isEmpty());
        }
        assertTrue(ServiceDocuments.portable(portable(List.of(paragraph("x".repeat(16384)))), "terms")
                .isEmpty());
        List<PortableServiceDocument.Block> blocks = new ArrayList<>();
        for (int index = 0; index < 1024; index++) blocks.add(text);
        assertTrue(ServiceDocuments.portable(portable(blocks), "terms").isEmpty());
        assertFalse(ServiceDocuments.portable(
                        new PortableServiceDocument("aep-service-document", "1.0", "terms", List.of(text), blocks),
                        "terms")
                .isEmpty());
        List<PortableServiceDocument.Block> nested = List.of(text);
        for (int depth = 1; depth <= 9; depth++) {
            nested = List.of(new PortableServiceDocument.Block("section", null, "Section", nested, null));
            assertEquals(
                    depth <= 8,
                    ServiceDocuments.portable(portable(nested), "terms").isEmpty());
        }
        for (String type : List.of("numbered_list", "bulleted_list")) {
            for (int size : List.of(0, 128, 129)) {
                var block = new PortableServiceDocument.Block(
                        type, null, null, null, java.util.Collections.nCopies(size, "Item"));
                assertEquals(
                        size == 128,
                        ServiceDocuments.portable(portable(List.of(block)), "terms")
                                .isEmpty());
            }
        }
        assertFalse(ServiceDocuments.portable(
                        portable(List.of(new PortableServiceDocument.Block("table", null, null, null, null))), "terms")
                .isEmpty());
        assertFalse(ServiceDocuments.portable(
                        new PortableServiceDocument("aep-service-document", "2.0", "terms", null, List.of(text)),
                        "terms")
                .isEmpty());
    }
}
