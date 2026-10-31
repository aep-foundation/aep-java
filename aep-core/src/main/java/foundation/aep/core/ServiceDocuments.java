package foundation.aep.core;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public final class ServiceDocuments {
    public static final String EXTENSION = "urn:aep:ext:aep-foundation:service-documents#v=1.0.0";
    public static final int MAX_BYTES = 1 << 20;
    private static final int MAX_DOCUMENTS = 7;
    private static final int MAX_BLOCKS = 1024;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,31}");
    private static final Pattern TYPE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern MEDIA = Pattern.compile("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+");

    private ServiceDocuments() {}

    public static List<String> preferredTypes() {
        return List.of(
                "acceptable_use_policy",
                "age_or_parental_consent",
                "ai_data_use_policy",
                "community_guidelines",
                "cookie_policy",
                "data_processing_agreement",
                "data_retention_notice",
                "electronic_signature_consent",
                "privacy_policy",
                "security_policy",
                "subscription_terms",
                "supplemental_terms",
                "terms_of_service");
    }

    public static List<ValidationIssue> identifiers(List<String> ids) {
        List<ValidationIssue> issues = new ArrayList<>();
        if (ids == null) return issues;
        if (ids.size() > MAX_DOCUMENTS) issues.add(issue("$", "At most seven document identifiers are allowed."));
        Set<String> seen = new HashSet<>();
        for (String id : ids) {
            if (!matches(ID, id) || !seen.add(id))
                issues.add(issue("$", "Expected unique valid document identifiers."));
        }
        return issues;
    }

    public static List<ValidationIssue> catalog(List<ServiceDocument> documents) {
        List<ValidationIssue> issues = new ArrayList<>();
        if (documents == null) return issues;
        if (documents.isEmpty() || documents.size() > MAX_DOCUMENTS)
            issues.add(issue("$", "Expected one through seven documents."));
        List<String> ids = new ArrayList<>();
        for (ServiceDocument document : documents) {
            issues.addAll(descriptor(document));
            if (document != null) ids.add(document.id());
        }
        issues.addAll(identifiers(ids));
        return issues;
    }

    public static List<ValidationIssue> descriptor(ServiceDocument document) {
        List<ValidationIssue> issues = new ArrayList<>();
        if (document == null) return List.of(issue("$", "Expected a document descriptor."));
        if (!matches(ID, document.id())) issues.add(issue("$.id", "Invalid document identifier."));
        if (!matches(TYPE, document.type())) issues.add(issue("$.type", "Invalid document type."));
        if (!text(document.title(), 256)) issues.add(issue("$.title", "Invalid document title."));
        if (!"required".equals(document.enrollment()) && !"not-required".equals(document.enrollment())) {
            issues.add(issue("$.enrollment", "Expected required or not-required."));
        }
        if (document.representations() == null
                || document.representations().isEmpty()
                || document.representations().size() > 8) {
            issues.add(issue("$.representations", "Expected one through eight representations."));
            return issues;
        }
        Set<String> media = new HashSet<>();
        for (ServiceDocument.Representation representation : document.representations()) {
            if (representation == null
                    || !matches(MEDIA, representation.mediaType())
                    || !media.add(representation.mediaType())
                    || !validUrl(representation.url())) {
                issues.add(issue(
                        "$.representations", "Expected unique lowercase media types and HTTPS or loopback HTTP URLs."));
            }
        }
        if (!media.contains("text/html")) issues.add(issue("$.representations", "An HTML representation is required."));
        return issues;
    }

    public static boolean validUrl(String value) {
        if (value == null
                || value.length() > 2048
                || value.chars().anyMatch(character -> character <= 32 || character > 127)) {
            return false;
        }
        try {
            URI uri = URI.create(value);
            return uri.getHost() != null
                    && ("https".equals(uri.getScheme())
                            || "http".equals(uri.getScheme()) && AepValidation.isLoopbackHost(uri.getHost()))
                    && uri.getUserInfo() == null;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    public static List<ValidationIssue> portable(PortableServiceDocument document, String expectedId) {
        List<ValidationIssue> issues = new ArrayList<>();
        if (document == null) return List.of(issue("$", "Expected a portable document."));
        if (!"aep-service-document".equals(document.format()) || !"1.0".equals(document.version())) {
            issues.add(issue("$", "Unsupported portable document format or version."));
        }
        if (!matches(ID, document.id()) || !document.id().equals(expectedId)) {
            issues.add(issue("$.id", "Document identifier must match its descriptor."));
        }
        if (document.content() == null
                || document.content().isEmpty()
                || document.summary() != null && document.summary().isEmpty()) {
            issues.add(issue("$", "Full content and any supplied summary must be nonempty."));
        }
        int count = blocks(document.summary(), 0, 0, issues);
        blocks(document.content(), 0, count, issues);
        return issues;
    }

    private static int blocks(
            List<PortableServiceDocument.Block> blocks, int depth, int previous, List<ValidationIssue> issues) {
        int count = previous;
        if (blocks == null) return count;
        for (PortableServiceDocument.Block block : blocks) {
            count++;
            if (count > MAX_BLOCKS) {
                issues.add(issue("$", "Document exceeds 1024 blocks."));
                return count;
            }
            if (block == null || block.type() == null) {
                issues.add(issue("$", "Expected a typed content block."));
                continue;
            }
            switch (block.type()) {
                case "paragraph" -> {
                    if (!text(block.text(), 16384)) issues.add(issue("$.text", "Invalid paragraph text."));
                }
                case "section" -> {
                    if (depth >= 8
                            || !text(block.title(), 256)
                            || block.blocks() == null
                            || block.blocks().isEmpty()) {
                        issues.add(issue("$.blocks", "Invalid section or section depth."));
                    } else count = blocks(block.blocks(), depth + 1, count, issues);
                }
                case "numbered_list", "bulleted_list" -> {
                    if (block.items() == null
                            || block.items().isEmpty()
                            || block.items().size() > 128
                            || block.items().stream().anyMatch(item -> !text(item, 16384))) {
                        issues.add(issue("$.items", "Invalid list items."));
                    }
                }
                default -> issues.add(issue("$.type", "Unsupported content block."));
            }
        }
        return count;
    }

    private static boolean text(String value, int maximum) {
        return value != null
                && !value.isEmpty()
                && value.codePointCount(0, value.length()) <= maximum
                && value.codePoints().noneMatch(character -> character >= 0xd800 && character <= 0xdfff);
    }

    private static boolean matches(Pattern pattern, String value) {
        return value != null && pattern.matcher(value).matches();
    }

    private static ValidationIssue issue(String path, String message) {
        return new ValidationIssue(path, message);
    }
}
