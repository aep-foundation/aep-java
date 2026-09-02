package foundation.aep.core;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class AepOpenApi {
    private AepOpenApi() {}

    public static URI resolveDocumentUri(URI finalInspectUri, String reference) {
        return resolveDocumentUri(finalInspectUri, reference, false);
    }

    public static URI resolveDocumentUri(URI finalInspectUri, String reference, boolean allowInsecureLoopback) {
        Objects.requireNonNull(finalInspectUri, "finalInspectUri");
        requireSafeUri(finalInspectUri, allowInsecureLoopback, "Final Inspect URI");
        if (reference == null || reference.isBlank()) {
            throw new IllegalArgumentException("OpenAPI reference must not be blank.");
        }
        URI resolved = finalInspectUri.resolve(reference);
        requireSafeUri(resolved, allowInsecureLoopback, "OpenAPI reference");
        if ("https".equalsIgnoreCase(finalInspectUri.getScheme()) && "http".equalsIgnoreCase(resolved.getScheme())) {
            throw new IllegalArgumentException("OpenAPI reference must not downgrade HTTPS.");
        }
        return resolved;
    }

    public static PathMatch matchPath(
            List<String> templates, String method, String requestPath, TrailingSlashMode trailingSlashMode) {
        Objects.requireNonNull(templates, "templates");
        Objects.requireNonNull(trailingSlashMode, "trailingSlashMode");
        if (method == null || method.isBlank()) {
            throw new IllegalArgumentException("HTTP method must not be blank.");
        }
        String path = requestPath(requestPath);
        List<Candidate> matches = new ArrayList<>();
        for (String template : templates) {
            Candidate candidate = match(template, path, trailingSlashMode);
            if (candidate != null) {
                matches.add(candidate);
            }
        }
        if (matches.isEmpty()) {
            throw new IllegalArgumentException("No OpenAPI path template matches the request path.");
        }
        matches.sort(Comparator.comparing(Candidate::specificity).reversed());
        Candidate selected = matches.get(0);
        if (matches.size() > 1 && selected.sameSpecificity(matches.get(1))) {
            throw new IllegalArgumentException("Multiple OpenAPI path templates match with equal specificity.");
        }
        return new PathMatch(method.toUpperCase(Locale.ROOT), selected.template());
    }

    private static Candidate match(String template, String path, TrailingSlashMode mode) {
        if (template == null || !template.startsWith("/") || template.indexOf('?') >= 0 || template.indexOf('#') >= 0) {
            return null;
        }
        String normalizedTemplate = normalizeSlash(template, mode);
        String normalizedPath = normalizeSlash(path, mode);
        String[] templateSegments = normalizedTemplate.split("/", -1);
        String[] pathSegments = normalizedPath.split("/", -1);
        if (templateSegments.length != pathSegments.length) {
            return null;
        }
        StringBuilder specificity = new StringBuilder(templateSegments.length);
        for (int index = 0; index < templateSegments.length; index++) {
            String expected = templateSegments[index];
            String actual = pathSegments[index];
            if (parameter(expected)) {
                if (actual.isEmpty()) return null;
                specificity.append('0');
            } else if (!expected.equals(actual)) {
                return null;
            } else {
                specificity.append('1');
            }
        }
        return new Candidate(template, specificity.toString());
    }

    private static String requestPath(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Request path must not be blank.");
        }
        URI reference = URI.create(value);
        String path = reference.getPath();
        if (path == null || !path.startsWith("/")) {
            throw new IllegalArgumentException("Request path must be absolute.");
        }
        return path;
    }

    private static String normalizeSlash(String value, TrailingSlashMode mode) {
        return mode == TrailingSlashMode.EQUIVALENT && value.length() > 1 && value.endsWith("/")
                ? value.substring(0, value.length() - 1)
                : value;
    }

    private static boolean parameter(String segment) {
        return segment.length() > 2 && segment.startsWith("{") && segment.endsWith("}");
    }

    private static void requireSafeUri(URI value, boolean allowInsecureLoopback, String name) {
        String host = value.getHost();
        boolean secure = "https".equalsIgnoreCase(value.getScheme());
        boolean loopback = allowInsecureLoopback
                && "http".equalsIgnoreCase(value.getScheme())
                && ("localhost".equals(host)
                        || "127.0.0.1".equals(host) // NOPMD - Explicit development opt-in permits loopback HTTP.
                        || "::1".equals(host) // NOPMD - Explicit development opt-in permits loopback HTTP.
                        || "[::1]".equals(host));
        if (host == null
                || (!secure && !loopback)
                || value.getRawUserInfo() != null
                || value.getRawFragment() != null) {
            throw new IllegalArgumentException(name + " must be a safe absolute URI.");
        }
    }

    public enum TrailingSlashMode {
        STRICT,
        EQUIVALENT
    }

    public record PathMatch(String method, String template) {}

    private record Candidate(String template, String specificity) {
        boolean sameSpecificity(Candidate other) {
            return specificity.equals(other.specificity);
        }
    }
}
