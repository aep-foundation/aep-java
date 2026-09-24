package foundation.aep.core;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class AepOpenApi {
    private static final int SINGLE = 1;

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

    /**
     * Resolves the effective security for one operation (CORE-OAS-011/013/014/015).
     *
     * <p>Operation-level security replaces the root value rather than adding to it, an empty list
     * makes the operation public, an empty requirement object is an anonymous alternative, several
     * requirement objects are alternatives, and several schemes inside one object are compound. An
     * Agent that cannot satisfy every member of a compound requirement treats that requirement as
     * unsupported, and never reduces it to the members it happens to support: the returned
     * alternatives are always whole requirement objects.
     *
     * @param rootSecurity the document-level {@code security} value, or {@code null} when absent
     * @param operationSecurity the operation's own {@code security} value, or {@code null} when the
     *     operation omits the member and therefore inherits the root value
     * @param supportedSchemes the security-scheme names this Agent is able to satisfy
     */
    public static SecurityResolution resolveSecurity(
            List<Map<String, List<String>>> rootSecurity,
            List<Map<String, List<String>>> operationSecurity,
            Collection<String> supportedSchemes) {
        Set<String> supported = supportedSchemes == null ? Set.of() : new LinkedHashSet<>(supportedSchemes);
        List<Map<String, List<String>>> effective = effectiveSecurity(rootSecurity, operationSecurity);
        if (effective.isEmpty()) {
            return new SecurityResolution(SecurityDisposition.PUBLIC, List.of());
        }
        List<List<String>> requirements = new ArrayList<>(effective.size());
        for (Map<String, List<String>> requirement : effective) {
            if (requirement == null) {
                throw new IllegalArgumentException("An OpenAPI security requirement must not be null.");
            }
            requirements.add(List.copyOf(requirement.keySet()));
        }
        if (requirements.stream().anyMatch(List::isEmpty)) {
            return new SecurityResolution(SecurityDisposition.OPTIONAL_ANONYMOUS, List.of());
        }
        List<List<String>> satisfiable =
                requirements.stream().filter(supported::containsAll).toList();
        if (satisfiable.isEmpty()) {
            return new SecurityResolution(SecurityDisposition.FALLBACK_LIVE_CHALLENGE, List.of());
        }
        if (requirements.size() > SINGLE) {
            return new SecurityResolution(SecurityDisposition.ALTERNATIVES, satisfiable);
        }
        SecurityDisposition disposition =
                satisfiable.get(0).size() > SINGLE ? SecurityDisposition.ALL_REQUIRED : SecurityDisposition.REQUIRED;
        return new SecurityResolution(disposition, satisfiable);
    }

    private static List<Map<String, List<String>>> effectiveSecurity(
            List<Map<String, List<String>>> rootSecurity, List<Map<String, List<String>>> operationSecurity) {
        if (operationSecurity != null) {
            return operationSecurity;
        }
        return rootSecurity == null ? List.of() : rootSecurity;
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
        String path = reference.getRawPath();
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

    /** How an Agent must treat the security an operation resolves to. */
    public enum SecurityDisposition {
        PUBLIC("public"),
        OPTIONAL_ANONYMOUS("optional-anonymous"),
        REQUIRED("required"),
        ALTERNATIVES("alternatives"),
        ALL_REQUIRED("all-required"),
        FALLBACK_LIVE_CHALLENGE("fallback-live-challenge");

        private final String wireValue;

        SecurityDisposition(String wireValue) {
            this.wireValue = wireValue;
        }

        public String value() {
            return wireValue;
        }
    }

    /**
     * The resolved security for an operation.
     *
     * @param satisfiable the complete requirement objects the Agent can satisfy, each listed as the
     *     scheme names it must present together; empty unless the disposition selects credentials
     */
    public record SecurityResolution(SecurityDisposition disposition, List<List<String>> satisfiable) {
        public SecurityResolution {
            Objects.requireNonNull(disposition, "disposition");
            List<List<String>> copied = new ArrayList<>();
            if (satisfiable != null) {
                satisfiable.forEach(requirement -> copied.add(Copies.list(requirement)));
            }
            satisfiable = List.copyOf(copied);
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
