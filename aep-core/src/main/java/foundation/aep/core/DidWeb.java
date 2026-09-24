package foundation.aep.core;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public final class DidWeb {
    private static final String PREFIX = "did:web:";

    private DidWeb() {}

    public static URI documentUri(String did) {
        return documentUri(did, false);
    }

    public static URI documentUri(String did, boolean allowInsecureLoopback) {
        if (did == null || !did.startsWith(PREFIX)) {
            throw new IllegalArgumentException("Unsupported DID method: " + did);
        }
        String[] components = did.substring(PREFIX.length()).split(":", -1);
        if (components.length == 0 || components[0].isEmpty()) {
            throw new IllegalArgumentException("Invalid did:web identifier: " + did);
        }
        String authority = decode(components[0]);
        URI authorityUri = URI.create("https://" + authority);
        String host = authorityUri.getHost();
        // The decoded authority is concatenated back into the document URI, so it has to be an
        // authority and nothing else. Without the round-trip check a value such as
        // "example.com%3Fx=1" parsed as a host plus a query, passed every individual check, and
        // produced a document URI whose query swallowed the whole did.json path.
        if (host == null
                || authorityUri.getUserInfo() != null
                || !authorityUri.getPath().isEmpty()
                || !authority.equals(authorityUri.getRawAuthority())) {
            throw new IllegalArgumentException("Invalid did:web authority: " + authority);
        }
        List<String> path = new ArrayList<>();
        for (int index = 1; index < components.length; index++) {
            String component = decode(components[index]);
            if (component.isEmpty() || component.contains("/") || ".".equals(component) || "..".equals(component)) {
                throw new IllegalArgumentException("Invalid did:web path component.");
            }
            path.add(components[index]);
        }
        String documentPath = path.isEmpty() ? "/.well-known/did.json" : "/" + String.join("/", path) + "/did.json";
        String scheme = allowInsecureLoopback && isLoopback(host) ? "http" : "https";
        return URI.create(scheme + "://" + authority + documentPath);
    }

    public static boolean bindsOrigin(String did, URI origin) {
        if (origin == null || origin.getHost() == null) {
            return false;
        }
        URI document = documentUri(did);
        return "https".equalsIgnoreCase(origin.getScheme())
                && normalizedHost(document).equals(normalizedHost(origin))
                && effectivePort(document) == effectivePort(origin);
    }

    private static String decode(String value) {
        try {
            URI uri = URI.create("https://did.invalid/" + value);
            if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("Invalid did:web component.");
            }
            return uri.getPath().substring(1);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid did:web percent encoding.", exception);
        }
    }

    private static String normalizedHost(URI value) {
        return IDN.toASCII(value.getHost()).toLowerCase(java.util.Locale.ROOT);
    }

    private static int effectivePort(URI value) {
        return value.getPort() == -1 ? ("https".equalsIgnoreCase(value.getScheme()) ? 443 : 80) : value.getPort();
    }

    private static boolean isLoopback(String host) {
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host) // NOPMD - Explicit development opt-in permits loopback HTTP.
                || "::1".equals(host) // NOPMD - Explicit development opt-in permits loopback HTTP.
                || "[::1]".equals(host);
    }
}
