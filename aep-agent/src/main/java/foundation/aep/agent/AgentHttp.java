package foundation.aep.agent;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.ProblemDetails;
import java.net.IDN;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

final class AgentHttp {
    private static final String CACHE_NO_STORE = "no-store";
    private static final String CACHE_NO_CACHE = "no-cache";

    private AgentHttp() {}

    static URI origin(URI value, boolean allowInsecureLoopback) {
        if (value == null || value.getScheme() == null || value.getHost() == null || value.getUserInfo() != null) {
            throw new IllegalArgumentException("AEP Service origin must be an absolute HTTP origin");
        }
        String scheme = value.getScheme().toLowerCase(Locale.ROOT);
        boolean loopback = isLoopback(value.getHost());
        if (!"https".equals(scheme) && !(allowInsecureLoopback && loopback && "http".equals(scheme))) {
            throw new IllegalArgumentException("AEP Service origin must use HTTPS");
        }
        if ((!value.getPath().isEmpty() && !"/".equals(value.getPath()))
                || value.getRawQuery() != null
                || value.getRawFragment() != null) {
            throw new IllegalArgumentException("AEP Service origin must not contain a path, query, or fragment");
        }
        String host = IDN.toASCII(value.getHost()).toLowerCase(Locale.ROOT);
        return URI.create(scheme + "://" + host + (value.getPort() < 0 ? "" : ":" + value.getPort()));
    }

    static boolean sameOrigin(URI left, URI right) {
        return left != null
                && right != null
                && left.getScheme() != null
                && right.getScheme() != null
                && left.getHost() != null
                && right.getHost() != null
                && left.getScheme().equalsIgnoreCase(right.getScheme())
                && IDN.toASCII(left.getHost()).equalsIgnoreCase(IDN.toASCII(right.getHost()))
                && effectivePort(left) == effectivePort(right);
    }

    static boolean validInspectTarget(URI origin, URI target) {
        return target != null
                && target.getUserInfo() == null
                && target.getRawFragment() == null
                && sameOrigin(origin, target);
    }

    static Optional<String> header(AepHttpTransport.Response response, String name) {
        return response.headers().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .flatMap(entry -> entry.getValue().stream())
                .findFirst();
    }

    static void requireBodyLimit(AepHttpTransport.Response response, int maximumBytes) {
        if (response.body().length > maximumBytes) {
            throw new AepAgentException("response_too_large", "AEP response exceeded the configured size limit");
        }
    }

    static String body(AepHttpTransport.Response response) {
        return new String(response.body(), StandardCharsets.UTF_8);
    }

    static void requireMediaType(AepHttpTransport.Response response, String expected) {
        String actual = header(response, "Content-Type").orElse("");
        String essence = actual.split(";", 2)[0].trim();
        if (!expected.equalsIgnoreCase(essence)) {
            throw new AepAgentException("invalid_media_type", "AEP response media type is invalid");
        }
    }

    static AepAgentException commandError(AepHttpTransport.Response response) {
        try {
            requireMediaType(response, Aep.PROBLEM_MEDIA_TYPE);
            ProblemDetails problem = AepJson.parseProblemDetails(body(response));
            return new AepAgentException(
                    problem.code(), problem.detail() == null ? problem.title() : problem.detail(), response.status());
        } catch (RuntimeException ignored) {
            return new AepAgentException("command_failed", "AEP command failed", response.status());
        }
    }

    static Instant expiresAt(AepHttpTransport.Response response, Instant now, Duration fallback) {
        String cacheControl = String.join(",", headerValues(response, "Cache-Control"));
        for (String directive : cacheControl.split(",")) {
            String value = directive.trim().toLowerCase(Locale.ROOT);
            if (CACHE_NO_STORE.equals(value) || CACHE_NO_CACHE.equals(value)) {
                return now;
            }
            if (value.startsWith("max-age=")) {
                try {
                    long seconds = Long.parseLong(value.substring("max-age=".length()));
                    return safeAdd(now, Duration.ofSeconds(Math.max(0, seconds)), fallback);
                } catch (ArithmeticException | NumberFormatException exception) {
                    return safeAdd(now, fallback, Duration.ZERO);
                }
            }
        }
        return safeAdd(now, fallback, Duration.ZERO);
    }

    static boolean isNoStore(AepHttpTransport.Response response) {
        return headerValues(response, "Cache-Control").stream()
                .flatMap(value -> java.util.Arrays.stream(value.split(",")))
                .map(String::trim)
                .anyMatch(CACHE_NO_STORE::equalsIgnoreCase);
    }

    static Map<String, List<String>> headers(Map<String, String> values) {
        return values.entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, entry -> List.of(entry.getValue())));
    }

    private static int effectivePort(URI value) {
        if (value.getPort() >= 0) {
            return value.getPort();
        }
        return "https".equalsIgnoreCase(value.getScheme()) ? 443 : 80;
    }

    private static List<String> headerValues(AepHttpTransport.Response response, String name) {
        List<String> values = new ArrayList<>();
        response.headers().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .forEach(entry -> values.addAll(entry.getValue()));
        return List.copyOf(values);
    }

    private static Instant safeAdd(Instant now, Duration value, Duration secondaryFallback) {
        try {
            return now.plus(value);
        } catch (ArithmeticException | DateTimeException exception) {
            if (secondaryFallback.isZero()) {
                return Instant.MAX;
            }
            return safeAdd(now, secondaryFallback, Duration.ZERO);
        }
    }

    private static boolean isLoopback(String host) {
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host) // NOPMD - Explicit development opt-in permits loopback HTTP.
                || "::1".equals(host) // NOPMD - Explicit development opt-in permits loopback HTTP.
                || "[::1]".equals(host);
    }
}
