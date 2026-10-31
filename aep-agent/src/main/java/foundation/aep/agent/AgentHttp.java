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
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

final class AgentHttp {
    private static final String CACHE_NO_STORE = "no-store";
    private static final String CACHE_NO_CACHE = "no-cache";
    private static final String TOKEN = "[!#$%&'*+.^_`|~0-9a-zA-Z-]+";
    private static final Pattern MEDIA_TYPE = Pattern.compile(TOKEN + "/" + TOKEN
            + "(?:[ \\t]*;[ \\t]*" + TOKEN + "=(?:" + TOKEN
            + "|\"(?:[\\t !#-\\[\\]-~\\x80-\\xFF]|\\\\[\\t !-~\\x80-\\xFF])*\"))*[ \\t]*");

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
        if (left == null
                || right == null
                || left.getScheme() == null
                || right.getScheme() == null
                || left.getHost() == null
                || right.getHost() == null
                || !left.getScheme().equalsIgnoreCase(right.getScheme())
                || effectivePort(left) != effectivePort(right)) {
            return false;
        }
        // A redirect Location is attacker-controlled, and IDN.toASCII rejects a malformed label by
        // throwing. An unparseable host is not the same origin; it is not an error to propagate.
        String leftHost = asciiHost(left.getHost());
        String rightHost = asciiHost(right.getHost());
        return leftHost != null && leftHost.equalsIgnoreCase(rightHost);
    }

    private static String asciiHost(String host) {
        try {
            return IDN.toASCII(host);
        } catch (IllegalArgumentException exception) {
            return null;
        }
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
        if (!MEDIA_TYPE.matcher(actual).matches() || !expected.equalsIgnoreCase(essence)) {
            throw new AepAgentException("invalid_media_type", "AEP response media type is invalid");
        }
    }

    static AepAgentException commandError(AepHttpTransport.Response response) {
        try {
            requireMediaType(response, Aep.PROBLEM_MEDIA_TYPE);
            ProblemDetails problem = AepJson.parseProblemDetails(body(response));
            return new AepAgentException(problem, response.status());
        } catch (RuntimeException ignored) {
            return new AepAgentException("command_failed", "AEP command failed", response.status());
        }
    }

    static Instant expiresAt(AepHttpTransport.Response response, Instant now, Duration fallback) {
        List<String> directives = new ArrayList<>();
        for (String value : headerValues(response, "Cache-Control")) {
            for (String directive : value.split(",")) {
                directives.add(directive.trim().toLowerCase(Locale.ROOT));
            }
        }
        if (directives.contains(CACHE_NO_STORE) || directives.contains(CACHE_NO_CACHE)) {
            return now;
        }
        for (String directive : directives) {
            if (directive.startsWith("max-age=")) {
                try {
                    String value = directive.substring("max-age=".length());
                    if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
                        value = value.substring(1, value.length() - 1);
                    }
                    long seconds = Long.parseLong(value);
                    return freshUntil(response, now, Duration.ofSeconds(Math.max(0, seconds)), fallback);
                } catch (ArithmeticException | NumberFormatException exception) {
                    return freshUntil(response, now, fallback, Duration.ZERO);
                }
            }
        }
        Instant date = httpDate(response, "Date").orElse(now);
        Duration lifetime = httpDate(response, "Expires")
                .map(expires -> Duration.between(date, expires))
                .orElse(fallback);
        return freshUntil(response, now, lifetime, Duration.ZERO);
    }

    private static Instant freshUntil(
            AepHttpTransport.Response response, Instant now, Duration lifetime, Duration fallback) {
        Duration apparentAge = httpDate(response, "Date")
                .map(date -> Duration.between(date, now))
                .orElse(Duration.ZERO);
        long ageSeconds;
        try {
            ageSeconds = Long.parseLong(header(response, "Age").orElse("0"));
        } catch (NumberFormatException exception) {
            ageSeconds = 0;
        }
        Duration age = Duration.ofSeconds(Math.max(0, ageSeconds));
        if (apparentAge.compareTo(age) > 0) age = apparentAge;
        if (lifetime.compareTo(age) <= 0) return now;
        return safeAdd(now, lifetime.minus(age), fallback);
    }

    private static Optional<Instant> httpDate(AepHttpTransport.Response response, String name) {
        try {
            return header(response, name)
                    .map(value -> ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME)
                            .toInstant());
        } catch (DateTimeParseException exception) {
            return Optional.empty();
        }
    }

    static Map<String, List<String>> cacheHeaders(AepHttpTransport.Response response) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String name : List.of("Cache-Control", "Date", "Expires")) {
            List<String> values = headerValues(response, name);
            if (!values.isEmpty()) headers.put(name, values);
        }
        return Map.copyOf(headers);
    }

    static AepHttpTransport.Response revalidated(AepHttpTransport.Response response, Map<String, List<String>> prior) {
        Map<String, List<String>> headers = new LinkedHashMap<>(response.headers());
        prior.forEach((name, values) -> {
            if (headerValues(response, name).isEmpty()) headers.put(name, values);
        });
        return new AepHttpTransport.Response(response.status(), headers, response.body());
    }

    /**
     * Checks a value the SDK is about to send as an HTTP field value.
     *
     * The idempotency key comes from an application-supplied provider and is written straight into
     * a request header. A value carrying a control character or a line break is not a field value
     * at all, and surrounding whitespace is stripped in transit, so the Service would record a
     * different key than the Agent did.
     */
    static String requireFieldValue(String value, String name) {
        if (value == null || value.isBlank() || !value.equals(value.strip())) {
            throw new AepAgentException(
                    "invalid_configuration", name + " must be a non-empty value without surrounding whitespace");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 0x20 || character == 0x7f) {
                throw new AepAgentException("invalid_configuration", name + " must not contain control characters");
            }
        }
        return value;
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
