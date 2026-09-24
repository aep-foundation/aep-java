package foundation.aep.platform;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class PlatformCopies {
    private PlatformCopies() {}

    // Platform responses carry headers straight out into an HTTP message, and a sign handler or an
    // embedding application supplies them. An unchecked name or value let a bare CR or LF terminate
    // the field early and inject a header, or a whole response, that nothing in AEP ever authored.
    static Map<String, List<String>> headers(Map<String, List<String>> source) {
        if (source == null) return Map.of();
        Map<String, List<String>> result = new LinkedHashMap<>();
        source.forEach((name, values) -> result.put(requireFieldName(name), requireFieldValues(values)));
        return Map.copyOf(result);
    }

    private static String requireFieldName(String value) {
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("Header names must not be empty.");
        for (int index = 0; index < value.length(); index++) {
            if (!isTokenCharacter(value.charAt(index))) {
                throw new IllegalArgumentException("Header names must be RFC 9110 tokens.");
            }
        }
        return value;
    }

    private static List<String> requireFieldValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("Header values must not be empty.");
        }
        return values.stream().map(PlatformCopies::requireFieldValue).toList();
    }

    private static String requireFieldValue(String value) {
        if (value == null || !value.equals(value.strip())) {
            throw new IllegalArgumentException("Header values must not be null or surrounded by whitespace.");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character != '\t' && (character < ' ' || character == 0x7f)) {
                throw new IllegalArgumentException("Header values must not contain control characters.");
            }
        }
        return value;
    }

    private static boolean isTokenCharacter(char value) {
        return value >= '0' && value <= '9'
                || value >= 'a' && value <= 'z'
                || value >= 'A' && value <= 'Z'
                || "!#$%&'*+-.^_`|~".indexOf(value) >= 0;
    }

    static Map<String, Object> jsonObject(Map<String, Object> source) {
        if (source == null) return Map.of();
        Map<String, Object> result = new LinkedHashMap<>();
        source.forEach((name, value) -> result.put(requireName(name), jsonValue(value)));
        return Collections.unmodifiableMap(result);
    }

    static Object jsonValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            map.forEach((name, nested) -> {
                if (!(name instanceof String stringName)) {
                    throw new IllegalArgumentException("JSON object member names must be strings.");
                }
                result.put(requireName(stringName), jsonValue(nested));
            });
            return Collections.unmodifiableMap(result);
        }
        if (value instanceof List<?> list)
            return list.stream().map(PlatformCopies::jsonValue).toList();
        if (value instanceof Double doubleValue && !Double.isFinite(doubleValue)
                || value instanceof Float floatValue && !Float.isFinite(floatValue)) {
            throw new IllegalArgumentException("JSON numbers must be finite.");
        }
        if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean) {
            return value;
        }
        throw new IllegalArgumentException("Platform JSON values must be JSON-compatible.");
    }

    private static String requireName(String value) {
        if (value == null) throw new IllegalArgumentException("JSON object member names must not be null.");
        return value;
    }
}
