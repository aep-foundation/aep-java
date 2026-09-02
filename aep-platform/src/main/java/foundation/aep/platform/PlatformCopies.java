package foundation.aep.platform;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class PlatformCopies {
    private PlatformCopies() {}

    static Map<String, List<String>> headers(Map<String, List<String>> source) {
        if (source == null) return Map.of();
        Map<String, List<String>> result = new LinkedHashMap<>();
        source.forEach((name, values) -> result.put(name, List.copyOf(values)));
        return Map.copyOf(result);
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
