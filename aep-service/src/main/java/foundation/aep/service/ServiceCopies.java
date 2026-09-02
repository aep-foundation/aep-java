package foundation.aep.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class ServiceCopies {
    private ServiceCopies() {}

    static Map<String, List<String>> headers(Map<String, List<String>> source) {
        if (source == null) return Map.of();
        Map<String, List<String>> result = new LinkedHashMap<>();
        source.forEach((name, values) -> result.put(name, List.copyOf(values)));
        return Map.copyOf(result);
    }

    static Map<String, Object> jsonObject(Map<String, Object> source) {
        if (source == null) throw new IllegalArgumentException("JSON object must not be null.");
        Map<String, Object> result = new LinkedHashMap<>();
        source.forEach((name, value) -> result.put(requireJsonName(name), jsonValue(value)));
        return java.util.Collections.unmodifiableMap(result);
    }

    private static Object jsonValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            map.forEach((name, member) -> {
                if (!(name instanceof String stringName)) {
                    throw new IllegalArgumentException("JSON object member names must be strings.");
                }
                result.put(requireJsonName(stringName), jsonValue(member));
            });
            return java.util.Collections.unmodifiableMap(result);
        }
        if (value instanceof List<?> list) {
            return list.stream().map(ServiceCopies::jsonValue).toList();
        }
        if (value instanceof Double doubleValue && !Double.isFinite(doubleValue)
                || value instanceof Float floatValue && !Float.isFinite(floatValue)) {
            throw new IllegalArgumentException("JSON numbers must be finite.");
        }
        if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean) {
            return value;
        }
        throw new IllegalArgumentException("Grant responses must contain JSON-compatible values.");
    }

    private static String requireJsonName(String value) {
        if (value == null) throw new IllegalArgumentException("JSON object member names must not be null.");
        return value;
    }
}
