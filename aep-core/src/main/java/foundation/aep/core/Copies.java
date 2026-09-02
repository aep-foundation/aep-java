package foundation.aep.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Copies {
    private Copies() {}

    static <T> List<T> list(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    static <T> List<T> nullableList(List<T> values) {
        return values == null ? null : List.copyOf(values);
    }

    static <K, V> Map<K, V> map(Map<K, V> values) {
        return values == null ? Map.of() : Map.copyOf(values);
    }

    static Map<String, List<String>> headers(Map<String, List<String>> values) {
        if (values == null) {
            return Map.of();
        }
        Map<String, List<String>> copy = new LinkedHashMap<>();
        values.forEach((name, entries) -> copy.put(name, list(entries)));
        return Map.copyOf(copy);
    }

    static Map<String, Object> jsonMap(Map<String, Object> values) {
        if (values == null) {
            return Map.of();
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        values.forEach((name, value) -> copy.put(name, jsonValue(value)));
        return Collections.unmodifiableMap(copy);
    }

    static Map<String, Object> nullableJsonMap(Map<String, Object> values) {
        return values == null ? null : jsonMap(values);
    }

    private static Object jsonValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> copy = new LinkedHashMap<>();
            map.forEach((name, nested) -> copy.put(name, jsonValue(nested)));
            return Collections.unmodifiableMap(copy);
        }
        if (value instanceof List<?> list) {
            return list.stream().map(Copies::jsonValue).toList();
        }
        return value;
    }
}
