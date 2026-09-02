package foundation.aep.agent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class PlatformJson {
    private PlatformJson() {}

    static Map<String, Object> copyMap(Map<String, Object> value) {
        if (value == null) return null; // NOPMD - Null preserves an omitted optional platform_context.
        Map<String, Object> result = new LinkedHashMap<>();
        value.forEach((key, item) -> result.put(key, copy(item)));
        return Collections.unmodifiableMap(result);
    }

    private static Object copy(Object value) {
        if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean) {
            return value;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            map.forEach((key, item) -> {
                if (!(key instanceof String name)) {
                    throw new IllegalArgumentException("AEP Platform context keys must be strings.");
                }
                result.put(name, copy(item));
            });
            return Collections.unmodifiableMap(result);
        }
        if (value instanceof List<?> list) {
            List<Object> result = new ArrayList<>(list.size());
            list.forEach(item -> result.add(copy(item)));
            return Collections.unmodifiableList(result);
        }
        throw new IllegalArgumentException("AEP Platform context must contain JSON-compatible values.");
    }
}
