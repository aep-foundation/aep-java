package foundation.aep.service;

import foundation.aep.core.AepJson;
import foundation.aep.core.ClaimValues;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

public record ClaimValueLimits(
        int maximumEncodedBytes, int maximumMemberCount, int maximumObjectDepth, int maximumStringLength) {
    private static final ClaimValueLimits DEFAULTS = new ClaimValueLimits(65_536, 128, 8, 4_096);

    public ClaimValueLimits {
        if (maximumEncodedBytes < 1 || maximumMemberCount < 1 || maximumObjectDepth < 1 || maximumStringLength < 1) {
            throw new IllegalArgumentException("AEP Claim Value limits must be positive.");
        }
    }

    public static ClaimValueLimits defaults() {
        return DEFAULTS;
    }

    boolean accepts(ClaimValues values) {
        if (values == null) return true;
        String json = AepJson.write(values);
        if (json.getBytes(StandardCharsets.UTF_8).length > maximumEncodedBytes) return false;
        Map<String, Object> object = AepJson.parseObject(json, "claim values");
        Counter counter = new Counter();
        return acceptsValue(object, 1, counter);
    }

    private boolean acceptsValue(Object value, int depth, Counter counter) {
        if (value instanceof String text) {
            return text.codePointCount(0, text.length()) <= maximumStringLength;
        }
        if (value == null || value instanceof Boolean || value instanceof Number) return true;
        if (depth > maximumObjectDepth) return false;
        if (value instanceof List<?> list) {
            return list.stream().allMatch(member -> acceptsValue(member, depth + 1, counter));
        }
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                counter.members++;
                if (!(entry.getKey() instanceof String name)
                        || name.codePointCount(0, name.length()) > maximumStringLength
                        || counter.members > maximumMemberCount
                        || !acceptsValue(entry.getValue(), depth + 1, counter)) return false;
            }
            return true;
        }
        return false;
    }

    private static final class Counter {
        private int members;
    }
}
