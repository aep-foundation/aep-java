package foundation.aep.platform;

import java.time.Instant;
import java.util.Map;

public record PlatformRequestContext(String principal, String idempotencyKey, Instant now, Map<String, Object> values) {
    public PlatformRequestContext {
        values = PlatformCopies.jsonObject(values);
    }

    public PlatformRequestContext(String principal, String idempotencyKey) {
        this(principal, idempotencyKey, null, Map.of());
    }

    @Override
    public Map<String, Object> values() {
        return PlatformCopies.jsonObject(values);
    }

    @Override
    public String toString() {
        return "PlatformRequestContext[principal=<redacted>, idempotencyKey=<redacted>, now=" + now + ", valueNames="
                + values.keySet() + "]";
    }
}
