package foundation.aep.agent;

import foundation.aep.core.PlatformAgentIdentity;
import java.util.Map;
import java.util.Objects;

public record PlatformPendingSign(
        PlatformAgentIdentity identity, Map<String, Object> platformContext, int retryAfterSeconds) {
    public PlatformPendingSign {
        Objects.requireNonNull(identity, "identity");
        if (retryAfterSeconds < 1 || retryAfterSeconds > 300) {
            throw new IllegalArgumentException("retryAfterSeconds must be between 1 and 300");
        }
        platformContext = PlatformJson.copyMap(platformContext);
    }

    @Override
    public Map<String, Object> platformContext() {
        return PlatformJson.copyMap(platformContext);
    }
}
