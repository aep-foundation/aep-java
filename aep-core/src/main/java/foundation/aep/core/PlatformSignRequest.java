package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record PlatformSignRequest(
        @JsonProperty("jti") String jwtId,
        @JsonProperty("lifetime_seconds") String lifetimeSeconds,
        @JsonProperty("op") AssertionOperation operation,
        @JsonProperty("platform_context") Map<String, Object> platformContext,
        String resource,
        @JsonProperty("service_did") String serviceDid) {
    public PlatformSignRequest {
        platformContext = Copies.nullableJsonMap(platformContext);
    }

    @Override
    public Map<String, Object> platformContext() {
        return Copies.nullableJsonMap(platformContext);
    }
}
