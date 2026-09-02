package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public interface PlatformSignResponses {
    public sealed interface Response permits Completed, Pending {
        String status();
    }

    public record Completed(
            String status,
            @JsonProperty("agent_did") String agentDid,
            @JsonProperty("client_assertion") String clientAssertion,
            @JsonProperty("expires_at") String expiresAt,
            @JsonProperty("issued_at") String issuedAt,
            @JsonProperty("jti") String jwtId,
            @JsonProperty("platform_context") Map<String, Object> platformContext,
            @JsonProperty("service_did") String serviceDid)
            implements Response {
        public Completed {
            platformContext = Copies.nullableJsonMap(platformContext);
        }

        @Override
        public Map<String, Object> platformContext() {
            return Copies.nullableJsonMap(platformContext);
        }
    }

    public record Pending(
            String status,
            @JsonProperty("platform_context") Map<String, Object> platformContext,
            @JsonProperty("retry_after_seconds") String retryAfterSeconds)
            implements Response {
        public Pending {
            platformContext = Copies.nullableJsonMap(platformContext);
        }

        @Override
        public Map<String, Object> platformContext() {
            return Copies.nullableJsonMap(platformContext);
        }
    }
}
