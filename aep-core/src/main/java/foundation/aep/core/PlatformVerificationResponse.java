package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PlatformVerificationResponse(
        @JsonProperty("agent_did") String agentDid,
        @JsonProperty("agent_identity_id") String agentIdentityId,
        @JsonProperty("op") AssertionOperation operation,
        String reason,
        @JsonProperty("service_did") String serviceDid,
        ManagedAgentStatus status,
        boolean verified) {}
