package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record EnrollRequest(
        @JsonProperty("agent_did") String agentDid,
        ClaimValues claims,
        @JsonProperty("idempotency_key") String idempotencyKey) {}
