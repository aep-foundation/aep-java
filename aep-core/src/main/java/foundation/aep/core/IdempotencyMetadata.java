package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record IdempotencyMetadata(
        @JsonProperty("agent_did") String agentDid,
        @JsonProperty("idempotency_key") String idempotencyKey,
        @JsonProperty("first_body_hash") String firstBodyHash,
        @JsonProperty("second_body_hash") String secondBodyHash) {}
