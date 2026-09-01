package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record StatusResponse(
        AgentStatus status,
        @JsonProperty("owner_action_required") String ownerActionRequired,
        @JsonProperty("verification_pending") List<String> verificationPending,
        @JsonProperty("requirements_pending") List<String> requirementsPending,
        String since) {
    public StatusResponse {
        verificationPending = Copies.nullableList(verificationPending);
        requirementsPending = Copies.nullableList(requirementsPending);
    }
}
