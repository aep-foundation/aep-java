package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record EnrollResponse(
        AgentStatus status,
        @JsonProperty("owner_action_required") String ownerActionRequired,
        @JsonProperty("verification_pending") List<String> verificationPending,
        @JsonProperty("requirements_pending") List<String> requirementsPending,
        @JsonProperty("acknowledged_document_ids") List<String> acknowledgedDocumentIds) {
    public EnrollResponse {
        verificationPending = Copies.nullableList(verificationPending);
        requirementsPending = Copies.nullableList(requirementsPending);
        acknowledgedDocumentIds = Copies.nullableList(acknowledgedDocumentIds);
    }

    public EnrollResponse(
            AgentStatus status,
            String ownerActionRequired,
            List<String> verificationPending,
            List<String> requirementsPending) {
        this(status, ownerActionRequired, verificationPending, requirementsPending, null);
    }
}
