package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record EnrollRequest(
        @JsonProperty("agent_did") String agentDid,
        ClaimValues claims,
        @JsonProperty("idempotency_key") String idempotencyKey,
        @JsonProperty("acknowledged_document_ids") List<String> acknowledgedDocumentIds) {
    public EnrollRequest {
        acknowledgedDocumentIds = Copies.nullableList(acknowledgedDocumentIds);
    }

    public EnrollRequest(String agentDid, ClaimValues claims, String idempotencyKey) {
        this(agentDid, claims, idempotencyKey, null);
    }
}
