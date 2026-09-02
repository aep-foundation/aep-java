package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record PlatformAgentIdentity(
        @JsonProperty("agent_did") String agentDid,
        @JsonProperty("agent_identity_id") String agentIdentityId,
        @JsonProperty("created_at") String createdAt,
        @JsonProperty("did_document_url") String didDocumentUrl,
        @JsonProperty("key_id") String keyId,
        @JsonProperty("service_did") String serviceDid,
        @JsonProperty("signing_algorithms") List<String> signingAlgorithms,
        ManagedAgentStatus status,
        @JsonProperty("updated_at") String updatedAt) {
    public PlatformAgentIdentity {
        signingAlgorithms = Copies.list(signingAlgorithms);
    }

    @Override
    public List<String> signingAlgorithms() {
        return List.copyOf(signingAlgorithms);
    }
}
