package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record GrantRequest(
        @JsonProperty("grant_type") String grantType,
        @JsonProperty("requested_scopes") List<String> requestedScopes) {
    public GrantRequest {
        requestedScopes = Copies.list(requestedScopes);
    }
}
