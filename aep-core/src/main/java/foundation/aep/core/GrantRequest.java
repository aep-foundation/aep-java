package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record GrantRequest(
        @JsonProperty("grant_type") String grantType,
        String label,
        @JsonProperty("requested_scopes") List<String> requestedScopes,
        @JsonProperty("token_format") String tokenFormat) {
    public GrantRequest {
        requestedScopes = Copies.list(requestedScopes);
    }

    public GrantRequest(String grantType, List<String> requestedScopes) {
        this(grantType, null, requestedScopes, null);
    }
}
