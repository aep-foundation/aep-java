package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public final class GrantResponses { // NOPMD - Namespace for the related built-in response types.
    private GrantResponses() {}

    public sealed interface BuiltIn permits ApiKey, Basic, OAuthBearer {
        String credentialId();

        String expiresAt();

        List<String> scopes();
    }

    public record OAuthBearer(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("credential_id") String credentialId,
            @JsonProperty("expires_at") String expiresAt,
            List<String> scopes,
            @JsonProperty("token_type") String tokenType)
            implements BuiltIn {
        public OAuthBearer {
            scopes = Copies.list(scopes);
        }

        @Override
        public String toString() {
            return "OAuthBearer[accessToken=<redacted>, credentialId=" + credentialId + ", expiresAt=" + expiresAt
                    + ", scopes=" + scopes + ", tokenType=" + tokenType + "]";
        }
    }

    public record ApiKey(
            @JsonProperty("api_key") String apiKey,
            @JsonProperty("credential_id") String credentialId,
            @JsonProperty("expires_at") String expiresAt,
            String header,
            List<String> scopes)
            implements BuiltIn {
        public ApiKey {
            scopes = Copies.list(scopes);
        }

        @Override
        public String toString() {
            return "ApiKey[apiKey=<redacted>, credentialId=" + credentialId + ", expiresAt=" + expiresAt + ", header="
                    + header + ", scopes=" + scopes + "]";
        }
    }

    public record Basic(
            @JsonProperty("credential_id") String credentialId,
            @JsonProperty("expires_at") String expiresAt,
            String password,
            String realm,
            List<String> scopes,
            String username)
            implements BuiltIn {
        public Basic {
            scopes = Copies.list(scopes);
        }

        @Override
        public String toString() {
            return "Basic[credentialId=" + credentialId + ", expiresAt=" + expiresAt + ", password=<redacted>, realm="
                    + realm + ", scopes=" + scopes + ", username=<redacted>]";
        }
    }
}
