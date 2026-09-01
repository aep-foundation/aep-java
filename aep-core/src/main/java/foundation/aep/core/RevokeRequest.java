package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RevokeRequest(
        @JsonProperty("grant_type") String grantType,
        @JsonProperty("credential_id") String credentialId,
        @JsonProperty("all_grant_types") String allGrantTypes) {
    public static RevokeRequest forAllGrantTypes() {
        return new RevokeRequest(null, null, "true");
    }

    public static RevokeRequest grantType(String grantType) {
        return new RevokeRequest(grantType, null, null);
    }

    public static RevokeRequest credential(String grantType, String credentialId) {
        return new RevokeRequest(grantType, credentialId, null);
    }
}
