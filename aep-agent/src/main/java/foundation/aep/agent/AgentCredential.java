package foundation.aep.agent;

import java.time.Instant;
import java.util.Objects;

public record AgentCredential(
        String serviceDid, String grantType, String credentialId, Instant expiresAt, String responseJson) {
    public AgentCredential {
        Objects.requireNonNull(serviceDid, "serviceDid");
        Objects.requireNonNull(grantType, "grantType");
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(responseJson, "responseJson");
    }

    @Override
    public String toString() {
        return "AgentCredential[serviceDid=" + serviceDid + ", grantType=" + grantType + ", credentialId="
                + credentialId + ", expiresAt=" + expiresAt + ", responseJson=<redacted>]";
    }
}
