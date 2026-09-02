package foundation.aep.service;

import foundation.aep.core.GrantResponses;
import java.time.Instant;
import java.util.Objects;

public record ServiceCredentialRecord(
        String agentDid,
        Instant createdAt,
        GrantResponses.BuiltIn credential,
        String credentialId,
        Instant expiresAt,
        String grantType) {
    public ServiceCredentialRecord {
        Objects.requireNonNull(agentDid, "agentDid");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(credential, "credential");
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(grantType, "grantType");
    }

    @Override
    public String toString() {
        return "ServiceCredentialRecord[agentDid=" + agentDid + ", createdAt=" + createdAt
                + ", credential=<redacted>, credentialId=" + credentialId + ", expiresAt=" + expiresAt
                + ", grantType=" + grantType + "]";
    }
}
