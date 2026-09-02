package foundation.aep.agent;

import java.util.Optional;

public record AgentGrantResult(String grantType, String responseJson, Optional<AgentCredential> credential) {
    public AgentGrantResult {
        credential = credential == null ? Optional.empty() : credential;
    }

    @Override
    public String toString() {
        return "AgentGrantResult[grantType=" + grantType + ", responseJson=<redacted>, credential=" + credential + "]";
    }
}
