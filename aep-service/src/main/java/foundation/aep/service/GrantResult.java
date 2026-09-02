package foundation.aep.service;

import java.util.Map;

public record GrantResult(String credentialId, Map<String, Object> response) {
    public GrantResult {
        if (credentialId == null || credentialId.isBlank()) {
            throw new IllegalArgumentException("Grant response requires a stable credential ID.");
        }
        response = ServiceCopies.jsonObject(response);
        if (!credentialId.equals(response.get("credential_id"))) {
            throw new IllegalArgumentException("Grant response credential_id must match its stable credential ID.");
        }
    }

    @Override
    public Map<String, Object> response() {
        return ServiceCopies.jsonObject(response);
    }
}
