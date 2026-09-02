package foundation.aep.platform;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record PlatformDidVerificationMethod(
        String controller,
        String id,
        @JsonProperty("publicKeyJwk") Map<String, Object> publicKeyJwk,
        String type) {
    public PlatformDidVerificationMethod {
        if (controller == null || controller.isBlank()) throw new IllegalArgumentException("controller is required");
        if (id == null || id.isBlank()) throw new IllegalArgumentException("id is required");
        if (type == null || type.isBlank()) throw new IllegalArgumentException("type is required");
        publicKeyJwk = PlatformCopies.jsonObject(publicKeyJwk);
        if (publicKeyJwk.isEmpty()) throw new IllegalArgumentException("publicKeyJwk is required");
    }

    @Override
    public Map<String, Object> publicKeyJwk() {
        return PlatformCopies.jsonObject(publicKeyJwk);
    }
}
