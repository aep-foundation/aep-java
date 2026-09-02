package foundation.aep.platform;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record PlatformDidDocument(
        @JsonProperty("@context") List<String> context,
        List<String> authentication,
        String id,
        @JsonProperty("verificationMethod") List<PlatformDidVerificationMethod> verificationMethods) {
    public PlatformDidDocument {
        context = List.copyOf(context);
        authentication = List.copyOf(authentication);
        verificationMethods = List.copyOf(verificationMethods);
    }

    @Override
    public List<String> context() {
        return List.copyOf(context);
    }

    @Override
    public List<String> authentication() {
        return List.copyOf(authentication);
    }

    @Override
    public List<PlatformDidVerificationMethod> verificationMethods() {
        return List.copyOf(verificationMethods);
    }
}
