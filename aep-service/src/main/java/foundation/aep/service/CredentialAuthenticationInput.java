package foundation.aep.service;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record CredentialAuthenticationInput(Map<String, List<String>> headers, String method, URI url, Instant now) {
    public CredentialAuthenticationInput {
        headers = ServiceCopies.headers(headers);
    }

    @Override
    public Map<String, List<String>> headers() {
        return ServiceCopies.headers(headers);
    }
}
