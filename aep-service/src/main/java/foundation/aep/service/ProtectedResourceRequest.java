package foundation.aep.service;

import java.net.URI;
import java.util.List;
import java.util.Map;

public record ProtectedResourceRequest(Map<String, List<String>> headers, String method, URI url) {
    public ProtectedResourceRequest {
        headers = ServiceCopies.headers(headers);
    }

    @Override
    public Map<String, List<String>> headers() {
        return ServiceCopies.headers(headers);
    }
}
