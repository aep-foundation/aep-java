package foundation.aep.platform;

import foundation.aep.core.ProblemDetails;
import java.util.List;
import java.util.Map;

public record PlatformResponse<T>(
        int status, String contentType, T body, ProblemDetails problem, Map<String, List<String>> headers) {
    public PlatformResponse {
        headers = PlatformCopies.headers(headers);
    }

    @Override
    public Map<String, List<String>> headers() {
        return PlatformCopies.headers(headers);
    }
}
