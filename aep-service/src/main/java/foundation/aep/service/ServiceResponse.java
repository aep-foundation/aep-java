package foundation.aep.service;

import foundation.aep.core.ProblemDetails;
import java.util.List;
import java.util.Map;

public record ServiceResponse<T>(
        int status, String contentType, T body, ProblemDetails problem, Map<String, List<String>> headers) {
    public ServiceResponse {
        headers = ServiceCopies.headers(headers);
    }

    @Override
    public Map<String, List<String>> headers() {
        return ServiceCopies.headers(headers);
    }

    public static <T> ServiceResponse<T> success(T body) {
        return new ServiceResponse<>(200, foundation.aep.core.Aep.MEDIA_TYPE, body, null, Map.of());
    }
}
