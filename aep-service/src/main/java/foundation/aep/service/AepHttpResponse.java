package foundation.aep.service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record AepHttpResponse(int status, String contentType, Map<String, List<String>> headers, byte[] body) {
    public AepHttpResponse {
        if (status < 100 || status > 599) throw new IllegalArgumentException("HTTP status is invalid.");
        Objects.requireNonNull(contentType, "contentType");
        headers = ServiceCopies.headers(headers);
        body = body == null ? new byte[0] : body.clone();
    }

    @Override
    public Map<String, List<String>> headers() {
        return ServiceCopies.headers(headers);
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    public String bodyText() {
        return new String(body, StandardCharsets.UTF_8);
    }
}
