package foundation.aep.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record AepHttpRequest(String method, URI url, Map<String, List<String>> headers, byte[] body) {
    public AepHttpRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(url, "url");
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

    public List<String> headerValues(String name) {
        Objects.requireNonNull(name, "name");
        List<String> values = new ArrayList<>();
        headers.forEach((candidate, candidateValues) -> {
            if (candidate.equalsIgnoreCase(name)) values.addAll(candidateValues);
        });
        return List.copyOf(values);
    }

    public static URI publicUrl(URI publicOrigin, String rawPath, String rawQuery) {
        if (publicOrigin == null
                || !("https".equalsIgnoreCase(publicOrigin.getScheme())
                        || "http".equalsIgnoreCase(publicOrigin.getScheme()))
                || publicOrigin.getHost() == null
                || publicOrigin.getUserInfo() != null
                || !(publicOrigin.getRawPath() == null
                        || publicOrigin.getRawPath().isEmpty()
                        || "/".equals(publicOrigin.getRawPath()))
                || publicOrigin.getRawQuery() != null
                || publicOrigin.getRawFragment() != null) {
            throw new IllegalArgumentException("publicOrigin must be an HTTP origin.");
        }
        if (rawPath == null || !rawPath.startsWith("/") || rawPath.startsWith("//")) {
            throw new IllegalArgumentException("rawPath must be an absolute path.");
        }
        try {
            return new URI(
                    publicOrigin.getScheme(),
                    null,
                    publicOrigin.getHost(),
                    publicOrigin.getPort(),
                    rawPath,
                    rawQuery,
                    null);
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Request target is invalid.", exception);
        }
    }
}
