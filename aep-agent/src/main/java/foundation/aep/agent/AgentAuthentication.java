package foundation.aep.agent;

import java.util.List;
import java.util.Map;

public record AgentAuthentication(String method, Map<String, List<String>> headers) {
    public AgentAuthentication {
        headers = headers == null
                ? Map.of()
                : headers.entrySet().stream()
                        .collect(java.util.stream.Collectors.toUnmodifiableMap(
                                Map.Entry::getKey, entry -> List.copyOf(entry.getValue())));
    }

    @Override
    public Map<String, List<String>> headers() {
        return headers.entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, entry -> List.copyOf(entry.getValue())));
    }

    @Override
    public String toString() {
        return "AgentAuthentication[method=" + method + ", headerNames=" + headers.keySet() + "]";
    }
}
