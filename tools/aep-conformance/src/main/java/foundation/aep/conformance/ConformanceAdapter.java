package foundation.aep.conformance;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ConformanceAdapter {
    private static final int MAXIMUM_MESSAGE_LENGTH = 1024;
    private static final ObjectMapper JSON =
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private ConformanceAdapter() {}

    public static void main(String[] arguments) throws IOException {
        String role = arguments.length == 1 ? arguments[0] : "";
        if (!"agent".equals(role) && !"platform".equals(role) && !"service".equals(role)) {
            throw new IllegalArgumentException("usage: ConformanceAdapter agent|platform|service");
        }
        try (var reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            while (line != null) {
                if (!line.isBlank()) {
                    AdapterRequest request = JSON.readValue(line, AdapterRequest.class);
                    if (!role.equals(request.role())) {
                        throw new IllegalArgumentException("Adapter request role does not match process role");
                    }
                    System.out.println(JSON.writeValueAsString(evaluate(request))); // NOPMD
                }
                line = reader.readLine();
            }
        }
    }

    private static Map<String, Object> evaluate(AdapterRequest request) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("protocol_version", "1");
        response.put("sequence", request.sequence());
        try {
            boolean passed =
                    switch (request.role()) {
                        case "agent" -> AgentConformance.evaluate(request);
                        case "platform" -> PlatformConformance.evaluate(request);
                        case "service" -> ServiceConformance.evaluate(request);
                        default -> false;
                    };
            response.put("status", passed ? "passed" : "failed");
            if (!passed) response.put("message", "Public Java API result did not match the vector");
        } catch (RuntimeException exception) {
            response.put("status", "failed");
            response.put("message", truncate(exception.getMessage()));
        }
        return response;
    }

    private static String truncate(String value) {
        String message = value == null ? "Conformance evaluation failed" : value;
        return message.length() <= MAXIMUM_MESSAGE_LENGTH ? message : message.substring(0, MAXIMUM_MESSAGE_LENGTH);
    }
}
