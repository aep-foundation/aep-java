package foundation.aep.conformance;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

record AdapterRequest(
        int sequence,
        String role,
        String profile,
        String expectation,
        Vector vector,
        @JsonProperty("case") TestCase testCase) {
    record Vector(String category, String id) {}

    record TestCase(JsonNode input, JsonNode expected) {}
}
