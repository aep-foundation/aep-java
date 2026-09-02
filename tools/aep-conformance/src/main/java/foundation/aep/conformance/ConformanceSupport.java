package foundation.aep.conformance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.aep.core.AepJson;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

final class ConformanceSupport {
    static final ObjectMapper MAPPER = new ObjectMapper();

    private ConformanceSupport() {}

    static JsonNode required(JsonNode object, String name) {
        JsonNode value = object.get(name);
        if (value == null) throw new IllegalArgumentException("Required field is missing: " + name);
        return value;
    }

    static String text(JsonNode object, String name) {
        return required(object, name).asText();
    }

    static List<String> strings(JsonNode object, String name) {
        JsonNode values = object.get(name);
        if (values == null) return List.of();
        List<String> result = new ArrayList<>();
        values.forEach(value -> result.add(value.asText()));
        return List.copyOf(result);
    }

    static boolean valid(AdapterRequest request) {
        return required(request.testCase().expected(), "valid").asBoolean();
    }

    static boolean parseValidity(AdapterRequest request, String field, Function<String, ?> parser) {
        boolean parsed;
        try {
            parser.apply(required(request.testCase().input(), field).toString());
            parsed = true;
        } catch (RuntimeException exception) {
            parsed = false;
        }
        return parsed == valid(request);
    }

    static boolean expectedBody(AdapterRequest request, Function<String, ?> parser) {
        JsonNode expected = required(request.testCase().expected(), "body");
        Object value = parser.apply(expected.toString());
        return json(AepJson.write(value)).equals(expected);
    }

    static JsonNode json(String value) {
        try {
            return MAPPER.readTree(value);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Unable to decode JSON", exception);
        }
    }

    static boolean jsonEquals(Object value, JsonNode expected) {
        return json(AepJson.write(value)).equals(expected);
    }

    static IllegalArgumentException unmapped(AdapterRequest request) {
        return new IllegalArgumentException("No " + request.role() + " operation maps vector "
                + request.vector().category() + "/" + request.vector().id());
    }
}
