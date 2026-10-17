package foundation.aep.json.jackson2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.type.LogicalType;
import foundation.aep.core.AepJsonProvider;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.InspectDocument;

public final class Jackson2JsonProvider implements AepJsonProvider {
    @JsonPOJOBuilder(withPrefix = "")
    private interface BuilderMixin {}

    @JsonDeserialize(builder = InspectDocument.Builder.class)
    private interface InspectDocumentMixin {}

    @JsonDeserialize(builder = ClaimValues.Builder.class)
    private interface ClaimValuesMixin {}

    private final ObjectMapper mapper = JsonMapper.builder()
            .addMixIn(InspectDocument.class, InspectDocumentMixin.class)
            .addMixIn(InspectDocument.Builder.class, BuilderMixin.class)
            .addMixIn(ClaimValues.class, ClaimValuesMixin.class)
            .addMixIn(ClaimValues.Builder.class, BuilderMixin.class)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .withCoercionConfig(
                    LogicalType.Textual,
                    coercion -> coercion.setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
                            .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
                            .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail))
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .build();

    @Override
    public <T> T decode(String json, Class<T> type) {
        try {
            return mapper.readValue(json, type);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Unable to decode AEP JSON", exception);
        }
    }

    @Override
    public String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Unable to encode AEP JSON", exception);
        }
    }
}
