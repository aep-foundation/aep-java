package foundation.aep.json.jackson3;

import com.fasterxml.jackson.annotation.JsonInclude;
import foundation.aep.core.AepJsonProvider;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.InspectDocument;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonPOJOBuilder;
import tools.jackson.databind.json.JsonMapper;

public final class Jackson3JsonProvider implements AepJsonProvider {
    @JsonPOJOBuilder(withPrefix = "")
    private interface BuilderMixin {}

    @JsonDeserialize(builder = InspectDocument.Builder.class)
    private interface InspectDocumentMixin {}

    @JsonDeserialize(builder = ClaimValues.Builder.class)
    private interface ClaimValuesMixin {}

    private final JsonMapper mapper = JsonMapper.builder()
            .addMixIn(InspectDocument.class, InspectDocumentMixin.class)
            .addMixIn(InspectDocument.Builder.class, BuilderMixin.class)
            .addMixIn(ClaimValues.class, ClaimValuesMixin.class)
            .addMixIn(ClaimValues.Builder.class, BuilderMixin.class)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .changeDefaultPropertyInclusion(inclusion -> inclusion.withValueInclusion(JsonInclude.Include.NON_NULL))
            .build();

    @Override
    public <T> T decode(String json, Class<T> type) {
        try {
            return mapper.readValue(json, type);
        } catch (JacksonException exception) {
            throw new IllegalArgumentException("Unable to decode AEP JSON", exception);
        }
    }

    @Override
    public String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JacksonException exception) {
            throw new IllegalArgumentException("Unable to encode AEP JSON", exception);
        }
    }
}
