package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ServiceDocument(
        String id, String type, String title, String enrollment, List<Representation> representations) {
    public ServiceDocument {
        representations = Copies.nullableList(representations);
    }

    public List<Representation> representations() {
        return representations == null ? null : List.copyOf(representations);
    }

    public record Representation(@JsonProperty("media_type") String mediaType, String url) {}
}
