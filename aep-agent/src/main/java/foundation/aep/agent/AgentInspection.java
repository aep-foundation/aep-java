package foundation.aep.agent;

import foundation.aep.core.InspectDocument;
import java.net.URI;
import java.util.Objects;

public record AgentInspection(URI origin, URI documentUri, InspectDocument document) {
    public AgentInspection {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(documentUri, "documentUri");
        Objects.requireNonNull(document, "document");
    }
}
