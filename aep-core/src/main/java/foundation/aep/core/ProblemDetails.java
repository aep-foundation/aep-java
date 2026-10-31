package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ProblemDetails(
        String type,
        String title,
        int status,
        String detail,
        String instance,
        String code,
        @JsonProperty("owner_action_required") String ownerActionRequired,
        @JsonProperty("requirements_pending") List<String> requirementsPending,
        @JsonProperty("verification_pending") List<String> verificationPending,
        @JsonProperty("required_document_ids") List<String> requiredDocumentIds) {
    public ProblemDetails {
        requirementsPending = Copies.nullableList(requirementsPending);
        verificationPending = Copies.nullableList(verificationPending);
        requiredDocumentIds = Copies.nullableList(requiredDocumentIds);
    }

    public ProblemDetails(
            String type,
            String title,
            int status,
            String detail,
            String instance,
            String code,
            String ownerActionRequired,
            List<String> requirementsPending,
            List<String> verificationPending) {
        this(
                type,
                title,
                status,
                detail,
                instance,
                code,
                ownerActionRequired,
                requirementsPending,
                verificationPending,
                null);
    }

    public static ProblemDetails of(String code, String title, int status) {
        return new ProblemDetails("urn:aep:error:" + code, title, status, null, null, code, null, null, null);
    }
}
