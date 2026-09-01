package foundation.aep.core;

import java.util.List;
import java.util.Map;
import java.util.Set;

final class AepRawJson {
    private static final String INSPECT_DOCUMENT = "Inspect document";
    private static final String NON_NULL_MESSAGE = "Expected a non-null value.";

    private AepRawJson() {}

    static void claimValues(Map<String, Object> value) {
        rejectNullPaths(
                value,
                "claim values",
                "contact.address.primary",
                "contact.email",
                "contact.mobile",
                "person.birthdate",
                "person.first_name",
                "person.last_name",
                "person.username");
        Object address = value.get("contact.address.primary");
        if (address instanceof Map<?, ?> object) {
            if (object.containsKey("postal_code")) {
                throw new AepValidationException(
                        "claim values",
                        List.of(new ValidationIssue(
                                "$.contact.address.primary.postal_code", "Expected the postcode member.")));
            }
            for (String member : List.of(
                    "city", "country", "first_name", "last_name", "line1", "line2", "line3", "postcode", "region")) {
                if (object.containsKey(member) && object.get(member) == null) {
                    throw new AepValidationException(
                            "claim values",
                            List.of(new ValidationIssue("$.contact.address.primary." + member, NON_NULL_MESSAGE)));
                }
            }
        }
    }

    static void inspectDocument(Map<String, Object> value) {
        rejectNullPaths(
                value,
                INSPECT_DOCUMENT,
                "aep_version",
                "authentication",
                "bindings",
                "claims",
                "commands",
                "core",
                "extensions",
                "http",
                "identity",
                "service");
        closedObject(value.get("authentication"), "$.authentication", Set.of("methods"));
        rejectKnownNulls(value.get("bindings"), "$.bindings", "supported");
        rejectKnownNulls(value.get("claims"), "$.claims", "required", "preferred", "optional");
        rejectKnownNulls(value.get("commands"), "$.commands", "supported", "grant_types", "grant_types_config");
        rejectKnownNulls(value.get("core"), "$.core", "signing_algorithms");
        rejectKnownNulls(value.get("extensions"), "$.extensions", "supported");
        rejectKnownNulls(value.get("identity"), "$.identity", "methods");
        rejectKnownNulls(value.get("service"), "$.service", "did");
        Object http = value.get("http");
        if (http instanceof Map<?, ?> httpObject) {
            rejectKnownNulls(http, "$.http", "endpoint_base", "openapi");
            Object openapi = httpObject.get("openapi");
            closedObject(openapi, "$.http.openapi", Set.of("url", "path_matching"));
            if (openapi instanceof Map<?, ?> openapiObject) {
                closedObject(
                        openapiObject.get("path_matching"), "$.http.openapi.path_matching", Set.of("trailing_slash"));
            }
        }
    }

    static void protectedResourceAuthorization(Map<String, Object> value) {
        for (String member : value.keySet()) {
            if (!Set.of("carrier", "scheme", "credentials").contains(member)) {
                throw new AepValidationException(
                        "protected-resource authorization",
                        List.of(new ValidationIssue("$", "Expected no unknown members.")));
            }
        }
    }

    static void rejectNullPaths(Map<String, Object> value, String documentType, String... members) {
        for (String member : members) {
            if (value.containsKey(member) && value.get(member) == null) {
                throw new AepValidationException(
                        documentType, List.of(new ValidationIssue("$." + member, NON_NULL_MESSAGE)));
            }
        }
    }

    static void requireMembers(Map<String, Object> value, String documentType, String... members) {
        for (String member : members) {
            if (!value.containsKey(member)) {
                throw new AepValidationException(
                        documentType, List.of(new ValidationIssue("$." + member, "Expected a required member.")));
            }
        }
    }

    private static void closedObject(Object value, String path, Set<String> allowed) {
        if (!(value instanceof Map<?, ?> object)) {
            return;
        }
        for (Object key : object.keySet()) {
            if (!(key instanceof String name) || !allowed.contains(name)) {
                throw new AepValidationException(
                        INSPECT_DOCUMENT, List.of(new ValidationIssue(path, "Expected no unknown members.")));
            }
        }
        for (Map.Entry<?, ?> entry : object.entrySet()) {
            if (entry.getValue() == null) {
                throw new AepValidationException(
                        INSPECT_DOCUMENT, List.of(new ValidationIssue(path + "." + entry.getKey(), NON_NULL_MESSAGE)));
            }
        }
    }

    private static void rejectKnownNulls(Object value, String path, String... members) {
        if (!(value instanceof Map<?, ?> object)) {
            return;
        }
        for (String member : members) {
            if (object.containsKey(member) && object.get(member) == null) {
                throw new AepValidationException(
                        INSPECT_DOCUMENT, List.of(new ValidationIssue(path + "." + member, NON_NULL_MESSAGE)));
            }
        }
    }
}
