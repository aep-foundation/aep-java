package foundation.aep.core;

import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.function.Function;

/** JSON encoding and native validation using an application-selected Jackson adapter. */
public final class AepJson {
    private static final String API_KEY_RESPONSE = "API-key Grant response";
    private static final String BASIC_RESPONSE = "Basic Grant response";
    private static final String CLIENT_ASSERTION = "client assertion claims";
    private static final String CREDENTIAL_ID = "credential_id";
    private static final String ENROLL_REQUEST = "Enroll request";
    private static final String ENROLL_RESPONSE = "Enroll response";
    private static final String EXPIRES_AT = "expires_at";
    private static final String GRANT_REQUEST = "Grant request";
    private static final String IDEMPOTENCY_METADATA = "Idempotency metadata";
    private static final String OAUTH_RESPONSE = "OAuth Bearer Grant response";
    private static final String OPENAPI_SCHEME = "OpenAPI AEP security scheme";
    private static final String PROBLEM_DETAILS = "Problem Details";
    private static final String PROTECTED_AUTHORIZATION = "protected-resource authorization";
    private static final String STATUS = "status";
    private static final String STATUS_RESPONSE = "Status response";
    private static final int REQUIRED_PROVIDER_COUNT = 1;
    private static final AepJsonProvider PROVIDER = loadProvider();

    private AepJson() {}

    public static InspectDocument parseInspectDocument(String json) {
        Map<String, Object> value = object(json, "Inspect document");
        AepRawJson.requireMembers(
                value,
                "Inspect document",
                "aep_version",
                "bindings",
                "commands",
                "core",
                "http",
                "identity",
                "service");
        AepRawJson.inspectDocument(value);
        return parse(json, InspectDocument.class, "Inspect document", AepValidation::inspectDocument);
    }

    public static ClaimValues parseClaimValues(String json) {
        AepRawJson.claimValues(object(json, "claim values"));
        return parse(json, ClaimValues.class, "claim values", AepValidation::claimValues);
    }

    public static EnrollRequest parseEnrollRequest(String json) {
        Map<String, Object> value = object(json, ENROLL_REQUEST);
        AepRawJson.requireMembers(value, ENROLL_REQUEST, "agent_did");
        AepRawJson.rejectNullPaths(value, ENROLL_REQUEST, "agent_did", "claims", "idempotency_key");
        return parse(json, EnrollRequest.class, ENROLL_REQUEST, AepValidation::enrollRequest);
    }

    public static EnrollResponse parseEnrollResponse(String json) {
        Map<String, Object> value = object(json, ENROLL_RESPONSE);
        AepRawJson.requireMembers(value, ENROLL_RESPONSE, STATUS);
        AepRawJson.rejectNullPaths(
                value,
                ENROLL_RESPONSE,
                STATUS,
                "owner_action_required",
                "verification_pending",
                "requirements_pending");
        return parse(json, EnrollResponse.class, ENROLL_RESPONSE, AepValidation::enrollResponse);
    }

    public static StatusResponse parseStatusResponse(String json) {
        Map<String, Object> value = object(json, STATUS_RESPONSE);
        AepRawJson.requireMembers(value, STATUS_RESPONSE, STATUS);
        AepRawJson.rejectNullPaths(
                value,
                STATUS_RESPONSE,
                STATUS,
                "owner_action_required",
                "verification_pending",
                "requirements_pending",
                "since");
        return parse(json, StatusResponse.class, STATUS_RESPONSE, AepValidation::statusResponse);
    }

    public static GrantRequest parseGrantRequest(String json) {
        Map<String, Object> value = object(json, GRANT_REQUEST);
        AepRawJson.requireMembers(value, GRANT_REQUEST, "grant_type");
        AepRawJson.rejectNullPaths(value, GRANT_REQUEST, "grant_type", "requested_scopes");
        return parse(json, GrantRequest.class, GRANT_REQUEST, AepValidation::grantRequest);
    }

    public static RevokeRequest parseRevokeRequest(String json) {
        AepRawJson.rejectNullPaths(
                object(json, "Revoke request"), "Revoke request", "grant_type", "credential_id", "all_grant_types");
        return parse(json, RevokeRequest.class, "Revoke request", AepValidation::revokeRequest);
    }

    public static RevokeResponse parseRevokeResponse(String json) {
        if (!object(json, "Revoke response").isEmpty()) {
            throw new AepValidationException(
                    "Revoke response", List.of(new ValidationIssue("$", "Expected an empty object.")));
        }
        return new RevokeResponse();
    }

    public static ClientAssertionClaims parseClientAssertionClaims(String json) {
        Map<String, Object> value = object(json, CLIENT_ASSERTION);
        AepRawJson.requireMembers(value, CLIENT_ASSERTION, "iss", "sub", "aud", "op", "iat", "exp", "jti");
        AepRawJson.rejectNullPaths(value, CLIENT_ASSERTION, "iss", "sub", "aud", "op", "iat", "exp", "jti", "resource");
        return parse(json, ClientAssertionClaims.class, CLIENT_ASSERTION, AepValidation::clientAssertionClaims);
    }

    public static IdempotencyMetadata parseIdempotencyMetadata(String json) {
        Map<String, Object> value = object(json, IDEMPOTENCY_METADATA);
        AepRawJson.requireMembers(value, IDEMPOTENCY_METADATA, "idempotency_key");
        AepRawJson.rejectNullPaths(
                value, IDEMPOTENCY_METADATA, "agent_did", "idempotency_key", "first_body_hash", "second_body_hash");
        return parse(json, IdempotencyMetadata.class, IDEMPOTENCY_METADATA, AepValidation::idempotencyMetadata);
    }

    public static ProblemDetails parseProblemDetails(String json) {
        Map<String, Object> value = object(json, PROBLEM_DETAILS);
        AepRawJson.requireMembers(value, PROBLEM_DETAILS, "type", "title", STATUS, "code");
        AepRawJson.rejectNullPaths(
                value,
                PROBLEM_DETAILS,
                "type",
                "title",
                STATUS,
                "detail",
                "instance",
                "code",
                "owner_action_required",
                "requirements_pending",
                "verification_pending");
        return parse(json, ProblemDetails.class, PROBLEM_DETAILS, AepValidation::problemDetails);
    }

    public static GrantResponses.OAuthBearer parseOAuthBearerGrantResponse(String json) {
        Map<String, Object> value = object(json, OAUTH_RESPONSE);
        AepRawJson.requireMembers(value, OAUTH_RESPONSE, "access_token", CREDENTIAL_ID, EXPIRES_AT, "token_type");
        AepRawJson.rejectNullPaths(value, OAUTH_RESPONSE, "access_token", CREDENTIAL_ID, EXPIRES_AT, "token_type");
        return parse(json, GrantResponses.OAuthBearer.class, OAUTH_RESPONSE, AepValidation::grantResponse);
    }

    public static GrantResponses.ApiKey parseApiKeyGrantResponse(String json) {
        Map<String, Object> value = object(json, API_KEY_RESPONSE);
        AepRawJson.requireMembers(value, API_KEY_RESPONSE, "api_key", CREDENTIAL_ID, EXPIRES_AT, "header");
        AepRawJson.rejectNullPaths(value, API_KEY_RESPONSE, "api_key", CREDENTIAL_ID, EXPIRES_AT, "header");
        return parse(json, GrantResponses.ApiKey.class, API_KEY_RESPONSE, AepValidation::grantResponse);
    }

    public static GrantResponses.Basic parseBasicGrantResponse(String json) {
        Map<String, Object> value = object(json, BASIC_RESPONSE);
        AepRawJson.requireMembers(value, BASIC_RESPONSE, CREDENTIAL_ID, EXPIRES_AT, "password", "username");
        AepRawJson.rejectNullPaths(value, BASIC_RESPONSE, CREDENTIAL_ID, EXPIRES_AT, "password", "realm", "username");
        return parse(json, GrantResponses.Basic.class, BASIC_RESPONSE, AepValidation::grantResponse);
    }

    public static GrantResponses.BuiltIn parseBuiltInGrantResponse(String grantType, String json) {
        if (Aep.GRANT_TYPE_OAUTH_BEARER.equals(grantType)) {
            return parseOAuthBearerGrantResponse(json);
        }
        if (Aep.GRANT_TYPE_API_KEY.equals(grantType)) {
            return parseApiKeyGrantResponse(json);
        }
        if (Aep.GRANT_TYPE_BASIC.equals(grantType)) {
            return parseBasicGrantResponse(json);
        }
        throw new IllegalArgumentException("Unsupported built-in AEP Grant Type: " + grantType);
    }

    public static ProtectedResourceAuthorization parseProtectedResourceAuthorization(String json) {
        Map<String, Object> value = object(json, PROTECTED_AUTHORIZATION);
        AepRawJson.requireMembers(value, PROTECTED_AUTHORIZATION, "carrier", "scheme", "credentials");
        AepRawJson.rejectNullPaths(value, PROTECTED_AUTHORIZATION, "carrier", "scheme", "credentials");
        AepRawJson.protectedResourceAuthorization(value);
        return parse(
                json,
                ProtectedResourceAuthorization.class,
                PROTECTED_AUTHORIZATION,
                AepValidation::protectedResourceAuthorization);
    }

    public static OpenApiAepSecurityScheme parseOpenApiSecurityScheme(String json) {
        Map<String, Object> value = object(json, OPENAPI_SCHEME);
        AepRawJson.requireMembers(value, OPENAPI_SCHEME, "x-aep-authentication-method");
        AepRawJson.rejectNullPaths(value, OPENAPI_SCHEME, "x-aep-authentication-method");
        return parse(json, OpenApiAepSecurityScheme.class, OPENAPI_SCHEME, AepValidation::openApiSecurityScheme);
    }

    public static String write(Object value) {
        return PROVIDER.write(canonicalValue(value));
    }

    private static Object canonicalValue(Object value) {
        if (value instanceof EnrollResponse response) {
            return new EnrollResponse(
                    response.status(),
                    canonicalOwnerAction(response.ownerActionRequired()),
                    canonicalPending(response.verificationPending()),
                    canonicalPending(response.requirementsPending()));
        }
        if (value instanceof StatusResponse response) {
            return new StatusResponse(
                    response.status(),
                    canonicalOwnerAction(response.ownerActionRequired()),
                    canonicalPending(response.verificationPending()),
                    canonicalPending(response.requirementsPending()),
                    response.since());
        }
        if (value instanceof ProblemDetails problem) {
            return new ProblemDetails(
                    problem.type(),
                    problem.title(),
                    problem.status(),
                    problem.detail(),
                    problem.instance(),
                    problem.code(),
                    canonicalOwnerAction(problem.ownerActionRequired()),
                    canonicalPending(problem.requirementsPending()),
                    canonicalPending(problem.verificationPending()));
        }
        return value;
    }

    private static String canonicalOwnerAction(String value) {
        return "false".equals(value) ? null : value;
    }

    private static List<String> canonicalPending(List<String> values) {
        return values != null && values.isEmpty() ? null : values;
    }

    private static <T> T parse(
            String json, Class<T> type, String documentType, Function<T, List<ValidationIssue>> validator) {
        T value;
        try {
            value = PROVIDER.decode(json, type);
        } catch (IllegalArgumentException exception) {
            throw invalidJson(documentType, exception);
        }
        List<ValidationIssue> issues = validator.apply(value);
        if (!issues.isEmpty()) {
            throw new AepValidationException(documentType, issues);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(String json, String documentType) {
        Object value;
        try {
            value = PROVIDER.decode(json, Object.class);
        } catch (IllegalArgumentException exception) {
            throw invalidJson(documentType, exception);
        }
        if (!(value instanceof Map<?, ?>)) {
            throw new AepValidationException(documentType, List.of(new ValidationIssue("$", "Expected an object.")));
        }
        return (Map<String, Object>) value;
    }

    private static AepJsonProvider loadProvider() {
        List<AepJsonProvider> providers = ServiceLoader.load(AepJsonProvider.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
        if (providers.size() != REQUIRED_PROVIDER_COUNT) {
            throw new IllegalStateException(
                    "Exactly one AEP JSON adapter is required; found " + providers.size() + ".");
        }
        return providers.get(0);
    }

    private static AepValidationException invalidJson(String documentType, IllegalArgumentException cause) {
        return new AepValidationException(
                documentType,
                List.of(new ValidationIssue("$", "Expected valid JSON for " + documentType + ".")),
                cause);
    }
}
