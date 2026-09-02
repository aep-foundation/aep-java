package foundation.aep.core;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public final class AepValidation {
    private static final Pattern VERSION = Pattern.compile("^(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$");
    private static final Pattern ADVERTISEMENT = Pattern.compile("^[a-z0-9]+(?:-[a-z0-9]+)*$");
    private static final Pattern IDENTITY_METHOD = Pattern.compile("^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$");
    private static final Pattern CLAIM_NAME = Pattern.compile("^[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)*$");
    private static final Pattern COUNTRY = Pattern.compile("^[A-Z]{2}$");
    private static final Pattern E164 = Pattern.compile("^\\+[1-9][0-9]{1,14}$");
    private static final Pattern BODY_HASH = Pattern.compile("^sha256:[0-9a-f]{64}$");
    private static final Pattern ERROR_CODE = Pattern.compile("^[a-z][a-z0-9_]*$");
    private static final Pattern HTTP_FIELD_NAME = Pattern.compile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");
    private static final Pattern ATEXT = Pattern.compile("[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~]+");
    private static final Set<String> AUTHENTICATED_COMMANDS = Set.of("enroll", "grant", "revoke", "status");
    private static final String COMMANDS_SUPPORTED_PATH = "$.commands.supported";
    private static final String AGENT_DID_PATH = "$.agent_did";
    private static final String OPERATION_PATH = "$.op";
    private static final String OPERATION_REQUIRED = "Expected a registered assertion operation.";
    private static final String RESOURCE_PATH = "$.resource";
    private static final String SERVICE_DID_PATH = "$.service_did";
    private static final String STATUS_PATH = "$.status";
    private static final String JSON_OBJECT = "object";
    private static final String HTTPS = "https";
    private static final String TRUE = "true";
    private static final int MAX_AUTHENTICATION_METHODS = 16;
    private static final int IPV4_OCTETS = 4;
    private static final int MAX_IPV6_SECTIONS = 2;
    private static final char BACKSLASH = '\\';
    private static final char QUOTE = '"';

    private AepValidation() {}

    public static List<ValidationIssue> inspectDocument(InspectDocument value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        if (!isCompatibleVersion(value.version())) {
            issues.add("$.aep_version", "Expected a supported AEP major.minor version.");
        }
        validateAuthentication(value.authentication(), issues);
        validateBindings(value.bindings(), issues);
        validateClaimsAdvertisement(value.claims(), issues);
        validateCommands(value.commands(), issues);
        validateCore(value.core(), issues);
        validateExtensions(value.extensions(), issues);
        validateHttp(value.http(), issues);
        validateIdentity(value.identity(), value.commands(), issues);
        if (value.service() == null
                || !nonEmpty(value.service().did())
                || !value.service().did().startsWith("did:")) {
            issues.add("$.service.did", "Expected a DID string.");
        }
        return issues.values();
    }

    public static InspectDocument requireInspectDocument(InspectDocument value) {
        return require("Inspect document", value, inspectDocument(value));
    }

    public static boolean isCompatibleVersion(String received) {
        if (received == null || !VERSION.matcher(received).matches()) {
            return false;
        }
        return received.substring(0, received.indexOf('.')).equals(Aep.VERSION.substring(0, Aep.VERSION.indexOf('.')));
    }

    public static List<ValidationIssue> claimValues(ClaimValues value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        ContactAddressPrimary address = value.contactAddressPrimary();
        if (address != null) {
            optionalNonEmpty(address.city(), "$.contact.address.primary.city", issues);
            matches(address.country(), COUNTRY, "$.contact.address.primary.country", issues);
            requiredNonEmpty(address.firstName(), "$.contact.address.primary.first_name", issues);
            requiredNonEmpty(address.lastName(), "$.contact.address.primary.last_name", issues);
            requiredNonEmpty(address.line1(), "$.contact.address.primary.line1", issues);
        }
        optional(
                value.contactEmail(),
                "$.contact.email",
                AepValidation::isMailbox,
                "Expected an RFC 5321 Mailbox.",
                issues);
        optional(
                value.contactMobile(),
                "$.contact.mobile",
                E164.asMatchPredicate(),
                "Expected an E.164 number.",
                issues);
        optional(
                value.personBirthdate(),
                "$.person.birthdate",
                AepValidation::isFullDate,
                "Expected an RFC 3339 full-date.",
                issues);
        optionalNonEmpty(value.personFirstName(), "$.person.first_name", issues);
        optionalNonEmpty(value.personLastName(), "$.person.last_name", issues);
        optionalNonEmpty(value.personUsername(), "$.person.username", issues);
        return issues.values();
    }

    public static ClaimValues requireClaimValues(ClaimValues value) {
        return require("claim values", value, claimValues(value));
    }

    public static List<ValidationIssue> enrollRequest(EnrollRequest value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        requiredNonEmpty(value.agentDid(), AGENT_DID_PATH, issues);
        if (value.claims() != null) {
            issues.prefix("$.claims", claimValues(value.claims()));
        }
        optionalNonEmpty(value.idempotencyKey(), "$.idempotency_key", issues);
        return issues.values();
    }

    public static List<ValidationIssue> enrollResponse(EnrollResponse value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        if (value.status() == null) {
            issues.add(STATUS_PATH, "Expected a registered Agent status.");
        }
        lifecycleMetadata(
                value.ownerActionRequired(), value.verificationPending(), value.requirementsPending(), issues);
        return issues.values();
    }

    public static List<ValidationIssue> statusResponse(StatusResponse value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        if (value.status() == null) {
            issues.add(STATUS_PATH, "Expected a registered Agent status.");
        }
        lifecycleMetadata(
                value.ownerActionRequired(), value.verificationPending(), value.requirementsPending(), issues);
        if (value.since() != null && !isDateTime(value.since())) {
            issues.add("$.since", "Expected an RFC 3339 date-time.");
        }
        return issues.values();
    }

    public static List<ValidationIssue> grantRequest(GrantRequest value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        requiredNonEmpty(value.grantType(), "$.grant_type", issues);
        strings(value.requestedScopes(), "$.requested_scopes", false, false, issues);
        return issues.values();
    }

    public static List<ValidationIssue> revokeRequest(RevokeRequest value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        optionalNonEmpty(value.grantType(), "$.grant_type", issues);
        optionalNonEmpty(value.credentialId(), "$.credential_id", issues);
        if (value.allGrantTypes() != null && !"true".equals(value.allGrantTypes())) {
            issues.add("$.all_grant_types", "Expected true.");
        }
        boolean hasAll = value.allGrantTypes() != null;
        boolean hasCredential = value.credentialId() != null;
        boolean hasGrant = value.grantType() != null;
        if ((!hasAll && !hasGrant) || (hasAll && (hasCredential || hasGrant)) || (hasCredential && !hasGrant)) {
            issues.add("$", "Expected grant_type, grant_type with credential_id, or all_grant_types.");
        }
        return issues.values();
    }

    public static List<ValidationIssue> clientAssertionClaims(ClientAssertionClaims value) {
        return clientAssertionClaims(value, false);
    }

    public static ClientAssertionClaims requireClientAssertionClaims(
            ClientAssertionClaims value, boolean allowInsecureLoopback) {
        return require("client assertion claims", value, clientAssertionClaims(value, allowInsecureLoopback));
    }

    public static List<ValidationIssue> clientAssertionClaims(
            ClientAssertionClaims value, boolean allowInsecureLoopback) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        requiredNonEmpty(value.issuer(), "$.iss", issues);
        requiredNonEmpty(value.subject(), "$.sub", issues);
        requiredNonEmpty(value.audience(), "$.aud", issues);
        requiredNonEmpty(value.jwtId(), "$.jti", issues);
        if (value.operation() == null) {
            issues.add(OPERATION_PATH, OPERATION_REQUIRED);
        }
        if (nonEmpty(value.issuer())
                && nonEmpty(value.subject())
                && !value.issuer().equals(value.subject())) {
            issues.add("$.sub", "Expected sub to equal iss.");
        }
        long maximumLifetime = Aep.MAX_ASSERTION_LIFETIME.toSeconds();
        if (value.expiresAt() <= value.issuedAt()
                || (value.issuedAt() <= Long.MAX_VALUE - maximumLifetime
                        && value.expiresAt() > value.issuedAt() + maximumLifetime)) {
            issues.add("$.exp", "Expected an assertion lifetime between 1 and 300 seconds.");
        }
        if (value.operation() == AssertionOperation.AUTHENTICATE) {
            if (!isProtectedResourceUri(value.resource(), allowInsecureLoopback)) {
                issues.add(RESOURCE_PATH, "Expected an absolute HTTPS URI without a fragment.");
            }
        } else if (value.resource() != null) {
            issues.add(RESOURCE_PATH, "resource is only valid for authenticate.");
        }
        return issues.values();
    }

    public static List<ValidationIssue> idempotencyMetadata(IdempotencyMetadata value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        optionalNonEmpty(value.agentDid(), "$.agent_did", issues);
        requiredNonEmpty(value.idempotencyKey(), "$.idempotency_key", issues);
        optionalMatch(value.firstBodyHash(), BODY_HASH, "$.first_body_hash", issues);
        optionalMatch(value.secondBodyHash(), BODY_HASH, "$.second_body_hash", issues);
        return issues.values();
    }

    public static List<ValidationIssue> problemDetails(ProblemDetails value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        requiredNonEmpty(value.code(), "$.code", issues);
        requiredNonEmpty(value.title(), "$.title", issues);
        if (value.code() != null && !ERROR_CODE.matcher(value.code()).matches()) {
            issues.add("$.code", "Expected a syntactically valid AEP error code.");
        }
        if (!nonEmpty(value.code()) || !("urn:aep:error:" + value.code()).equals(value.type())) {
            issues.add("$.type", "Expected an AEP error URN matching code.");
        }
        if (value.ownerActionRequired() != null && !"true".equals(value.ownerActionRequired())) {
            issues.add("$.owner_action_required", "Expected true.");
        }
        strings(value.requirementsPending(), "$.requirements_pending", true, true, issues);
        strings(value.verificationPending(), "$.verification_pending", true, true, issues);
        if ("not_recognized".equals(value.code())
                && (value.ownerActionRequired() != null
                        || value.requirementsPending() != null
                        || value.verificationPending() != null)) {
            issues.add("$", "not_recognized must not expose pending or owner-action metadata.");
        }
        return issues.values();
    }

    public static List<ValidationIssue> platformDiscoveryDocument(PlatformDiscoveryDocument value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        if (!isCompatibleVersion(value.version())) {
            issues.add("$.aep_version", "Expected a supported AEP major.minor version.");
        }
        PlatformDiscoveryDocument.Endpoints endpoints = value.endpoints();
        if (endpoints == null) {
            issues.required("$.endpoints", JSON_OBJECT);
        } else {
            optionalEndpoint(endpoints.hostedVerification(), "$.endpoints.hosted_verification", issues);
            requiredEndpointTemplate(endpoints.lifecycle(), "{agent_identity_id}", "$.endpoints.lifecycle", issues);
            requiredEndpoint(endpoints.list(), "$.endpoints.list", issues);
            requiredEndpoint(endpoints.provision(), "$.endpoints.provision", issues);
            requiredEndpointTemplate(endpoints.sign(), "{agent_identity_id}", "$.endpoints.sign", issues);
        }
        if (value.http() == null) {
            issues.required("$.http", JSON_OBJECT);
        } else {
            requiredEndpoint(value.http().endpointBase(), "$.http.endpoint_base", issues);
        }
        PlatformDiscoveryDocument.Identity identity = value.identity();
        if (identity == null) {
            issues.required("$.identity", JSON_OBJECT);
        } else {
            strings(identity.didMethods(), "$.identity.did_methods", true, true, issues);
            if (identity.didUrlTemplate() == null
                    || !identity.didUrlTemplate().contains("{agent_did_id}")
                    || !isAbsoluteHttpsUri(identity.didUrlTemplate().replace("{agent_did_id}", "validation"))) {
                issues.add("$.identity.did_url_template", "Expected an absolute HTTPS URL template.");
            }
        }
        PlatformDiscoveryDocument.Platform platform = value.platform();
        if (platform == null) {
            issues.required("$.platform", JSON_OBJECT);
        } else {
            if (platform.did() != null && !platform.did().startsWith("did:")) {
                issues.add("$.platform.did", "Expected a DID string.");
            }
            requiredNonEmpty(platform.name(), "$.platform.name", issues);
        }
        PlatformDiscoveryDocument.Signing signing = value.signing();
        if (signing == null) {
            issues.required("$.signing", JSON_OBJECT);
        } else {
            signingAlgorithms(signing.algorithms(), "$.signing.algorithms", issues);
            positiveIntegerString(signing.defaultLifetimeSeconds(), 300, "$.signing.default_lifetime_seconds", issues);
        }
        return issues.values();
    }

    public static PlatformDiscoveryDocument requirePlatformDiscoveryDocument(PlatformDiscoveryDocument value) {
        return require("Platform discovery document", value, platformDiscoveryDocument(value));
    }

    public static List<ValidationIssue> platformAgentIdentity(PlatformAgentIdentity value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        requiredDid(value.agentDid(), AGENT_DID_PATH, issues);
        requiredNonEmpty(value.agentIdentityId(), "$.agent_identity_id", issues);
        requiredDateTime(value.createdAt(), "$.created_at", issues);
        if (!isAbsoluteHttpsUri(value.didDocumentUrl())) {
            issues.add("$.did_document_url", "Expected an absolute HTTPS URI.");
        }
        requiredNonEmpty(value.keyId(), "$.key_id", issues);
        requiredDid(value.serviceDid(), SERVICE_DID_PATH, issues);
        signingAlgorithms(value.signingAlgorithms(), "$.signing_algorithms", issues);
        if (value.status() == null) issues.add(STATUS_PATH, "Expected a managed Agent status.");
        requiredDateTime(value.updatedAt(), "$.updated_at", issues);
        return issues.values();
    }

    public static PlatformAgentIdentity requirePlatformAgentIdentity(PlatformAgentIdentity value) {
        return require("Platform Agent identity", value, platformAgentIdentity(value));
    }

    public static List<ValidationIssue> platformAgentIdentityListResponse(PlatformAgentIdentityListResponse value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        nonNegativeIntegerString(value.count(), "$.count", issues);
        nonNegativeIntegerString(value.total(), "$.total", issues);
        if (value.data() == null) {
            issues.required("$.data", "array");
        } else {
            for (int index = 0; index < value.data().size(); index++) {
                issues.prefix(
                        "$.data[" + index + "]",
                        platformAgentIdentity(value.data().get(index)));
            }
            if (nonNegativeInteger(value.count()) != value.data().size()) {
                issues.add("$.count", "Expected count to equal the number of data entries.");
            }
        }
        return issues.values();
    }

    public static List<ValidationIssue> platformProvisionRequest(PlatformProvisionRequest value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        requiredDid(value.serviceDid(), SERVICE_DID_PATH, issues);
        return issues.values();
    }

    public static List<ValidationIssue> platformLifecycleRequest(PlatformLifecycleRequest value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        if (value.status() == null) issues.add(STATUS_PATH, "Expected a managed Agent status.");
        return issues.values();
    }

    public static List<ValidationIssue> platformSignRequest(PlatformSignRequest value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        requiredNonEmpty(value.jwtId(), "$.jti", issues);
        if (value.operation() == null) issues.add(OPERATION_PATH, OPERATION_REQUIRED);
        requiredDid(value.serviceDid(), SERVICE_DID_PATH, issues);
        if (value.lifetimeSeconds() != null) {
            positiveIntegerString(value.lifetimeSeconds(), 300, "$.lifetime_seconds", issues);
        }
        operationResource(value.operation(), value.resource(), RESOURCE_PATH, issues);
        return issues.values();
    }

    public static List<ValidationIssue> platformSignResponse(PlatformSignResponses.Response value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        if (value instanceof PlatformSignResponses.Completed completed) {
            if (!"completed".equals(completed.status())) issues.add(STATUS_PATH, "Expected completed.");
            requiredDid(completed.agentDid(), AGENT_DID_PATH, issues);
            requiredNonEmpty(completed.clientAssertion(), "$.client_assertion", issues);
            requiredDateTime(completed.expiresAt(), "$.expires_at", issues);
            requiredDateTime(completed.issuedAt(), "$.issued_at", issues);
            requiredNonEmpty(completed.jwtId(), "$.jti", issues);
            requiredDid(completed.serviceDid(), SERVICE_DID_PATH, issues);
        } else if (value instanceof PlatformSignResponses.Pending pending) {
            if (!"pending".equals(pending.status())) issues.add(STATUS_PATH, "Expected pending.");
            positiveIntegerString(pending.retryAfterSeconds(), 300, "$.retry_after_seconds", issues);
        }
        return issues.values();
    }

    public static PlatformSignResponses.Response requirePlatformSignResponse(PlatformSignResponses.Response value) {
        return require("Platform sign response", value, platformSignResponse(value));
    }

    public static List<ValidationIssue> platformVerificationRequest(PlatformVerificationRequest value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        requiredNonEmpty(value.clientAssertion(), "$.client_assertion", issues);
        if (value.operation() == null) issues.add(OPERATION_PATH, OPERATION_REQUIRED);
        requiredDid(value.serviceDid(), SERVICE_DID_PATH, issues);
        operationResource(value.operation(), value.resource(), RESOURCE_PATH, issues);
        return issues.values();
    }

    public static List<ValidationIssue> platformVerificationResponse(PlatformVerificationResponse value) {
        Issues issues = new Issues();
        if (value == null) return issues.required("$", JSON_OBJECT).values();
        requiredDid(value.serviceDid(), SERVICE_DID_PATH, issues);
        if (value.verified()) {
            requiredDid(value.agentDid(), AGENT_DID_PATH, issues);
            requiredNonEmpty(value.agentIdentityId(), "$.agent_identity_id", issues);
            if (value.operation() == null) issues.add(OPERATION_PATH, OPERATION_REQUIRED);
            if (!"verified".equals(value.reason())) issues.add("$.reason", "Expected verified.");
            if (value.status() == null) issues.add(STATUS_PATH, "Expected a managed Agent status.");
        } else {
            if (!"not_recognized".equals(value.reason())) issues.add("$.reason", "Expected not_recognized.");
            if (value.agentDid() != null
                    || value.agentIdentityId() != null
                    || value.operation() != null
                    || value.status() != null) {
                issues.add("$", "An unrecognized response must not disclose identity details.");
            }
        }
        return issues.values();
    }

    public static List<ValidationIssue> grantResponse(GrantResponses.BuiltIn value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        requiredNonEmpty(value.credentialId(), "$.credential_id", issues);
        if (!isDateTime(value.expiresAt())) {
            issues.add("$.expires_at", "Expected an RFC 3339 date-time.");
        }
        strings(value.scopes(), "$.scopes", false, false, issues);
        if (value instanceof GrantResponses.OAuthBearer bearer) {
            requiredNonEmpty(bearer.accessToken(), "$.access_token", issues);
            if (!"Bearer".equals(bearer.tokenType())) {
                issues.add("$.token_type", "Expected Bearer.");
            }
        } else if (value instanceof GrantResponses.ApiKey apiKey) {
            requiredNonEmpty(apiKey.apiKey(), "$.api_key", issues);
            requiredNonEmpty(apiKey.header(), "$.header", issues);
            if (nonEmpty(apiKey.apiKey()) && !isApiKeyValue(apiKey.apiKey())) {
                issues.add("$.api_key", "Expected an unambiguous HTTP field value.");
            }
            if (nonEmpty(apiKey.header())
                    && !HTTP_FIELD_NAME.matcher(apiKey.header()).matches()) {
                issues.add("$.header", "Expected an HTTP field name.");
            }
        } else if (value instanceof GrantResponses.Basic basic) {
            requiredNonEmpty(basic.password(), "$.password", issues);
            requiredNonEmpty(basic.username(), "$.username", issues);
            optionalNonEmpty(basic.realm(), "$.realm", issues);
            if (nonEmpty(basic.username())
                    && (basic.username().indexOf(':') >= 0 || containsControlCharacter(basic.username()))) {
                issues.add("$.username", "Expected an RFC 7617 username without a colon or control character.");
            }
            if (nonEmpty(basic.password()) && containsControlCharacter(basic.password())) {
                issues.add("$.password", "Expected a value without control characters.");
            }
        }
        return issues.values();
    }

    public static List<ValidationIssue> protectedResourceAuthorization(ProtectedResourceAuthorization value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        if (value.carrier() == null) {
            issues.add("$.carrier", "Expected a registered authorization carrier.");
        }
        if (value.scheme() == null) {
            issues.add("$.scheme", "Expected a registered authorization scheme.");
        }
        requiredNonEmpty(value.credentials(), "$.credentials", issues);
        return issues.values();
    }

    public static List<ValidationIssue> openApiSecurityScheme(OpenApiAepSecurityScheme value) {
        Issues issues = new Issues();
        if (value == null) {
            return issues.required("$", JSON_OBJECT).values();
        }
        if (value.authenticationMethod() == null
                || !ADVERTISEMENT.matcher(value.authenticationMethod()).matches()) {
            issues.add("$.x-aep-authentication-method", "Expected a syntactically valid AEP identifier.");
        }
        return issues.values();
    }

    private static void validateAuthentication(InspectDocument.Authentication value, Issues issues) {
        if (value == null) {
            return;
        }
        strings(value.methods(), "$.authentication.methods", true, true, issues);
        if (value.methods().size() > MAX_AUTHENTICATION_METHODS) {
            issues.add("$.authentication.methods", "Expected at most 16 items.");
        }
        matchItems(value.methods(), ADVERTISEMENT, "$.authentication.methods", issues);
    }

    private static void validateBindings(InspectDocument.Bindings value, Issues issues) {
        if (value == null) {
            issues.required("$.bindings", JSON_OBJECT);
            return;
        }
        strings(value.supported(), "$.bindings.supported", true, false, issues);
        matchItems(value.supported(), ADVERTISEMENT, "$.bindings.supported", issues);
        if (!value.supported().contains("http")) {
            issues.add("$.bindings.supported", "Expected http to be advertised.");
        }
    }

    private static void validateClaimsAdvertisement(InspectDocument.Claims value, Issues issues) {
        if (value == null) {
            return;
        }
        matchItems(value.required(), CLAIM_NAME, "$.claims.required", issues);
        matchItems(value.preferred(), CLAIM_NAME, "$.claims.preferred", issues);
        matchItems(value.optional(), CLAIM_NAME, "$.claims.optional", issues);
    }

    private static void validateCommands(InspectDocument.Commands value, Issues issues) {
        if (value == null) {
            issues.required("$.commands", JSON_OBJECT);
            return;
        }
        strings(value.supported(), COMMANDS_SUPPORTED_PATH, true, false, issues);
        matchItems(value.supported(), ADVERTISEMENT, COMMANDS_SUPPORTED_PATH, issues);
        if (!value.supported().contains("inspect")) {
            issues.add(COMMANDS_SUPPORTED_PATH, "Expected inspect to be advertised.");
        }
        if (value.supported().contains("authenticate")) {
            issues.add(COMMANDS_SUPPORTED_PATH, "authenticate is an assertion operation, not a command.");
        }
        matchItems(value.grantTypes(), ADVERTISEMENT, "$.commands.grant_types", issues);
        if ((value.supported().contains("grant") || value.supported().contains("revoke"))
                && value.grantTypes().isEmpty()) {
            issues.add("$.commands.grant_types", "Expected at least one advertised grant type.");
        }
        for (Map.Entry<String, InspectDocument.GrantTypeConfig> entry :
                value.grantTypesConfig().entrySet()) {
            String path = "$.commands.grant_types_config." + entry.getKey();
            if (!ADVERTISEMENT.matcher(entry.getKey()).matches()) {
                issues.add(path, "Expected a syntactically valid grant type.");
            }
            if (!value.grantTypes().contains(entry.getKey())) {
                issues.add(path, "Expected configuration for an advertised grant type.");
            }
            String supported =
                    entry.getValue() == null ? null : entry.getValue().supportsPerCredentialRevoke();
            if (supported != null && !TRUE.equals(supported) && !"false".equals(supported)) {
                issues.add(path + ".supports_per_credential_revoke", "Expected false or true.");
            }
        }
    }

    private static void validateCore(InspectDocument.Core value, Issues issues) {
        if (value == null) {
            issues.required("$.core", JSON_OBJECT);
            return;
        }
        strings(value.signingAlgorithms(), "$.core.signing_algorithms", true, false, issues);
        for (String required : Aep.REQUIRED_SIGNING_ALGORITHMS) {
            if (!value.signingAlgorithms().contains(required)) {
                issues.add("$.core.signing_algorithms", "Expected " + required + " to be advertised.");
            }
        }
    }

    private static void validateExtensions(InspectDocument.Extensions value, Issues issues) {
        if (value == null) {
            return;
        }
        for (int index = 0; index < value.supported().size(); index++) {
            if (!isAbsoluteUri(value.supported().get(index))) {
                issues.add("$.extensions.supported[" + index + "]", "Expected an absolute URI.");
            }
        }
    }

    private static void validateHttp(InspectDocument.Http value, Issues issues) {
        if (value == null) {
            issues.required("$.http", JSON_OBJECT);
            return;
        }
        if (value.endpointBase() != null && !value.endpointBase().startsWith("/")) {
            issues.add("$.http.endpoint_base", "Expected a path beginning with '/'.");
        }
        if (value.openapi() != null) {
            requiredNonEmpty(value.openapi().url(), "$.http.openapi.url", issues);
            if (nonEmpty(value.openapi().url())
                    && !isUriReference(value.openapi().url())) {
                issues.add("$.http.openapi.url", "Expected a URI reference.");
            }
            String slash = value.openapi().pathMatching() == null
                    ? null
                    : value.openapi().pathMatching().trailingSlash();
            if (!"strict".equals(slash) && !"equivalent".equals(slash)) {
                issues.add("$.http.openapi.path_matching.trailing_slash", "Expected strict or equivalent.");
            }
        }
    }

    private static void validateIdentity(
            InspectDocument.Identity value, InspectDocument.Commands commands, Issues issues) {
        if (value == null) {
            issues.required("$.identity", JSON_OBJECT);
            return;
        }
        matchItems(value.methods(), IDENTITY_METHOD, "$.identity.methods", issues);
        if (commands != null
                && commands.supported().stream().anyMatch(AUTHENTICATED_COMMANDS::contains)
                && value.methods().isEmpty()) {
            issues.add("$.identity.methods", "Expected at least one identity method for authenticated commands.");
        }
    }

    private static void lifecycleMetadata(
            String ownerAction, List<String> verification, List<String> requirements, Issues issues) {
        if (ownerAction != null && !TRUE.equals(ownerAction) && !"false".equals(ownerAction)) {
            issues.add("$.owner_action_required", "Expected true or false.");
        }
        strings(verification, "$.verification_pending", true, true, issues);
        strings(requirements, "$.requirements_pending", true, true, issues);
    }

    private static void strings(
            List<String> values, String path, boolean nonEmptyArray, boolean unique, Issues issues) {
        if (values == null) {
            return;
        }
        if (nonEmptyArray && values.isEmpty()) {
            issues.add(path, "Expected at least one item.");
        }
        Set<String> seen = unique ? new HashSet<>() : null;
        for (int index = 0; index < values.size(); index++) {
            String value = values.get(index);
            if (value == null || (nonEmptyArray && value.isEmpty())) {
                issues.add(path + "[" + index + "]", "Expected a non-empty string.");
            } else if (seen != null && !seen.add(value)) {
                issues.add(path + "[" + index + "]", "Expected unique items.");
            }
        }
    }

    private static void matchItems(List<String> values, Pattern pattern, String path, Issues issues) {
        if (values == null) {
            return;
        }
        for (int index = 0; index < values.size(); index++) {
            String value = values.get(index);
            if (value == null || !pattern.matcher(value).matches()) {
                issues.add(path + "[" + index + "]", "Expected a syntactically valid AEP identifier.");
            }
        }
    }

    private static void signingAlgorithms(List<String> values, String path, Issues issues) {
        strings(values, path, true, true, issues);
        if (values != null && values.stream().anyMatch(value -> !Aep.REQUIRED_SIGNING_ALGORITHMS.contains(value))) {
            issues.add(path, "Expected only registered AEP signing algorithms.");
        }
    }

    private static void requiredDid(String value, String path, Issues issues) {
        if (!nonEmpty(value) || !value.startsWith("did:")) issues.add(path, "Expected a DID string.");
    }

    private static void requiredDateTime(String value, String path, Issues issues) {
        if (!isDateTime(value)) issues.add(path, "Expected an RFC 3339 date-time.");
    }

    private static void requiredEndpoint(String value, String path, Issues issues) {
        if (!isEndpointPath(value)) issues.add(path, "Expected an absolute path without a query or fragment.");
    }

    private static void requiredEndpointTemplate(String value, String variable, String path, Issues issues) {
        if (value == null || !value.contains(variable) || !isEndpointPath(value.replace(variable, "validation"))) {
            issues.add(path, "Expected an absolute path template containing " + variable + ".");
        }
    }

    private static void optionalEndpoint(String value, String path, Issues issues) {
        if (value != null) requiredEndpoint(value, path, issues);
    }

    private static void positiveIntegerString(String value, int maximum, String path, Issues issues) {
        int number = nonNegativeInteger(value);
        if (number < 1 || number > maximum || !Integer.toString(number).equals(value)) {
            issues.add(path, "Expected a decimal integer string from 1 through " + maximum + ".");
        }
    }

    private static void nonNegativeIntegerString(String value, String path, Issues issues) {
        int number = nonNegativeInteger(value);
        if (number < 0 || !Integer.toString(number).equals(value)) {
            issues.add(path, "Expected a non-negative decimal integer string.");
        }
    }

    private static int nonNegativeInteger(String value) {
        try {
            if (value == null || value.startsWith("+") || value.startsWith("-")) return -1;
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    private static void operationResource(AssertionOperation operation, String resource, String path, Issues issues) {
        if (operation == AssertionOperation.AUTHENTICATE) {
            if (!isProtectedResourceUri(resource, false)) {
                issues.add(path, "Expected an absolute HTTPS URI without a fragment.");
            }
        } else if (resource != null) {
            issues.add(path, "resource is only valid for authenticate.");
        }
    }

    private static boolean isEndpointPath(String value) {
        if (!nonEmpty(value) || !value.startsWith("/") || value.startsWith("//")) return false;
        try {
            URI uri = URI.create(value);
            return !uri.isAbsolute() && uri.getRawQuery() == null && uri.getRawFragment() == null;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static boolean isAbsoluteHttpsUri(String value) {
        if (!nonEmpty(value)) return false;
        try {
            URI uri = URI.create(value);
            return uri.isAbsolute()
                    && HTTPS.equalsIgnoreCase(uri.getScheme())
                    && uri.getHost() != null
                    && uri.getUserInfo() == null
                    && uri.getFragment() == null;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static void requiredNonEmpty(String value, String path, Issues issues) {
        if (!nonEmpty(value)) {
            issues.add(path, "Expected a non-empty string.");
        }
    }

    private static void optionalNonEmpty(String value, String path, Issues issues) {
        if (value != null && value.isEmpty()) {
            issues.add(path, "Expected a non-empty string.");
        }
    }

    private static void matches(String value, Pattern pattern, String path, Issues issues) {
        if (value == null || !pattern.matcher(value).matches()) {
            issues.add(path, "Expected string to match " + pattern.pattern() + ".");
        }
    }

    private static void optionalMatch(String value, Pattern pattern, String path, Issues issues) {
        if (value != null && !pattern.matcher(value).matches()) {
            issues.add(path, "Expected string to match " + pattern.pattern() + ".");
        }
    }

    private static void optional(
            String value, String path, Predicate<String> predicate, String message, Issues issues) {
        if (value != null && !predicate.test(value)) {
            issues.add(path, message);
        }
    }

    private static boolean nonEmpty(String value) {
        return value != null && !value.isEmpty();
    }

    private static boolean isApiKeyValue(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 0x21
                    || character > 0x7e
                    || character == 0x22
                    || character == 0x2c
                    || character == 0x3b
                    || character == BACKSLASH) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsControlCharacter(String value) {
        return value.codePoints().anyMatch(character -> character <= 0x1f || character == 0x7f);
    }

    private static boolean isDateTime(String value) {
        if (!nonEmpty(value)) {
            return false;
        }
        try {
            return OffsetDateTime.parse(value) != null;
        } catch (DateTimeException exception) {
            return false;
        }
    }

    private static boolean isFullDate(String value) {
        try {
            return value.length() == 10 && LocalDate.parse(value).toString().equals(value);
        } catch (DateTimeException exception) {
            return false;
        }
    }

    private static boolean isMailbox(String value) {
        int separator = mailboxSeparator(value);
        if (separator < 1 || separator == value.length() - 1) {
            return false;
        }
        String local = value.substring(0, separator);
        String domain = value.substring(separator + 1);
        if (local.getBytes(StandardCharsets.UTF_8).length > 64
                || domain.getBytes(StandardCharsets.UTF_8).length > 255) {
            return false;
        }
        return isMailboxLocalPart(local) && isMailboxDomain(domain);
    }

    private static int mailboxSeparator(String value) {
        if (!value.startsWith("\"")) {
            int separator = value.indexOf('@');
            return separator == value.lastIndexOf('@') ? separator : -1;
        }
        boolean escaped = false;
        for (int index = 1; index < value.length(); index++) {
            char character = value.charAt(index);
            if (escaped) {
                escaped = false;
            } else if (character == BACKSLASH) {
                escaped = true;
            } else if (character == QUOTE) {
                return index + 1 < value.length() && value.charAt(index + 1) == '@' ? index + 1 : -1;
            }
        }
        return -1;
    }

    private static boolean isMailboxLocalPart(String value) {
        if (value.startsWith("\"")) {
            return isQuotedLocalPart(value);
        }
        return java.util.Arrays.stream(value.split("\\.", -1)).allMatch(ATEXT.asMatchPredicate());
    }

    private static boolean isQuotedLocalPart(String value) {
        if (value.length() < 2 || !value.endsWith("\"")) {
            return false;
        }
        int index = 1;
        while (index < value.length() - 1) {
            int character = value.charAt(index);
            if (character == BACKSLASH) {
                index++;
                if (index >= value.length() - 1) {
                    return false;
                }
                int escaped = value.charAt(index);
                if (escaped < 32 || escaped > 126) {
                    return false;
                }
            } else if (!((character >= 32 && character <= 33)
                    || (character >= 35 && character <= 91)
                    || (character >= 93 && character <= 126))) {
                return false;
            }
            index++;
        }
        return true;
    }

    private static boolean isMailboxDomain(String value) {
        if (value.startsWith("[") || value.endsWith("]")) {
            return isAddressLiteral(value);
        }
        return java.util.Arrays.stream(value.split("\\.", -1))
                .allMatch(label -> label.length() <= 63 && label.matches("[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"));
    }

    private static boolean isAddressLiteral(String value) {
        if (!value.startsWith("[") || !value.endsWith("]")) {
            return false;
        }
        String content = value.substring(1, value.length() - 1);
        if (isIpv4Address(content)) {
            return true;
        }
        if (content.startsWith("IPv6:")) {
            return isIpv6Address(content.substring(5));
        }
        int separator = content.indexOf(':');
        if (separator < 1 || separator == content.length() - 1) {
            return false;
        }
        String tag = content.substring(0, separator);
        String literal = content.substring(separator + 1);
        return tag.matches("[A-Za-z0-9-]*[A-Za-z0-9]")
                && literal.chars()
                        .allMatch(character ->
                                (character >= 33 && character <= 90) || (character >= 94 && character <= 126));
    }

    private static boolean isIpv4Address(String value) {
        String[] octets = value.split("\\.", -1);
        if (octets.length != IPV4_OCTETS) {
            return false;
        }
        for (String octet : octets) {
            if (!octet.matches("[0-9]{1,3}") || Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6Address(String value) {
        if (value.isEmpty() || value.indexOf("::") != value.lastIndexOf("::")) {
            return false;
        }
        boolean compressed = value.contains("::");
        String[] sections = compressed ? value.split("::", -1) : new String[] {value};
        if (sections.length > MAX_IPV6_SECTIONS) {
            return false;
        }
        int left = ipv6Groups(sections[0]);
        int right = sections.length == MAX_IPV6_SECTIONS ? ipv6Groups(sections[1]) : 0;
        if (left < 0 || right < 0) {
            return false;
        }
        int groups = left + right;
        return compressed ? groups < 8 : groups == 8;
    }

    private static int ipv6Groups(String value) {
        if (value.isEmpty()) {
            return 0;
        }
        String[] groups = value.split(":", -1);
        int count = 0;
        for (int index = 0; index < groups.length; index++) {
            String group = groups[index];
            if (group.contains(".")) {
                if (index != groups.length - 1 || !isIpv4Address(group)) {
                    return -1;
                }
                count += 2;
            } else if (!group.matches("[0-9A-Fa-f]{1,4}")) {
                return -1;
            } else {
                count++;
            }
        }
        return count;
    }

    private static boolean isProtectedResourceUri(String value, boolean allowInsecureLoopback) {
        if (!nonEmpty(value)) {
            return false;
        }
        try {
            URI uri = URI.create(value);
            if (!uri.isAbsolute() || uri.getHost() == null || uri.getFragment() != null) {
                return false;
            }
            if (HTTPS.equalsIgnoreCase(uri.getScheme())) {
                return true;
            }
            return allowInsecureLoopback
                    && "http".equalsIgnoreCase(uri.getScheme())
                    && Set.of(
                                    "localhost",
                                    "127.0.0.1", // NOPMD - Explicit development opt-in permits loopback HTTP.
                                    "::1") // NOPMD - Explicit development opt-in permits loopback HTTP.
                            .contains(uri.getHost().toLowerCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static boolean isAbsoluteUri(String value) {
        try {
            return URI.create(value).isAbsolute();
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static boolean isUriReference(String value) {
        try {
            URI.create(value);
            return true;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static <T> T require(String type, T value, List<ValidationIssue> issues) {
        if (!issues.isEmpty()) {
            throw new AepValidationException(type, issues);
        }
        return value;
    }

    private static final class Issues {
        private final List<ValidationIssue> collected = new ArrayList<>();

        void add(String path, String message) {
            collected.add(new ValidationIssue(path, message));
        }

        Issues required(String path, String type) {
            add(path, "Expected a required " + type + ".");
            return this;
        }

        void prefix(String prefix, List<ValidationIssue> nested) {
            nested.forEach(issue -> add(
                    "$".equals(issue.path()) ? prefix : prefix + issue.path().substring(1), issue.message()));
        }

        List<ValidationIssue> values() {
            return List.copyOf(collected);
        }
    }
}
