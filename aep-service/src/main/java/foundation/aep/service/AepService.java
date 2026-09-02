package foundation.aep.service;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttp;
import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidation;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.AuthorizationScheme;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.EnrollResponse;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.ProblemDetails;
import foundation.aep.core.ProtectedResourceAuthorization;
import foundation.aep.core.RevokeRequest;
import foundation.aep.core.RevokeResponse;
import foundation.aep.core.StatusResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

public final class AepService {
    private static final String ERROR_NOT_RECOGNIZED = "not_recognized";
    private static final String TITLE_NOT_RECOGNIZED = "Not recognized";
    private static final String ERROR_INVALID_REQUEST = "invalid_request";
    private static final String TITLE_INVALID_REQUEST = "Invalid request";
    private static final String STRING_TRUE = "true";
    private static final String LOCALHOST = "localhost";
    private static final int SINGLE_VALUE = 1;
    private final InspectDocument document;
    private final ClientAssertionVerifier verifier;
    private final EnrollmentStore enrollmentStore;
    private final EnrollmentPolicy enrollmentPolicy;
    private final ReplayStore replayStore;
    private final IdempotencyStore idempotencyStore;
    private final Map<String, GrantTypeDefinition> grantTypes;
    private final Map<String, CredentialAuthenticator> authenticators;
    private final Clock clock;
    private final Duration clockSkew;
    private final boolean allowInsecureLoopback;
    private final Supplier<String> identifierSupplier;
    private final URI inspectUri;

    private AepService(Builder builder) {
        document = AepValidation.requireInspectDocument(builder.configuredDocument);
        verifier = Objects.requireNonNull(builder.configuredVerifier, "verifier");
        enrollmentStore = builder.configuredEnrollmentStore;
        enrollmentPolicy = builder.configuredEnrollmentPolicy;
        replayStore = builder.configuredReplayStore;
        idempotencyStore = builder.configuredIdempotencyStore == null
                ? IdempotencyStore.inMemory(builder.configuredClock)
                : builder.configuredIdempotencyStore;
        grantTypes = Map.copyOf(builder.configuredGrantTypes);
        authenticators = Map.copyOf(builder.configuredAuthenticators);
        clock = builder.configuredClock;
        clockSkew = builder.configuredClockSkew;
        allowInsecureLoopback = builder.configuredAllowInsecureLoopback;
        identifierSupplier = builder.configuredIdentifierSupplier;
        inspectUri = builder.configuredInspectUri;
        requireConfiguration();
    }

    public static Builder builder(InspectDocument document, ClientAssertionVerifier verifier) {
        return new Builder(document, verifier);
    }

    public InspectDocument inspectDocument() {
        return document;
    }

    public CompletionStage<ServiceResponse<EnrollResponse>> enroll(EnrollRequest request, CommandOptions options) {
        return authenticateAssertion(options, AssertionOperation.ENROLL, null).thenCompose(authentication -> {
            if (authentication.isEmpty()) return completed(problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401));
            ClientAssertionClaims claims = authentication.get();
            if (!validIdempotency(options)
                    || request == null
                    || !claims.subject().equals(request.agentDid())
                    || (request.idempotencyKey() != null
                            && !request.idempotencyKey().equals(options.idempotencyKey()))
                    || !AepValidation.enrollRequest(request).isEmpty()) {
                return completed(problem(ERROR_INVALID_REQUEST, TITLE_INVALID_REQUEST, 400));
            }
            return idempotent(claims.subject(), "enroll", options.idempotencyKey(), request, () -> enrollNew(request));
        });
    }

    public CompletionStage<ServiceResponse<StatusResponse>> status(CommandOptions options) {
        return authenticateAssertion(options, AssertionOperation.STATUS, null).thenCompose(authentication -> {
            if (authentication.isEmpty()) return completed(problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401));
            return enrollmentStore
                    .find(authentication.get().subject())
                    .thenApply(record -> record.<ServiceResponse<StatusResponse>>map(
                                    value -> ServiceResponse.success(statusResponse(value)))
                            .orElseGet(() -> problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401)));
        });
    }

    public CompletionStage<ServiceResponse<Map<String, Object>>> grant(GrantRequest request, CommandOptions options) {
        return authenticateAssertion(options, AssertionOperation.GRANT, null).thenCompose(authentication -> {
            if (authentication.isEmpty()) return completed(problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401));
            if (!validIdempotency(options)
                    || request == null
                    || !AepValidation.grantRequest(request).isEmpty()) {
                return completed(problem(ERROR_INVALID_REQUEST, TITLE_INVALID_REQUEST, 400));
            }
            String agentDid = authentication.get().subject();
            return idempotent(agentDid, "grant", options.idempotencyKey(), request, () -> grantNew(agentDid, request));
        });
    }

    public CompletionStage<ServiceResponse<RevokeResponse>> revoke(RevokeRequest request, CommandOptions options) {
        return authenticateAssertion(options, AssertionOperation.REVOKE, null).thenCompose(authentication -> {
            if (authentication.isEmpty()) return completed(problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401));
            if (!validIdempotency(options)
                    || request == null
                    || !AepValidation.revokeRequest(request).isEmpty()) {
                return completed(problem(ERROR_INVALID_REQUEST, TITLE_INVALID_REQUEST, 400));
            }
            String agentDid = authentication.get().subject();
            return idempotent(
                    agentDid, "revoke", options.idempotencyKey(), request, () -> revokeNew(agentDid, request));
        });
    }

    public CompletionStage<ProtectedResourceResult> authenticate(ProtectedResourceRequest request) {
        URI resource;
        try {
            resource = requireProtectedResource(request.url());
        } catch (IllegalArgumentException exception) {
            return CompletableFuture.failedFuture(exception);
        }
        Presentation presentation = selectPresentation(request.headers());
        if (!presentation.valid()) {
            return completed(ProtectedResourceResult.rejected(resourceProblem(ERROR_NOT_RECOGNIZED, resource)));
        }
        if (presentation.authorization() != null && presentation.authorization().scheme() == AuthorizationScheme.AEP) {
            if (!authenticationMethods().contains(Aep.AUTHENTICATION_METHOD_JWT)) {
                return completed(ProtectedResourceResult.rejected(
                        resourceProblem("unsupported_authentication_method", resource)));
            }
            CommandOptions options =
                    CommandOptions.authenticated(presentation.authorization().credentials());
            return authenticateAssertion(options, AssertionOperation.AUTHENTICATE, resource.toString())
                    .thenCompose(
                            authentication -> activePrincipal(authentication, Aep.AUTHENTICATION_METHOD_JWT, resource));
        }
        String presentedMethod = authenticationMethod(presentation.authorization());
        if (presentedMethod != null && !authenticationMethods().contains(presentedMethod)) {
            return completed(
                    ProtectedResourceResult.rejected(resourceProblem("unsupported_authentication_method", resource)));
        }
        CredentialAuthenticationInput input =
                new CredentialAuthenticationInput(request.headers(), request.method(), resource, clock.instant());
        return authenticateCredential(
                new ArrayList<>(authenticationMethods()), 0, input, presentation.authorization() != null, resource);
    }

    private CompletionStage<ServiceResponse<EnrollResponse>> enrollNew(EnrollRequest request) {
        return enrollmentStore.find(request.agentDid()).thenCompose(existing -> {
            if (existing.isPresent()) {
                return completed(ServiceResponse.success(enrollResponse(existing.get())));
            }
            List<String> missing = missingRequiredClaims(request);
            if (!missing.isEmpty()) {
                return completed(problem("requirements_unmet", "Requirements unmet", 422, missing));
            }
            return enrollmentStore
                    .findOrCreate(request.agentDid(), () -> createEnrollment(request))
                    .thenApply(selection -> ServiceResponse.success(enrollResponse(selection.record())));
        });
    }

    private CompletionStage<EnrollmentRecord> createEnrollment(EnrollRequest request) {
        Instant now = clock.instant();
        return enrollmentPolicy
                .decide(request, now)
                .thenApply(decision -> EnrollmentRecord.builder(
                                request.agentDid(), requireIdentifier(), decision.status(), now)
                        .claims(request.claims())
                        .ownerActionRequired(decision.ownerActionRequired())
                        .verificationPending(decision.verificationPending())
                        .requirementsPending(decision.requirementsPending())
                        .build());
    }

    private List<String> missingRequiredClaims(EnrollRequest request) {
        List<String> missing = new ArrayList<>();
        InspectDocument.Claims claims = document.claims();
        if (claims != null) {
            for (String required : claims.required()) {
                if (request.claims() == null || !request.claims().contains(required)) missing.add(required);
            }
        }
        return missing;
    }

    private CompletionStage<ServiceResponse<Map<String, Object>>> grantNew(String agentDid, GrantRequest request) {
        GrantTypeDefinition definition = grantTypes.get(request.grantType());
        if (definition == null) return completed(problem("unsupported_grant_type", "Unsupported Grant Type", 400));
        return enrollmentStore.find(agentDid).thenCompose(enrollment -> {
            if (enrollment.isEmpty()) return completed(problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401));
            ServiceResponse<Map<String, Object>> lifecycle = blockedGrant(enrollment.get());
            if (lifecycle != null) return completed(lifecycle);
            GrantContext context = new GrantContext(agentDid, enrollment.get(), request.grantType(), clock.instant());
            return definition
                    .handler()
                    .grant(request, context)
                    .thenApply(result -> ServiceResponse.success(result.response()));
        });
    }

    private CompletionStage<ServiceResponse<RevokeResponse>> revokeNew(String agentDid, RevokeRequest request) {
        if (request.grantType() != null && !grantTypes.containsKey(request.grantType())) {
            return completed(problem("unsupported_grant_type", "Unsupported Grant Type", 400));
        }
        if (request.credentialId() != null) {
            InspectDocument.GrantTypeConfig config =
                    document.commands().grantTypesConfig().get(request.grantType());
            if (config == null || !STRING_TRUE.equals(config.supportsPerCredentialRevoke())) {
                return completed(problem(ERROR_INVALID_REQUEST, TITLE_INVALID_REQUEST, 400));
            }
        }
        return enrollmentStore.find(agentDid).thenCompose(enrollment -> {
            if (enrollment.isEmpty()) return completed(problem(ERROR_NOT_RECOGNIZED, TITLE_NOT_RECOGNIZED, 401));
            List<GrantTypeDefinition> targets = STRING_TRUE.equals(request.allGrantTypes())
                    ? grantTypes.values().stream()
                            .sorted(java.util.Comparator.comparing(GrantTypeDefinition::grantType))
                            .toList()
                    : List.of(grantTypes.get(request.grantType()));
            CompletionStage<Void> stage = CompletableFuture.completedFuture(null);
            for (GrantTypeDefinition target : targets) {
                RevokeContext context =
                        new RevokeContext(agentDid, enrollment.get(), target.grantType(), clock.instant());
                stage = stage.thenCompose(ignored -> target.handler().revoke(request, context));
            }
            return stage.thenApply(ignored -> ServiceResponse.success(new RevokeResponse()));
        });
    }

    private CompletionStage<Optional<ClientAssertionClaims>> authenticateAssertion(
            CommandOptions options, AssertionOperation operation, String resource) {
        if (options == null
                || options.clientAssertion() == null
                || options.clientAssertion().isBlank()) {
            return completed(Optional.empty());
        }
        AssertionVerificationContext context = new AssertionVerificationContext(
                document.service().did(),
                operation,
                resource,
                options.idempotencyKey(),
                document.core().signingAlgorithms(),
                clock,
                clockSkew,
                allowInsecureLoopback);
        CompletionStage<ClientAssertionClaims> verification;
        try {
            verification = verifier.verify(options.clientAssertion(), context);
        } catch (RuntimeException exception) {
            return completed(Optional.empty());
        }
        return verification
                .handle((claims, failure) -> failure == null && validClaims(claims, operation, resource)
                        ? Optional.of(claims)
                        : Optional.<ClientAssertionClaims>empty())
                .thenCompose(claims -> {
                    if (claims.isEmpty()) return completed(claims);
                    Instant expiresAt;
                    try {
                        expiresAt =
                                Instant.ofEpochSecond(claims.get().expiresAt()).plus(clockSkew);
                    } catch (RuntimeException exception) {
                        return completed(Optional.empty());
                    }
                    ReplayRecord replay = new ReplayRecord(
                            claims.get().subject(), claims.get().jwtId(), expiresAt);
                    return replayStore
                            .consume(replay, clock.instant())
                            .thenApply(consumed -> consumed ? claims : Optional.empty());
                });
    }

    private boolean validClaims(ClientAssertionClaims claims, AssertionOperation operation, String resource) {
        if (claims == null
                || !AepValidation.clientAssertionClaims(claims, allowInsecureLoopback)
                        .isEmpty()) return false;
        if (!claims.issuer().equals(claims.subject())
                || !claims.audience().equals(document.service().did())
                || claims.operation() != operation
                || !Objects.equals(claims.resource(), resource)
                || !identityMethods().contains(identityMethod(claims.subject()))) return false;
        Instant now = clock.instant();
        try {
            Instant issued = Instant.ofEpochSecond(claims.issuedAt());
            Instant expires = Instant.ofEpochSecond(claims.expiresAt());
            return !issued.isAfter(now.plus(clockSkew)) && !expires.isBefore(now.minus(clockSkew));
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private CompletionStage<ProtectedResourceResult> activePrincipal(
            Optional<ClientAssertionClaims> authentication, String method, URI resource) {
        if (authentication.isEmpty()) {
            return completed(ProtectedResourceResult.rejected(resourceProblem(ERROR_NOT_RECOGNIZED, resource)));
        }
        return enrollmentStore.find(authentication.get().subject()).thenApply(enrollment -> {
            if (enrollment.isEmpty() || enrollment.get().status() != AgentStatus.ACTIVE) {
                return ProtectedResourceResult.rejected(resourceProblem(ERROR_NOT_RECOGNIZED, resource));
            }
            return ProtectedResourceResult.authenticated(new AuthenticatedPrincipal(
                    authentication.get().subject(),
                    method,
                    null,
                    null,
                    List.of(),
                    AuthenticatedPrincipal.Kind.AEP_JWT));
        });
    }

    private CompletionStage<ProtectedResourceResult> authenticateCredential(
            List<String> methods, int index, CredentialAuthenticationInput input, boolean presented, URI resource) {
        if (index == methods.size()) {
            String code = presented ? ERROR_NOT_RECOGNIZED : "authentication_required";
            return completed(ProtectedResourceResult.rejected(resourceProblem(code, resource)));
        }
        String method = methods.get(index);
        if (Aep.AUTHENTICATION_METHOD_JWT.equals(method)) {
            return authenticateCredential(methods, index + 1, input, presented, resource);
        }
        CredentialAuthenticator authenticator = authenticators.get(method);
        return authenticator.hasPresentation(input).thenCompose(hasPresentation -> {
            if (!hasPresentation) {
                return authenticateCredential(methods, index + 1, input, presented, resource);
            }
            return authenticator.authenticate(input).thenCompose(principal -> {
                if (principal.isEmpty()) {
                    return authenticateCredential(methods, index + 1, input, true, resource);
                }
                AuthenticatedPrincipal value = principal.get();
                if (value.kind() != AuthenticatedPrincipal.Kind.SESSION_CREDENTIAL
                        || !method.equals(value.authenticationMethod())
                        || !method.equals(value.grantType())
                        || value.agentDid() == null
                        || value.agentDid().isBlank()) {
                    return CompletableFuture.failedFuture(
                            new IllegalArgumentException("Credential authenticator returned an invalid principal."));
                }
                return enrollmentStore
                        .find(value.agentDid())
                        .thenApply(enrollment -> enrollment.isPresent()
                                        && enrollment.get().status() == AgentStatus.ACTIVE
                                ? ProtectedResourceResult.authenticated(value)
                                : ProtectedResourceResult.rejected(resourceProblem(ERROR_NOT_RECOGNIZED, resource)));
            });
        });
    }

    private <T> CompletionStage<ServiceResponse<T>> idempotent(
            String agentDid,
            String command,
            String key,
            Object request,
            Supplier<CompletionStage<ServiceResponse<T>>> operation) {
        IdempotencyInput input = new IdempotencyInput(agentDid, key, command, requestHash(request));
        return idempotencyStore.execute(input, operation).handle((result, failure) -> {
            Throwable cause = unwrap(failure);
            if (cause != null) throw new java.util.concurrent.CompletionException(cause);
            return result.state() == IdempotencyResult.State.CONFLICT
                    ? problem("idempotency_conflict", "Idempotency conflict", 409)
                    : result.response();
        });
    }

    private void requireConfiguration() {
        if (clockSkew.isNegative() || clockSkew.compareTo(Aep.RECOMMENDED_CLOCK_SKEW) > 0 || clockSkew.getNano() != 0) {
            throw new IllegalArgumentException("Clock skew must be between zero and thirty seconds.");
        }
        if (inspectUri != null) requireAbsoluteHttps(inspectUri, "Inspect URI");
        List<String> advertisedGrantTypes = document.commands().grantTypes();
        if (!grantTypes.keySet().equals(new java.util.HashSet<>(advertisedGrantTypes))) {
            throw new IllegalArgumentException("Grant Type handlers must match the Inspect advertisement.");
        }
        for (String method : authenticationMethods()) {
            if (!Aep.AUTHENTICATION_METHOD_JWT.equals(method)
                    && (!grantTypes.containsKey(method) || !authenticators.containsKey(method))) {
                throw new IllegalArgumentException(
                        "Session authentication methods require Grant and authentication handlers.");
            }
        }
    }

    private List<String> authenticationMethods() {
        return document.authentication() == null
                ? List.of()
                : document.authentication().methods();
    }

    private List<String> identityMethods() {
        return document.identity() == null ? List.of() : document.identity().methods();
    }

    private static String identityMethod(String did) {
        String[] parts = did.split(":", 3);
        return parts.length == 3 && "did".equals(parts[0]) ? "did:" + parts[1] : "";
    }

    private static boolean validIdempotency(CommandOptions options) {
        return options != null
                && options.idempotencyKey() != null
                && !options.idempotencyKey().isBlank();
    }

    private String requireIdentifier() {
        String value = identifierSupplier.get();
        if (value == null || value.isBlank())
            throw new IllegalStateException("Identifier supplier returned an empty value.");
        return value;
    }

    private static String requestHash(Object request) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(AepJson.write(canonicalRequest(request)).getBytes(StandardCharsets.UTF_8));
            return "sha256:" + java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    private static Object canonicalRequest(Object request) {
        if (request instanceof EnrollRequest enroll) {
            Map<String, Object> value = new java.util.TreeMap<>();
            value.put("agent_did", enroll.agentDid());
            if (enroll.claims() != null) value.put("claims", canonicalClaims(enroll.claims()));
            if (enroll.idempotencyKey() != null) value.put("idempotency_key", enroll.idempotencyKey());
            return value;
        }
        if (request instanceof GrantRequest grant) {
            Map<String, Object> value = new java.util.TreeMap<>();
            value.put("grant_type", grant.grantType());
            if (!grant.requestedScopes().isEmpty()) value.put("requested_scopes", grant.requestedScopes());
            return value;
        }
        if (request instanceof RevokeRequest revoke) {
            Map<String, Object> value = new java.util.TreeMap<>();
            if (revoke.grantType() != null) value.put("grant_type", revoke.grantType());
            if (revoke.credentialId() != null) value.put("credential_id", revoke.credentialId());
            if (revoke.allGrantTypes() != null) value.put("all_grant_types", revoke.allGrantTypes());
            return value;
        }
        throw new IllegalArgumentException("Unsupported idempotent request type.");
    }

    private static Map<String, Object> canonicalClaims(foundation.aep.core.ClaimValues claims) {
        Map<String, Object> value = new java.util.TreeMap<>();
        if (claims.contactAddressPrimary() != null)
            value.put(Aep.CLAIM_CONTACT_ADDRESS_PRIMARY, claims.contactAddressPrimary());
        if (claims.contactEmail() != null) value.put(Aep.CLAIM_CONTACT_EMAIL, claims.contactEmail());
        if (claims.contactMobile() != null) value.put(Aep.CLAIM_CONTACT_MOBILE, claims.contactMobile());
        if (claims.personBirthdate() != null) value.put(Aep.CLAIM_PERSON_BIRTHDATE, claims.personBirthdate());
        if (claims.personFirstName() != null) value.put(Aep.CLAIM_PERSON_FIRST_NAME, claims.personFirstName());
        if (claims.personLastName() != null) value.put(Aep.CLAIM_PERSON_LAST_NAME, claims.personLastName());
        if (claims.personUsername() != null) value.put(Aep.CLAIM_PERSON_USERNAME, claims.personUsername());
        claims.additional().forEach((name, claimValue) -> value.put(name, canonicalJsonValue(claimValue)));
        return value;
    }

    private static Object canonicalJsonValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new java.util.TreeMap<>();
            map.forEach((key, member) -> sorted.put(String.valueOf(key), canonicalJsonValue(member)));
            return sorted;
        }
        if (value instanceof List<?> list)
            return list.stream().map(AepService::canonicalJsonValue).toList();
        return value;
    }

    private static EnrollResponse enrollResponse(EnrollmentRecord record) {
        return new EnrollResponse(
                record.status(),
                record.ownerActionRequired() ? STRING_TRUE : null,
                emptyToNull(record.verificationPending()),
                emptyToNull(record.requirementsPending()));
    }

    private static StatusResponse statusResponse(EnrollmentRecord record) {
        return new StatusResponse(
                record.status(),
                record.ownerActionRequired() ? STRING_TRUE : null,
                emptyToNull(record.verificationPending()),
                emptyToNull(record.requirementsPending()),
                DateTimeFormatter.ISO_INSTANT.format(record.since()));
    }

    private static List<String> emptyToNull(List<String> values) {
        return values.isEmpty() ? null : values;
    }

    private static <T> ServiceResponse<T> blockedGrant(EnrollmentRecord enrollment) {
        return switch (enrollment.status()) {
            case ACTIVE -> null;
            case PENDING -> problem("verification_pending", "Verification pending", 403);
            case SUSPENDED -> problem("identity_suspended", "Identity suspended", 403);
            case TERMINATED -> problem("identity_terminated", "Identity terminated", 403);
            case UNAVAILABLE -> problem("identity_unavailable", "Identity unavailable", 403);
            case REJECTED -> problem("enrollment_failed", "Enrollment failed", 400);
        };
    }

    private ServiceResponse<?> resourceProblem(String code, URI resource) {
        ServiceResponse<?> response = problem(code, humanize(code), 401);
        URI advertisedInspect = inspectUri == null ? resource.resolve(Aep.WELL_KNOWN_PATH) : inspectUri;
        String challenge = "AEP service_did=\"" + document.service().did() + "\",inspect=\"" + advertisedInspect
                + "\",reason=\"" + code + "\"";
        return new ServiceResponse<>(
                response.status(),
                response.contentType(),
                null,
                response.problem(),
                Map.of("WWW-Authenticate", List.of(challenge)));
    }

    private URI requireProtectedResource(URI value) {
        if (value == null || !value.isAbsolute() || value.getUserInfo() != null || value.getFragment() != null) {
            throw new IllegalArgumentException(
                    "Protected resource URL must be an absolute URI without credentials or a fragment.");
        }
        boolean secure = "https".equalsIgnoreCase(value.getScheme());
        boolean loopback =
                allowInsecureLoopback && "http".equalsIgnoreCase(value.getScheme()) && isLoopback(value.getHost());
        if (!secure && !loopback) {
            throw new IllegalArgumentException("Protected resource URL must use HTTPS.");
        }
        return value;
    }

    private void requireAbsoluteHttps(URI value, String name) {
        boolean secure = value.isAbsolute()
                && "https".equalsIgnoreCase(value.getScheme())
                && value.getHost() != null
                && value.getUserInfo() == null
                && value.getFragment() == null;
        boolean loopback = allowInsecureLoopback
                && value.isAbsolute()
                && "http".equalsIgnoreCase(value.getScheme())
                && isLoopback(value.getHost())
                && value.getUserInfo() == null
                && value.getFragment() == null;
        if (!secure && !loopback) throw new IllegalArgumentException(name + " must be an absolute HTTPS URI.");
    }

    private static boolean isLoopback(String host) {
        if (LOCALHOST.equalsIgnoreCase(host)) return true;
        if (host == null) return false;
        String value = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        boolean numeric = value.indexOf(':') >= 0
                || value.chars().allMatch(character -> Character.isDigit(character) || character == '.');
        if (!numeric) return false;
        try {
            return java.net.InetAddress.getByName(value).isLoopbackAddress();
        } catch (java.net.UnknownHostException exception) {
            return false;
        }
    }

    private static Presentation selectPresentation(Map<String, List<String>> headers) {
        List<String> dedicated = headerValues(headers, Aep.AUTHORIZATION_HEADER);
        List<String> standard = headerValues(headers, "Authorization");
        if (!dedicated.isEmpty()) {
            if (dedicated.size() != SINGLE_VALUE) return Presentation.invalid();
            ProtectedResourceAuthorization selected;
            try {
                selected = AepHttp.parseAuthorization(dedicated.get(0), AuthorizationCarrier.DEDICATED);
            } catch (IllegalArgumentException exception) {
                return Presentation.invalid();
            }
            if (standard.stream().anyMatch(AepService::isRecognizedAuthorization)) return Presentation.invalid();
            return Presentation.valid(selected);
        }
        List<ProtectedResourceAuthorization> recognized = new ArrayList<>();
        for (String value : standard) {
            try {
                recognized.add(AepHttp.parseAuthorization(value, AuthorizationCarrier.STANDARD));
            } catch (IllegalArgumentException ignored) {
                // Unrelated Authorization schemes remain available to other protocols.
            }
        }
        if (recognized.size() > SINGLE_VALUE || (recognized.size() == SINGLE_VALUE && standard.size() > SINGLE_VALUE))
            return Presentation.invalid();
        return Presentation.valid(recognized.isEmpty() ? null : recognized.get(0));
    }

    private static boolean isRecognizedAuthorization(String value) {
        try {
            AepHttp.parseAuthorization(value, AuthorizationCarrier.STANDARD);
            return true;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static String authenticationMethod(ProtectedResourceAuthorization authorization) {
        if (authorization == null) return null;
        return switch (authorization.scheme()) {
            case BASIC -> Aep.GRANT_TYPE_BASIC;
            case BEARER -> Aep.GRANT_TYPE_OAUTH_BEARER;
            case AEP -> Aep.AUTHENTICATION_METHOD_JWT;
        };
    }

    private static List<String> headerValues(Map<String, List<String>> headers, String name) {
        List<String> values = new ArrayList<>();
        headers.forEach((candidate, candidateValues) -> {
            if (candidate.equalsIgnoreCase(name)) values.addAll(candidateValues);
        });
        return values;
    }

    private static String humanize(String code) {
        String value = code.replace('_', ' ');
        return value.substring(0, 1).toUpperCase(Locale.ROOT) + value.substring(1);
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private static <T> ServiceResponse<T> problem(String code, String title, int status) {
        return problem(code, title, status, null);
    }

    private static <T> ServiceResponse<T> problem(
            String code, String title, int status, List<String> requirementsPending) {
        ProblemDetails details = new ProblemDetails(
                "urn:aep:error:" + code, title, status, null, null, code, null, requirementsPending, null);
        Map<String, List<String>> headers =
                status == 401 ? Map.of("WWW-Authenticate", List.of("AEP reason=\"" + code + "\"")) : Map.of();
        return new ServiceResponse<>(status, Aep.PROBLEM_MEDIA_TYPE, null, details, headers);
    }

    private static Throwable unwrap(Throwable failure) {
        if (failure == null) return null;
        Throwable value = failure;
        while ((value instanceof java.util.concurrent.CompletionException
                        || value instanceof java.util.concurrent.ExecutionException)
                && value.getCause() != null) value = value.getCause();
        return value;
    }

    private record Presentation(boolean valid, ProtectedResourceAuthorization authorization) {
        static Presentation valid(ProtectedResourceAuthorization value) {
            return new Presentation(true, value);
        }

        static Presentation invalid() {
            return new Presentation(false, null);
        }
    }

    public static final class Builder {
        private final InspectDocument configuredDocument;
        private final ClientAssertionVerifier configuredVerifier;
        private EnrollmentStore configuredEnrollmentStore = EnrollmentStore.inMemory();
        private EnrollmentPolicy configuredEnrollmentPolicy = EnrollmentPolicy.active();
        private ReplayStore configuredReplayStore = ReplayStore.inMemory();
        private IdempotencyStore configuredIdempotencyStore;
        private final Map<String, GrantTypeDefinition> configuredGrantTypes = new LinkedHashMap<>();
        private final Map<String, CredentialAuthenticator> configuredAuthenticators = new LinkedHashMap<>();
        private Clock configuredClock = Clock.systemUTC();
        private Duration configuredClockSkew = Aep.RECOMMENDED_CLOCK_SKEW;
        private boolean configuredAllowInsecureLoopback;
        private Supplier<String> configuredIdentifierSupplier =
                () -> UUID.randomUUID().toString();
        private URI configuredInspectUri;

        private Builder(InspectDocument document, ClientAssertionVerifier verifier) {
            configuredDocument = document;
            configuredVerifier = verifier;
        }

        public Builder enrollmentStore(EnrollmentStore value) {
            configuredEnrollmentStore = Objects.requireNonNull(value);
            return this;
        }

        public Builder enrollmentPolicy(EnrollmentPolicy value) {
            configuredEnrollmentPolicy = Objects.requireNonNull(value);
            return this;
        }

        public Builder replayStore(ReplayStore value) {
            configuredReplayStore = Objects.requireNonNull(value);
            return this;
        }

        public Builder idempotencyStore(IdempotencyStore value) {
            configuredIdempotencyStore = Objects.requireNonNull(value);
            return this;
        }

        public Builder grantType(GrantTypeDefinition value) {
            if (configuredGrantTypes.putIfAbsent(value.grantType(), value) != null) {
                throw new IllegalArgumentException("Grant Type handlers must be unique.");
            }
            return this;
        }

        public Builder credentialAuthenticator(String method, CredentialAuthenticator value) {
            if (configuredAuthenticators.putIfAbsent(method, value) != null) {
                throw new IllegalArgumentException("Credential authentication methods must be unique.");
            }
            return this;
        }

        public Builder clock(Clock value) {
            configuredClock = Objects.requireNonNull(value);
            return this;
        }

        public Builder clockSkew(Duration value) {
            configuredClockSkew = Objects.requireNonNull(value);
            return this;
        }

        public Builder allowInsecureLoopback(boolean value) {
            configuredAllowInsecureLoopback = value;
            return this;
        }

        public Builder identifierSupplier(Supplier<String> value) {
            configuredIdentifierSupplier = Objects.requireNonNull(value);
            return this;
        }

        public Builder inspectUri(URI value) {
            configuredInspectUri = value;
            return this;
        }

        public AepService build() {
            return new AepService(this);
        }
    }
}
