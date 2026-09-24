package foundation.aep.platform;

import com.nimbusds.jwt.SignedJWT;
import foundation.aep.core.Aep;
import foundation.aep.core.AepValidation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertionVerification;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.DidWeb;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformAgentIdentityListResponse;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.core.PlatformVerificationRequest;
import foundation.aep.core.PlatformVerificationResponse;
import foundation.aep.core.ProblemDetails;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import java.util.function.Supplier;

public final class AepPlatform {
    private static final int MAX_LIST_LIMIT = 100;
    private static final Duration MAX_ASSERTION_LIFETIME = Duration.ofSeconds(300);
    private static final String IDENTITY_NOT_RECOGNIZED = "Identity not recognized.";
    private static final String INVALID_REQUEST = "invalid_request";
    private static final String NOT_RECOGNIZED = "not_recognized";
    private static final String DID_URL_PROBE = "aep-platform-did-url-probe";
    private static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.ofPattern(
                    "EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.ROOT)
            .withZone(ZoneOffset.UTC);
    private final PlatformDiscoveryDocument platformDiscovery;
    private final String didHost;
    private final String didPathPrefix;
    private final PlatformAuthorizer authorizer;
    private final PlatformIdentityStore identityStore;
    private final PlatformIdempotencyStore idempotencyStore;
    private final PlatformKeyStore keyStore;
    private final PlatformServiceDidResolver serviceDidResolver;
    private final PlatformLifecyclePolicy lifecyclePolicy;
    private final PlatformReplayStore replayStore;
    private final PlatformSignHandler signHandler;
    private final Clock clock;
    private final Duration defaultLifetime;
    private final Duration maximumLifetime;
    private final Supplier<String> identityIdSupplier;
    private final Supplier<String> agentDidIdSupplier;
    private final String discoveryETag;
    private final String discoveryModified;

    private AepPlatform(Builder builder) {
        platformDiscovery = AepValidation.requirePlatformDiscoveryDocument(builder.configuredDiscovery);
        didHost = requireDidHost(builder.configuredDidHost);
        didPathPrefix = normalizeDidPathPrefix(builder.configuredDidPathPrefix);
        authorizer = Objects.requireNonNull(builder.configuredAuthorizer, "authorizer");
        identityStore = builder.configuredIdentityStore;
        idempotencyStore = builder.configuredIdempotencyStore == null
                ? PlatformIdempotencyStore.inMemory(builder.configuredClock)
                : builder.configuredIdempotencyStore;
        keyStore = Objects.requireNonNull(builder.configuredKeyStore, "keyStore");
        serviceDidResolver = Objects.requireNonNull(builder.configuredServiceDidResolver, "serviceDidResolver");
        lifecyclePolicy = builder.configuredLifecyclePolicy;
        replayStore = builder.configuredReplayStore;
        signHandler = builder.configuredSignHandler;
        clock = builder.configuredClock;
        maximumLifetime = requireLifetime(builder.configuredMaximumLifetime, MAX_ASSERTION_LIFETIME, "maximumLifetime");
        defaultLifetime = requireLifetime(
                Duration.ofSeconds(Long.parseLong(platformDiscovery.signing().defaultLifetimeSeconds())),
                maximumLifetime,
                "defaultLifetime");
        identityIdSupplier = builder.configuredIdentityIdSupplier;
        agentDidIdSupplier = builder.configuredAgentDidIdSupplier;
        if (platformDiscovery.platform().hostedVerification() && replayStore == null) {
            throw new IllegalArgumentException("Hosted verification requires a replay store.");
        }
        if (platformDiscovery.platform().hostedVerification()
                != (platformDiscovery.endpoints().hostedVerification() != null)) {
            throw new IllegalArgumentException(
                    "Hosted verification capability and endpoint must be configured together.");
        }
        validateDidUrlTemplate();
        discoveryETag = entityTag(platformDiscovery);
        discoveryModified = HTTP_DATE.format(clock.instant());
    }

    public static Builder builder(
            PlatformDiscoveryDocument discovery,
            String didHost,
            PlatformAuthorizer authorizer,
            PlatformKeyStore keyStore,
            PlatformServiceDidResolver serviceDidResolver) {
        return new Builder(discovery, didHost, authorizer, keyStore, serviceDidResolver);
    }

    public PlatformResponse<PlatformDiscoveryDocument> discovery() {
        // PLT-DISC-012 asks for validators alongside the freshness lifetime, and PLT-DISC-013 makes
        // a client honour them. Sending only Cache-Control left every expiry as a full refetch,
        // because the client had nothing to put in an If-None-Match or If-Modified-Since request.
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Cache-Control", List.of("max-age=300"));
        headers.put("ETag", List.of(discoveryETag));
        headers.put("Last-Modified", List.of(discoveryModified));
        return success(200, platformDiscovery, Aep.MEDIA_TYPE, headers);
    }

    public CompletionStage<PlatformResponse<PlatformDidDocument>> getDidDocument(
            String agentDidId, PlatformRequestContext context) {
        if (agentDidId == null || agentDidId.isBlank()) {
            return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
        }
        PlatformRequestContext effectiveContext = context(context);
        return identityStore.findByAgentDidId(agentDidId).thenCompose(identity -> {
            if (identity.isEmpty() || identity.get().status() != ManagedAgentStatus.ACTIVE) {
                return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
            }
            PlatformIdentityRecord record = identity.get();
            return keyStore.didVerificationMethod(record, effectiveContext)
                    .thenApply(method -> success(
                            200,
                            didDocument(record, method),
                            Aep.DID_MEDIA_TYPE,
                            Map.of("Cache-Control", List.of("max-age=300"))));
        });
    }

    public CompletionStage<PlatformResponse<PlatformAgentIdentity>> getIdentity(
            String agentIdentityId, PlatformRequestContext context) {
        PlatformRequestContext effectiveContext = context(context);
        return authorizedIdentity(agentIdentityId, effectiveContext, PlatformAuthorizationRequest::getIdentity)
                .thenApply(identity -> identity.map(value -> success(200, publicIdentity(value)))
                        .orElseGet(() -> problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED)));
    }

    public CompletionStage<PlatformResponse<PlatformAgentIdentityListResponse>> list(
            PlatformIdentityListQuery query, PlatformRequestContext context) {
        PlatformRequestContext effectiveContext = context(context);
        PlatformIdentityListQuery effective = query == null ? PlatformIdentityListQuery.defaults() : query;
        if (!validListQuery(effective)) {
            return completed(problem(400, INVALID_REQUEST, "Identity list query is invalid."));
        }
        return authorizer
                .authorize(PlatformAuthorizationRequest.list(effective), effectiveContext)
                .thenCompose(authorized -> {
                    if (!authorized || !hasPrincipal(effectiveContext)) {
                        return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
                    }
                    return identityStore
                            .list(effectiveContext.principal(), effective)
                            .thenApply(result -> success(
                                    200,
                                    new PlatformAgentIdentityListResponse(
                                            Integer.toString(result.identities().size()),
                                            result.identities().stream()
                                                    .map(AepPlatform::publicIdentity)
                                                    .toList(),
                                            Integer.toString(result.total()))));
                });
    }

    public CompletionStage<PlatformResponse<PlatformAgentIdentity>> provision(
            PlatformProvisionRequest request, PlatformRequestContext context) {
        PlatformRequestContext effectiveContext = context(context);
        if (!AepValidation.platformProvisionRequest(request).isEmpty()) {
            return completed(problem(400, INVALID_REQUEST, "service_did must be a DID."));
        }
        if (!hasIdempotencyContext(effectiveContext)) {
            return completed(
                    problem(400, INVALID_REQUEST, "Idempotency-Key and authenticated principal are required."));
        }
        return authorizer
                .authorize(PlatformAuthorizationRequest.provision(request), effectiveContext)
                .thenCompose(authorized -> {
                    if (!authorized) {
                        return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
                    }
                    return idempotent(
                            PlatformIdempotentOperation.PROVISION,
                            List.of(request.serviceDid()),
                            effectiveContext,
                            () -> serviceDidResolver
                                    .resolve(request.serviceDid(), effectiveContext)
                                    .thenCompose(resolved -> resolved
                                            ? provisionResolved(request.serviceDid(), effectiveContext)
                                            : completed(problem(
                                                    400, INVALID_REQUEST, "Service DID could not be resolved."))));
                });
    }

    public CompletionStage<PlatformResponse<PlatformSignResponses.Response>> sign(
            String agentIdentityId, PlatformSignRequest request, PlatformRequestContext context) {
        PlatformRequestContext effectiveContext = context(context);
        if (agentIdentityId == null || agentIdentityId.isBlank()) {
            return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
        }
        if (!AepValidation.platformSignRequest(request).isEmpty()) {
            return completed(problem(400, INVALID_REQUEST, "Delegated signing request is invalid."));
        }
        Duration lifetime = request.lifetimeSeconds() == null
                ? defaultLifetime
                : Duration.ofSeconds(Long.parseLong(request.lifetimeSeconds()));
        if (lifetime.compareTo(maximumLifetime) > 0) {
            return completed(problem(400, INVALID_REQUEST, "lifetime_seconds exceeds the configured maximum."));
        }
        if (!hasIdempotencyContext(effectiveContext)) {
            return completed(
                    problem(400, INVALID_REQUEST, "Idempotency-Key and authenticated principal are required."));
        }
        return authorizedIdentity(
                        agentIdentityId,
                        effectiveContext,
                        identity -> PlatformAuthorizationRequest.sign(identity, request))
                .thenCompose(identity -> identity.filter(
                                value -> value.serviceDid().equals(request.serviceDid()))
                        .map(value -> idempotent(
                                PlatformIdempotentOperation.SIGN,
                                List.of(agentIdentityId, requestMaterial(request)),
                                effectiveContext,
                                () -> signAuthorized(value, request, lifetime, effectiveContext)))
                        .orElseGet(() -> completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED))));
    }

    public CompletionStage<PlatformResponse<PlatformAgentIdentity>> updateIdentity(
            String agentIdentityId, PlatformLifecycleRequest request, PlatformRequestContext context) {
        PlatformRequestContext effectiveContext = context(context);
        if (agentIdentityId == null || agentIdentityId.isBlank()) {
            return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
        }
        if (!AepValidation.platformLifecycleRequest(request).isEmpty()) {
            return completed(problem(400, INVALID_REQUEST, "Lifecycle status is invalid."));
        }
        return authorizedIdentity(
                        agentIdentityId,
                        effectiveContext,
                        identity -> PlatformAuthorizationRequest.update(identity, request))
                .thenCompose(identity -> {
                    if (identity.isEmpty()) {
                        return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
                    }
                    PlatformIdentityRecord current = identity.get();
                    return lifecyclePolicy
                            .canTransition(current, request.status(), effectiveContext)
                            .thenCompose(allowed -> allowed
                                    ? identityStore
                                            .update(agentIdentityId, request.status(), clock.instant())
                                            .thenApply(
                                                    updated -> updated.map(value -> success(200, publicIdentity(value)))
                                                            .orElseGet(() -> problem(
                                                                    404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED)))
                                    : completed(problem(
                                            403,
                                            lifecycleProblemCode(current.status()),
                                            "Lifecycle transition rejected.")));
                });
    }

    public CompletionStage<PlatformResponse<PlatformVerificationResponse>> verify(
            PlatformVerificationRequest request, PlatformRequestContext context) {
        PlatformRequestContext effectiveContext = context(context);
        if (!platformDiscovery.platform().hostedVerification()) {
            return completed(problem(404, NOT_RECOGNIZED, "Hosted verification is not available."));
        }
        if (!AepValidation.platformVerificationRequest(request).isEmpty()) {
            return completed(problem(400, INVALID_REQUEST, "Hosted verification request is invalid."));
        }
        if (!hasIdempotencyContext(effectiveContext)) {
            return completed(
                    problem(400, INVALID_REQUEST, "Idempotency-Key and authenticated principal are required."));
        }
        return verifyAuthorized(request, effectiveContext);
    }

    // Provision validates and authorizes the principal before the store scopes the identity to it.
    private CompletionStage<PlatformResponse<PlatformAgentIdentity>> provisionResolved(
            String serviceDid, PlatformRequestContext context) {
        return identityStore
                .findOrCreate(context.principal(), serviceDid, () -> createIdentity(serviceDid, context))
                .thenApply(selection -> success(200, publicIdentity(selection.identity())));
    }

    private CompletionStage<PlatformIdentityRecord> createIdentity(String serviceDid, PlatformRequestContext context) {
        String identityId = requireGenerated(identityIdSupplier.get(), "identity identifier");
        String agentDidId = requireGenerated(agentDidIdSupplier.get(), "Agent DID identifier");
        Instant now = clock.instant();
        String agentDid = createServiceScopedAgentDid(agentDidId);
        PlatformIdentityRecord identity = PlatformIdentityRecord.builder()
                .agentDid(agentDid)
                .agentDidId(agentDidId)
                .agentIdentityId(identityId.startsWith("pai_") ? identityId : "pai_" + identityId)
                .createdAt(now)
                .didDocumentUrl(renderDidDocumentUrl(agentDidId))
                .keyId(agentDid)
                .principal(context.principal())
                .serviceDid(serviceDid)
                .signingAlgorithms(platformDiscovery.signing().algorithms())
                .status(ManagedAgentStatus.ACTIVE)
                .updatedAt(now)
                .build();
        return keyStore.create(identity, context).thenApply(ignored -> identity);
    }

    private CompletionStage<PlatformResponse<PlatformSignResponses.Response>> signAuthorized(
            PlatformIdentityRecord identity,
            PlatformSignRequest request,
            Duration lifetime,
            PlatformRequestContext context) {
        if (!identity.serviceDid().equals(request.serviceDid())) {
            return completed(problem(404, NOT_RECOGNIZED, IDENTITY_NOT_RECOGNIZED));
        }
        return lifecyclePolicy.canSign(identity, context).thenCompose(allowed -> {
            // PLT-LIFE-002 and PLT-SIGN-007 forbid signing for a revoked, suspended, or terminated
            // identity outright, so the configured policy may only narrow this floor. Consulting the
            // policy alone let a custom one widen a MUST NOT back open.
            if (!allowed || identity.status() != ManagedAgentStatus.ACTIVE) {
                return completed(problem(403, lifecycleProblemCode(identity.status()), "Identity cannot sign."));
            }
            if (signHandler == null) return signWithKeyStore(identity, request, lifetime, context);
            return signHandler
                    .sign(identity, request, context)
                    .thenCompose(result -> result.map(response -> validateHandledSign(response, identity, request))
                            .orElseGet(() -> signWithKeyStore(identity, request, lifetime, context)));
        });
    }

    private CompletionStage<PlatformResponse<PlatformSignResponses.Response>> signWithKeyStore(
            PlatformIdentityRecord identity,
            PlatformSignRequest request,
            Duration lifetime,
            PlatformRequestContext context) {
        Instant issuedAt = context.now() == null ? clock.instant() : context.now();
        ClientAssertionClaims claims = new ClientAssertionClaims(
                identity.agentDid(),
                identity.agentDid(),
                request.serviceDid(),
                request.operation(),
                issuedAt.getEpochSecond(),
                issuedAt.plus(lifetime).getEpochSecond(),
                request.jwtId(),
                request.resource());
        AepValidation.requireClientAssertionClaims(claims, false);
        return keyStore.sign(identity, claims, context)
                .thenApply(assertion ->
                        success(200, (PlatformSignResponses.Response) new PlatformSignResponses.Completed(
                                "completed",
                                identity.agentDid(),
                                requireGenerated(assertion, "client assertion"),
                                DateTimeFormatter.ISO_INSTANT.format(issuedAt.plus(lifetime)),
                                DateTimeFormatter.ISO_INSTANT.format(issuedAt),
                                request.jwtId(),
                                request.platformContext(),
                                request.serviceDid())));
    }

    private CompletionStage<PlatformResponse<PlatformSignResponses.Response>> validateHandledSign(
            PlatformResponse<PlatformSignResponses.Response> response,
            PlatformIdentityRecord identity,
            PlatformSignRequest request) {
        // PLT-SIGN-017 keeps the HTTP Retry-After header off this contract entirely, not only off a
        // pending response: polling cadence travels in retry_after_seconds. The header is checked
        // before the Problem Details branch so a handler cannot smuggle it in on an error either.
        if (hasRetryAfter(response.headers())) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Platform sign handler must not send a Retry-After header."));
        }
        if (validProblem(response)) return completed(response);
        // PLT-SIGN-010 caps the effective assertion lifetime, and the configured maximum may cut it
        // shorter. This runs ahead of the schema gate so an unparseable or unbounded validity window
        // is reported as the lifetime failure it is rather than as a generic shape mismatch.
        if (response.body() instanceof PlatformSignResponses.Completed bounded && !boundedLifetime(bounded)) {
            return CompletableFuture.failedFuture(new IllegalArgumentException(
                    "Platform sign handler returned an assertion lifetime outside the permitted window."));
        }
        if ((response.status() != 200 && response.status() != 202)
                || !Aep.MEDIA_TYPE.equals(response.contentType())
                || response.body() == null
                || response.problem() != null
                || !AepValidation.platformSignResponse(response.body()).isEmpty()) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Platform sign handler returned an invalid response."));
        }
        if (response.body() instanceof PlatformSignResponses.Completed completed
                && (!identity.agentDid().equals(completed.agentDid())
                        || !request.serviceDid().equals(completed.serviceDid())
                        || !request.jwtId().equals(completed.jwtId())
                        || response.status() != 200)) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Platform sign handler response does not match the request."));
        }
        if (response.body() instanceof PlatformSignResponses.Pending && response.status() != 202) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Pending Platform signing must return 202."));
        }
        return completed(response);
    }

    private CompletionStage<PlatformResponse<PlatformVerificationResponse>> verifyAuthorized(
            PlatformVerificationRequest request, PlatformRequestContext context) {
        String keyId = assertionKeyId(request.clientAssertion());
        ClientAssertionClaims decoded;
        try {
            decoded = ClientAssertions.decodeUnverified(request.clientAssertion());
        } catch (IllegalArgumentException exception) {
            return completed(unrecognized(request.serviceDid()));
        }
        // PLT-SIGN-022 binds the JOSE kid of a Platform-hosted identity to the Service-scoped Agent
        // DID carried in key_id, with no verification-method fragment. AEP core accepts a fragment
        // because an ordinary did:web Agent may publish several methods, so the Platform-specific
        // narrowing has to happen here.
        if (decoded.issuer() == null
                || !decoded.issuer().equals(decoded.subject())
                || !decoded.issuer().equals(keyId)) {
            return completed(unrecognized(request.serviceDid()));
        }
        return identityStore.findByAgentDid(decoded.issuer()).thenCompose(identity -> {
            if (identity.isEmpty()
                    || !identity.get().serviceDid().equals(request.serviceDid())
                    || !identity.get().keyId().equals(keyId)) {
                return completed(unrecognized(request.serviceDid()));
            }
            PlatformIdentityRecord record = identity.get();
            return authorizer
                    .authorize(PlatformAuthorizationRequest.verify(record, request), context)
                    .thenCompose(authorized -> {
                        if (!authorized) return completed(unrecognized(request.serviceDid()));
                        // PLT-VER-004 makes the current lifecycle state part of what verification
                        // checks, and PLT-LIFE-002 settles what that state has to be. As on the
                        // signing path, the configured policy narrows this floor rather than
                        // replacing it.
                        return idempotent(
                                PlatformIdempotentOperation.HOSTED_VERIFICATION,
                                listIncludingNulls(
                                        request.clientAssertion(),
                                        request.operation().value(),
                                        request.resource(),
                                        request.serviceDid()),
                                context,
                                () -> lifecyclePolicy
                                        .canVerify(record, context)
                                        .thenCompose(allowed -> allowed && record.status() == ManagedAgentStatus.ACTIVE
                                                ? verifyAssertion(record, request, context)
                                                : completed(unrecognized(request.serviceDid()))));
                    });
        });
    }

    private CompletionStage<PlatformResponse<PlatformVerificationResponse>> verifyAssertion(
            PlatformIdentityRecord identity, PlatformVerificationRequest request, PlatformRequestContext context) {
        Instant now = context.now() == null ? clock.instant() : context.now();
        return keyStore.verificationKey(identity, context).thenCompose(key -> {
            ClientAssertionClaims claims;
            try {
                claims = ClientAssertions.verify(
                        request.clientAssertion(),
                        key,
                        ClientAssertionVerification.builder(
                                        request.serviceDid(), identity.agentDid(), request.operation())
                                .clock(Clock.fixed(now, ZoneOffset.UTC))
                                .resource(request.resource())
                                .build());
            } catch (IllegalArgumentException exception) {
                return completed(unrecognized(request.serviceDid()));
            }
            String replayKey = request.serviceDid()
                    + '\0'
                    + request.operation().value()
                    + '\0'
                    + identity.agentDid()
                    + '\0'
                    + claims.jwtId();
            return replayStore
                    .consume(replayKey, Instant.ofEpochSecond(claims.expiresAt()), now, context)
                    .thenApply(consumed -> consumed
                            ? success(
                                    200,
                                    new PlatformVerificationResponse(
                                            identity.agentDid(),
                                            identity.agentIdentityId(),
                                            request.operation(),
                                            "verified",
                                            request.serviceDid(),
                                            identity.status(),
                                            true))
                            : unrecognized(request.serviceDid()));
        });
    }

    private CompletionStage<Optional<PlatformIdentityRecord>> authorizedIdentity(
            String agentIdentityId,
            PlatformRequestContext context,
            Function<PlatformIdentityRecord, PlatformAuthorizationRequest> request) {
        if (agentIdentityId == null || agentIdentityId.isBlank()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return identityStore.get(agentIdentityId).thenCompose(identity -> {
            if (identity.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
            PlatformIdentityRecord record = identity.get();
            return authorizer
                    .authorize(request.apply(record), context)
                    .thenApply(authorized -> authorized
                                    && hasPrincipal(context)
                                    && record.principal().equals(context.principal())
                            ? Optional.of(record)
                            : Optional.empty());
        });
    }

    private <T> CompletionStage<PlatformResponse<T>> idempotent(
            PlatformIdempotentOperation operation,
            Object material,
            PlatformRequestContext context,
            Supplier<CompletionStage<PlatformResponse<T>>> execute) {
        PlatformIdempotencyInput input = new PlatformIdempotencyInput(
                context.principal(), context.idempotencyKey(), operation, fingerprint(material));
        return idempotencyStore
                .execute(input, execute)
                .thenApply(result -> result.state() == PlatformIdempotencyResult.State.CONFLICT
                        ? problem(409, "idempotency_conflict", "Idempotency key conflicts with an earlier request.")
                        : result.response());
    }

    private static boolean hasIdempotencyContext(PlatformRequestContext context) {
        return hasPrincipal(context)
                && context.idempotencyKey() != null
                && !context.idempotencyKey().isBlank();
    }

    private static PlatformAgentIdentity publicIdentity(PlatformIdentityRecord identity) {
        return new PlatformAgentIdentity(
                identity.agentDid(),
                identity.agentIdentityId(),
                DateTimeFormatter.ISO_INSTANT.format(identity.createdAt()),
                identity.didDocumentUrl(),
                identity.keyId(),
                identity.serviceDid(),
                identity.signingAlgorithms(),
                identity.status(),
                DateTimeFormatter.ISO_INSTANT.format(identity.updatedAt()));
    }

    private static PlatformDidDocument didDocument(
            PlatformIdentityRecord identity, PlatformDidVerificationMethod method) {
        if (!identity.agentDid().equals(method.id()) || !identity.agentDid().equals(method.controller())) {
            throw new IllegalArgumentException("Platform DID verification method must use the Agent DID as its ID.");
        }
        return new PlatformDidDocument(
                List.of("https://www.w3.org/ns/did/v1"),
                List.of(identity.agentDid()),
                identity.agentDid(),
                List.of(method));
    }

    private static PlatformResponse<PlatformVerificationResponse> unrecognized(String serviceDid) {
        return success(
                200, new PlatformVerificationResponse(null, null, null, NOT_RECOGNIZED, serviceDid, null, false));
    }

    private String createServiceScopedAgentDid(String agentDidId) {
        List<String> components = new ArrayList<>();
        components.add("did:web");
        components.add(encodeDidComponent(didHost));
        // normalizeDidPathPrefix has already refused a blank, ".", or ".." component, so every split
        // part is a real path segment.
        for (String component : didPathPrefix.split("/")) {
            components.add(encodeDidComponent(component));
        }
        components.add(encodeDidComponent(agentDidId));
        return String.join(":", components);
    }

    // requirePlatformDiscoveryDocument has already established that the template names
    // {agent_did_id} and renders an absolute HTTPS URL carrying no user information and no fragment,
    // and encodePathSegment keeps a generated identifier inside a single path segment. The shape the
    // constructor probed is therefore the shape every identity gets.
    private String renderDidDocumentUrl(String agentDidId) {
        return platformDiscovery.identity().didUrlTemplate().replace("{agent_did_id}", encodePathSegment(agentDidId));
    }

    // PLT-DID-005 lets a Service treat a Platform-hosted Agent DID as an ordinary did:web DID, and
    // PLT-DISC-006 makes did_url_template describe where those documents actually live. The DID host,
    // the DID path prefix, and the template are configured independently, so nothing stopped a
    // Platform from advertising a did_document_url no Service would ever fetch. Probing both with one
    // identifier settles it at construction instead of at the first Service handshake.
    private void validateDidUrlTemplate() {
        String rendered = renderDidDocumentUrl(DID_URL_PROBE);
        URI resolved = DidWeb.documentUri(createServiceScopedAgentDid(DID_URL_PROBE));
        if (!rendered.equals(resolved.toString())) {
            throw new IllegalArgumentException("did_url_template renders " + rendered
                    + " where resolving the minted Agent DID reaches " + resolved + ".");
        }
    }

    // A sign handler mints its own issued_at and expires_at, so the bound the key-store path inherits
    // from the validated request has to be re-checked against what the handler actually returned.
    private boolean boundedLifetime(PlatformSignResponses.Completed completed) {
        Instant issuedAt;
        Instant expiresAt;
        try {
            issuedAt = OffsetDateTime.parse(completed.issuedAt()).toInstant();
            expiresAt = OffsetDateTime.parse(completed.expiresAt()).toInstant();
        } catch (DateTimeParseException exception) {
            return false;
        }
        Duration lifetime = Duration.between(issuedAt, expiresAt);
        return !lifetime.isZero() && !lifetime.isNegative() && lifetime.compareTo(maximumLifetime) <= 0;
    }

    private static boolean hasRetryAfter(Map<String, List<String>> headers) {
        return headers.keySet().stream().anyMatch(name -> "retry-after".equalsIgnoreCase(name));
    }

    // Returns null for a token that is not a signed JWT or carries no kid, which the caller then
    // fails on the Agent DID comparison rather than by unwinding a second parse failure.
    private static String assertionKeyId(String assertion) {
        try {
            return SignedJWT.parse(assertion).getHeader().getKeyID();
        } catch (ParseException exception) {
            return null;
        }
    }

    private static String entityTag(PlatformDiscoveryDocument document) {
        return "\"sha256:" + fingerprint(discoveryMaterial(document)) + "\"";
    }

    private static List<Object> discoveryMaterial(PlatformDiscoveryDocument document) {
        return listIncludingNulls(
                document.version(),
                document.endpoints().hostedVerification(),
                document.endpoints().lifecycle(),
                document.endpoints().list(),
                document.endpoints().provision(),
                document.endpoints().sign(),
                document.http().endpointBase(),
                document.identity().didMethods(),
                document.identity().didUrlTemplate(),
                document.platform().did(),
                document.platform().hostedVerification(),
                document.platform().name(),
                document.signing().algorithms(),
                document.signing().defaultLifetimeSeconds());
    }

    private static boolean validListQuery(PlatformIdentityListQuery query) {
        return query.limit() >= 1
                && query.limit() <= MAX_LIST_LIMIT
                && query.offset() >= 0
                && (query.serviceDid() == null || query.serviceDid().startsWith("did:"));
    }

    private static Map<String, Object> requestMaterial(PlatformSignRequest request) {
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("jti", request.jwtId());
        material.put("lifetime_seconds", request.lifetimeSeconds());
        material.put("op", request.operation().value());
        material.put("platform_context", request.platformContext());
        material.put("resource", request.resource());
        material.put("service_did", request.serviceDid());
        return material;
    }

    private static List<Object> listIncludingNulls(Object... values) {
        List<Object> result = new ArrayList<>(values.length);
        java.util.Collections.addAll(result, values);
        return result;
    }

    private static String fingerprint(Object value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            canonical(value, digest);
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    private static void canonical(Object value, MessageDigest digest) {
        if (value == null) {
            update(digest, "null", "");
        } else if (value instanceof String string) {
            update(digest, "string", string);
        } else if (value instanceof Number number) {
            update(digest, "number", number.toString());
        } else if (value instanceof Boolean bool) {
            update(digest, "boolean", bool.toString());
        } else if (value instanceof List<?> list) {
            update(digest, "list", Integer.toString(list.size()));
            list.forEach(item -> canonical(item, digest));
        } else if (value instanceof Map<?, ?> map) {
            List<Map.Entry<?, ?>> entries = new ArrayList<>(map.entrySet());
            entries.sort(Comparator.comparing(entry -> String.valueOf(entry.getKey())));
            update(digest, "map", Integer.toString(entries.size()));
            for (Map.Entry<?, ?> entry : entries) {
                canonical(entry.getKey(), digest);
                canonical(entry.getValue(), digest);
            }
        } else {
            throw new IllegalArgumentException("Idempotency material must be JSON-compatible.");
        }
    }

    private static void update(MessageDigest digest, String type, String value) {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        digest.update(type.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
        digest.update(encoded);
    }

    private static String encodeDidComponent(String value) {
        return encodePathSegment(value);
    }

    private static String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String requireDidHost(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("didHost is required.");
        URI uri = URI.create("https://" + value);
        if (uri.getHost() == null || uri.getUserInfo() != null || !uri.getPath().isEmpty()) {
            throw new IllegalArgumentException("didHost must be a host with an optional port.");
        }
        return value;
    }

    private static String normalizeDidPathPrefix(String value) {
        String prefix = value == null || value.isBlank() ? "agents" : value;
        for (String component : prefix.split("/")) {
            if (component.isBlank() || ".".equals(component) || "..".equals(component)) {
                throw new IllegalArgumentException("didPathPrefix contains an invalid path component.");
            }
        }
        return prefix;
    }

    private static Duration requireLifetime(Duration value, Duration maximum, String name) {
        if (value == null
                || value.isZero()
                || value.isNegative()
                || value.compareTo(maximum) > 0
                || value.toNanosPart() != 0) {
            throw new IllegalArgumentException(name + " must be a whole number of seconds within 300 seconds.");
        }
        return value;
    }

    private static String requireGenerated(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank.");
        return value;
    }

    private static boolean hasPrincipal(PlatformRequestContext context) {
        return context != null
                && context.principal() != null
                && !context.principal().isBlank();
    }

    private static PlatformRequestContext context(PlatformRequestContext context) {
        return context == null ? new PlatformRequestContext(null, null) : context;
    }

    // RFC 9457 makes the status member the HTTP status code of the response it travels in, so a
    // handler reporting one code in the body and another on the wire has produced a Problem Details
    // document no client can act on consistently.
    private static boolean validProblem(PlatformResponse<?> response) {
        return response.status() >= 400
                && Aep.PROBLEM_MEDIA_TYPE.equals(response.contentType())
                && response.body() == null
                && response.problem() != null
                && response.problem().status() == response.status()
                && AepValidation.problemDetails(response.problem()).isEmpty();
    }

    private static String lifecycleProblemCode(ManagedAgentStatus status) {
        if (status == ManagedAgentStatus.TERMINATED) return "identity_terminated";
        if (status == ManagedAgentStatus.SUSPENDED || status == ManagedAgentStatus.REVOKED) {
            return "identity_suspended";
        }
        return "identity_unavailable";
    }

    private static <T> PlatformResponse<T> success(int status, T body) {
        return success(status, body, Aep.MEDIA_TYPE, Map.of());
    }

    private static <T> PlatformResponse<T> success(
            int status, T body, String contentType, Map<String, List<String>> headers) {
        return new PlatformResponse<>(status, contentType, body, null, headers);
    }

    private static <T> PlatformResponse<T> problem(int status, String code, String title) {
        return new PlatformResponse<>(
                status, Aep.PROBLEM_MEDIA_TYPE, null, ProblemDetails.of(code, title, status), Map.of());
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    public static final class Builder {
        private final PlatformDiscoveryDocument configuredDiscovery;
        private final String configuredDidHost;
        private final PlatformAuthorizer configuredAuthorizer;
        private final PlatformKeyStore configuredKeyStore;
        private final PlatformServiceDidResolver configuredServiceDidResolver;
        private PlatformIdentityStore configuredIdentityStore = PlatformIdentityStore.inMemory();
        private PlatformIdempotencyStore configuredIdempotencyStore;
        private PlatformLifecyclePolicy configuredLifecyclePolicy = PlatformLifecyclePolicy.permissiveTransitions();
        private PlatformReplayStore configuredReplayStore;
        private PlatformSignHandler configuredSignHandler;
        private Clock configuredClock = Clock.systemUTC();
        private Duration configuredMaximumLifetime = MAX_ASSERTION_LIFETIME;
        private String configuredDidPathPrefix = "agents";
        private Supplier<String> configuredIdentityIdSupplier =
                () -> UUID.randomUUID().toString().replace("-", "");
        private Supplier<String> configuredAgentDidIdSupplier =
                () -> UUID.randomUUID().toString().replace("-", "");

        private Builder(
                PlatformDiscoveryDocument discovery,
                String didHost,
                PlatformAuthorizer authorizer,
                PlatformKeyStore keyStore,
                PlatformServiceDidResolver serviceDidResolver) {
            configuredDiscovery = discovery;
            configuredDidHost = didHost;
            configuredAuthorizer = authorizer;
            configuredKeyStore = keyStore;
            configuredServiceDidResolver = serviceDidResolver;
        }

        public Builder identityStore(PlatformIdentityStore value) {
            configuredIdentityStore = Objects.requireNonNull(value, "identityStore");
            return this;
        }

        public Builder idempotencyStore(PlatformIdempotencyStore value) {
            configuredIdempotencyStore = Objects.requireNonNull(value, "idempotencyStore");
            return this;
        }

        public Builder lifecyclePolicy(PlatformLifecyclePolicy value) {
            configuredLifecyclePolicy = Objects.requireNonNull(value, "lifecyclePolicy");
            return this;
        }

        public Builder replayStore(PlatformReplayStore value) {
            configuredReplayStore = Objects.requireNonNull(value, "replayStore");
            return this;
        }

        public Builder signHandler(PlatformSignHandler value) {
            configuredSignHandler = Objects.requireNonNull(value, "signHandler");
            return this;
        }

        public Builder clock(Clock value) {
            configuredClock = Objects.requireNonNull(value, "clock");
            return this;
        }

        public Builder maximumLifetime(Duration value) {
            configuredMaximumLifetime = Objects.requireNonNull(value, "maximumLifetime");
            return this;
        }

        public Builder didPathPrefix(String value) {
            configuredDidPathPrefix = value;
            return this;
        }

        public Builder identityIdSupplier(Supplier<String> value) {
            configuredIdentityIdSupplier = Objects.requireNonNull(value, "identityIdSupplier");
            return this;
        }

        public Builder agentDidIdSupplier(Supplier<String> value) {
            configuredAgentDidIdSupplier = Objects.requireNonNull(value, "agentDidIdSupplier");
            return this;
        }

        public AepPlatform build() {
            return new AepPlatform(this);
        }
    }
}
