package foundation.aep.agent;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidation;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.DidWeb;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformAgentIdentityListResponse;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import java.math.BigInteger;
import java.net.IDN;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

public final class PlatformIdentityProvider implements AgentIdentityProvider {
    private static final Duration DEFAULT_DISCOVERY_FRESHNESS = Duration.ofMinutes(5);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final int DEFAULT_MAXIMUM_REDIRECTS = 5;
    private static final int DEFAULT_MAXIMUM_RESPONSE_BYTES = 1_048_576;
    private static final int HTTP_NOT_MODIFIED = 304;
    private static final String IDENTITY_PARAMETER = "{agent_identity_id}";
    private static final String PLATFORM_DISCOVERY_REDIRECT = "platform_discovery_redirect";
    private static final String PLATFORM_IDENTITY_INVALID = "platform_identity_invalid";

    private final URI platformOrigin;
    private final AepHttpTransport transport;
    private final PlatformAuthenticationHeadersProvider authenticationHeaders;
    private final String authorization;
    private final Supplier<String> idempotencyKeys;
    private final PlatformContextProvider platformContext;
    private final PlatformPendingSignResolver pendingSignResolver;
    private final Clock clock;
    private final Duration defaultDiscoveryFreshness;
    private final Duration requestTimeout;
    private final int maximumRedirects;
    private final int maximumResponseBytes;
    private final boolean allowInsecureLoopback;

    private Optional<DiscoveryEntry> cachedDiscovery = Optional.empty();
    private Optional<CompletableFuture<DiscoveryEntry>> discoveryInFlight = Optional.empty();

    private PlatformIdentityProvider(Builder builder) {
        platformOrigin = Builder.origin(builder.requestedPlatformOrigin, builder.configuredAllowInsecureLoopback);
        transport = builder.configuredTransport;
        authenticationHeaders = builder.configuredAuthenticationHeaders;
        authorization = builder.configuredAuthorization;
        idempotencyKeys = builder.configuredIdempotencyKeys;
        platformContext = builder.configuredPlatformContext;
        pendingSignResolver = builder.configuredPendingSignResolver;
        clock = builder.configuredClock;
        defaultDiscoveryFreshness = builder.configuredDefaultDiscoveryFreshness;
        requestTimeout = builder.configuredRequestTimeout;
        maximumRedirects = builder.configuredMaximumRedirects;
        maximumResponseBytes = builder.configuredMaximumResponseBytes;
        allowInsecureLoopback = builder.configuredAllowInsecureLoopback;
    }

    public static Builder builder(URI platformOrigin) {
        return new Builder(platformOrigin);
    }

    @Override
    public CompletionStage<AgentIdentity> getOrCreate(URI serviceOrigin, String serviceDid) {
        requireDid(serviceDid, "serviceDid");
        URI origin = AgentHttp.origin(serviceOrigin, allowInsecureLoopback);
        if (!bindsServiceDid(serviceDid, origin)) {
            return failed("service_identity_mismatch", "AEP Service DID does not bind the Service origin");
        }
        return findIdentityByServiceDid(serviceDid)
                .thenCompose(
                        existing -> existing.map(identity -> CompletableFuture.completedFuture(agentIdentity(identity)))
                                .orElseGet(() -> provision(serviceDid).thenApply(this::agentIdentity)));
    }

    public CompletionStage<Optional<PlatformAgentIdentity>> findIdentityByServiceDid(String serviceDid) {
        requireDid(serviceDid, "serviceDid");
        return discover().thenCompose(discovery -> {
            URI endpoint = endpoint(discovery.document().endpoints().list(), null);
            String query = "descending=true&limit=100&service_did=" + queryValue(serviceDid);
            return command("GET", URI.create(endpoint + "?" + query), null, null)
                    .thenApply(response -> {
                        PlatformAgentIdentityListResponse listed =
                                AepJson.parsePlatformAgentIdentityListResponse(AgentHttp.body(response));
                        requireValidIdentityList(listed, discovery.document());
                        return listed.data().stream()
                                .filter(candidate -> serviceDid.equals(candidate.serviceDid()))
                                .filter(candidate -> candidate.status() == ManagedAgentStatus.ACTIVE)
                                .findFirst();
                    });
        });
    }

    private CompletableFuture<PlatformAgentIdentity> provision(String serviceDid) {
        return discover().thenCompose(discovery -> {
            PlatformProvisionRequest request = new PlatformProvisionRequest(serviceDid);
            requireValid("Platform provision request", AepValidation.platformProvisionRequest(request));
            return command(
                            "POST",
                            endpoint(discovery.document().endpoints().provision(), null),
                            idempotencyKey(),
                            request)
                    .thenApply(response -> {
                        PlatformAgentIdentity identity = AepJson.parsePlatformAgentIdentity(AgentHttp.body(response));
                        requireUsableIdentity(identity, discovery.document());
                        if (!serviceDid.equals(identity.serviceDid())
                                || identity.status() != ManagedAgentStatus.ACTIVE) {
                            throw new AepAgentException(
                                    "platform_identity_mismatch",
                                    "AEP Platform provisioned an identity outside the requested Service scope");
                        }
                        return identity;
                    });
        });
    }

    private AgentIdentity agentIdentity(PlatformAgentIdentity identity) {
        return new AgentIdentity(identity.agentDid(), claims -> sign(identity, claims));
    }

    private CompletableFuture<String> sign(PlatformAgentIdentity identity, ClientAssertionClaims claims) {
        AepValidation.requireClientAssertionClaims(claims, allowInsecureLoopback);
        if (!identity.agentDid().equals(claims.issuer())
                || !identity.agentDid().equals(claims.subject())
                || !identity.serviceDid().equals(claims.audience())) {
            return failed("platform_identity_mismatch", "AEP Platform signer received claims for another identity");
        }
        CompletionStage<Map<String, Object>> initial = platformContext == null
                ? CompletableFuture.completedFuture(null)
                : platformContext.context(identity, claims);
        return future(initial).thenCompose(context -> sign(identity, claims, PlatformJson.copyMap(context), null));
    }

    private CompletableFuture<String> sign(
            PlatformAgentIdentity identity,
            ClientAssertionClaims claims,
            Map<String, Object> context,
            String previousIdempotencyKey) {
        String idempotencyKey = idempotencyKey();
        if (idempotencyKey.equals(previousIdempotencyKey)) {
            return failed(
                    "platform_idempotency_key_reused",
                    "AEP Platform pending Sign stages require distinct idempotency keys");
        }
        return discover().thenCompose(discovery -> {
            PlatformSignRequest request = new PlatformSignRequest(
                    claims.jwtId(),
                    Long.toString(claims.expiresAt() - claims.issuedAt()),
                    claims.operation(),
                    context,
                    claims.resource(),
                    claims.audience());
            requireValid("Platform Sign request", AepValidation.platformSignRequest(request));
            URI uri = endpoint(discovery.document().endpoints().sign(), identity.agentIdentityId());
            return command("POST", uri, idempotencyKey, request).thenCompose(response -> {
                PlatformSignResponses.Response result = AepJson.parsePlatformSignResponse(AgentHttp.body(response));
                if (result instanceof PlatformSignResponses.Completed completed) {
                    requireCompletedSign(response.status(), completed, identity, claims);
                    return CompletableFuture.completedFuture(completed.clientAssertion());
                }
                PlatformSignResponses.Pending pending = (PlatformSignResponses.Pending) result;
                if (response.status() != 202
                        || AgentHttp.header(response, "Retry-After").isPresent()) {
                    return failed("platform_sign_invalid", "AEP Platform returned an invalid pending Sign response");
                }
                int retryAfter = Integer.parseInt(pending.retryAfterSeconds());
                PlatformPendingSign pendingSign =
                        new PlatformPendingSign(identity, pending.platformContext(), retryAfter);
                if (pendingSignResolver == null) {
                    return CompletableFuture.failedFuture(new PlatformSignPendingException(pendingSign));
                }
                return future(pendingSignResolver.resolve(pendingSign))
                        .thenCompose(next -> sign(identity, claims, PlatformJson.copyMap(next), idempotencyKey));
            });
        });
    }

    private static void requireCompletedSign(
            int status,
            PlatformSignResponses.Completed completed,
            PlatformAgentIdentity identity,
            ClientAssertionClaims claims) {
        Instant issued;
        Instant expires;
        try {
            issued = Instant.parse(completed.issuedAt());
            expires = Instant.parse(completed.expiresAt());
        } catch (DateTimeParseException exception) {
            throw new AepAgentException(
                    "platform_sign_invalid", "AEP Platform returned invalid Sign timestamps", exception);
        }
        long requestedLifetime = claims.expiresAt() - claims.issuedAt();
        if (status != 200
                || !identity.agentDid().equals(completed.agentDid())
                || !identity.serviceDid().equals(completed.serviceDid())
                || !claims.jwtId().equals(completed.jwtId())
                || Duration.between(issued, expires).getSeconds() != requestedLifetime) {
            throw new AepAgentException(
                    "platform_sign_invalid", "AEP Platform returned an invalid completed Sign response");
        }
    }

    private CompletableFuture<AepHttpTransport.Response> command(
            String method, URI uri, String idempotencyKey, Object body) {
        CompletionStage<Map<String, List<String>>> supplied = authenticationHeaders == null
                ? CompletableFuture.completedFuture(Map.of())
                : authenticationHeaders.headers();
        return future(supplied).thenCompose(values -> {
            Map<String, List<String>> headers = commandHeaders(values, idempotencyKey, body != null);
            byte[] encoded = body == null ? new byte[0] : AepJson.write(body).getBytes(StandardCharsets.UTF_8);
            AepHttpTransport.Request request =
                    new AepHttpTransport.Request(method, uri, headers, encoded, requestTimeout);
            return future(transport.execute(request)).thenApply(response -> {
                AgentHttp.requireBodyLimit(response, maximumResponseBytes);
                if (isRedirect(response.status())) {
                    throw new AepAgentException(
                            "platform_command_redirect", "AEP Platform commands must not follow redirects");
                }
                if (response.status() < 200 || response.status() >= 300) {
                    throw AgentHttp.commandError(response);
                }
                AgentHttp.requireMediaType(response, Aep.MEDIA_TYPE);
                return response;
            });
        });
    }

    private Map<String, List<String>> commandHeaders(
            Map<String, List<String>> supplied, String idempotencyKey, boolean hasBody) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        if (authorization != null) putHeader(headers, "Authorization", List.of(authorization));
        if (supplied != null) {
            supplied.forEach((name, values) -> {
                if (!ownedHeader(name)) {
                    putHeader(headers, requireHeaderName(name), requireHeaderValues(values));
                }
            });
        }
        headers.put("Accept", List.of(Aep.MEDIA_TYPE));
        if (hasBody) headers.put("Content-Type", List.of(Aep.MEDIA_TYPE));
        if (idempotencyKey != null) headers.put("Idempotency-Key", List.of(idempotencyKey));
        return Map.copyOf(headers);
    }

    private synchronized CompletableFuture<DiscoveryEntry> discover() {
        Optional<DiscoveryEntry> fresh =
                cachedDiscovery.filter(entry -> entry.expiresAt().isAfter(clock.instant()));
        if (fresh.isPresent()) {
            return CompletableFuture.completedFuture(fresh.orElseThrow());
        }
        if (discoveryInFlight.isPresent()) {
            return discoveryInFlight.orElseThrow().thenApply(value -> value);
        }
        URI requested = platformOrigin.resolve(Aep.PLATFORM_WELL_KNOWN_PATH);
        URI target = cachedDiscovery.map(DiscoveryEntry::finalUri).orElse(requested);
        CompletableFuture<DiscoveryEntry> created = fetchDiscovery(target, cachedDiscovery, 0);
        discoveryInFlight = Optional.of(created);
        created.whenComplete((value, failure) -> finishDiscovery(created, value, failure));
        return created.thenApply(value -> value);
    }

    private synchronized void finishDiscovery(
            CompletableFuture<DiscoveryEntry> flight, DiscoveryEntry value, Throwable failure) {
        if (!discoveryInFlight.filter(flight::equals).isPresent()) return;
        discoveryInFlight = Optional.empty();
        if (failure == null) cachedDiscovery = value.noStore() ? Optional.empty() : Optional.of(value);
    }

    private CompletableFuture<DiscoveryEntry> fetchDiscovery(
            URI target, Optional<DiscoveryEntry> prior, int redirects) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Accept", List.of(Aep.MEDIA_TYPE));
        prior.map(DiscoveryEntry::etag).ifPresent(value -> headers.put("If-None-Match", List.of(value)));
        prior.map(DiscoveryEntry::lastModified).ifPresent(value -> headers.put("If-Modified-Since", List.of(value)));
        AepHttpTransport.Request request =
                new AepHttpTransport.Request("GET", target, headers, new byte[0], requestTimeout);
        return future(transport.execute(request)).thenCompose(response -> {
            AgentHttp.requireBodyLimit(response, maximumResponseBytes);
            if (isRedirect(response.status())) {
                if (redirects >= maximumRedirects) {
                    return failed(PLATFORM_DISCOVERY_REDIRECT, "AEP Platform discovery redirect limit exceeded");
                }
                URI next = redirectTarget(target, response);
                return fetchDiscovery(next, prior, redirects + 1);
            }
            if (response.status() == HTTP_NOT_MODIFIED) {
                if (prior.isEmpty()) {
                    return failed(
                            "platform_discovery_invalid",
                            "AEP Platform discovery returned 304 without a cached document");
                }
                return CompletableFuture.completedFuture(
                        createDiscoveryEntry(prior.orElseThrow().document(), target, response, prior));
            }
            if (response.status() < 200 || response.status() >= 300) {
                return failed(
                        "platform_discovery_failed", "AEP Platform discovery failed with HTTP " + response.status());
            }
            AgentHttp.requireMediaType(response, Aep.MEDIA_TYPE);
            PlatformDiscoveryDocument document = AepJson.parsePlatformDiscoveryDocument(AgentHttp.body(response));
            return CompletableFuture.completedFuture(
                    createDiscoveryEntry(document, target, response, Optional.empty()));
        });
    }

    private DiscoveryEntry createDiscoveryEntry(
            PlatformDiscoveryDocument document,
            URI finalUri,
            AepHttpTransport.Response response,
            Optional<DiscoveryEntry> prior) {
        Instant now = clock.instant();
        return new DiscoveryEntry(
                document,
                finalUri,
                AgentHttp.header(response, "ETag")
                        .orElseGet(() -> prior.map(DiscoveryEntry::etag).orElse(null)),
                AgentHttp.header(response, "Last-Modified")
                        .orElseGet(() -> prior.map(DiscoveryEntry::lastModified).orElse(null)),
                AgentHttp.expiresAt(response, now, defaultDiscoveryFreshness),
                AgentHttp.isNoStore(response));
    }

    private URI redirectTarget(URI current, AepHttpTransport.Response response) {
        String location = AgentHttp.header(response, "Location")
                .orElseThrow(() -> new AepAgentException(
                        PLATFORM_DISCOVERY_REDIRECT, "AEP Platform discovery redirect omitted Location"));
        URI next;
        try {
            next = current.resolve(location);
        } catch (IllegalArgumentException exception) {
            throw new AepAgentException(
                    PLATFORM_DISCOVERY_REDIRECT, "AEP Platform discovery redirect is invalid", exception);
        }
        if (next.getUserInfo() != null
                || next.getRawFragment() != null
                || (!"https".equalsIgnoreCase(next.getScheme())
                        && !(allowInsecureLoopback && "http".equalsIgnoreCase(next.getScheme())))
                || !AgentHttp.sameOrigin(platformOrigin, next)) {
            throw new AepAgentException(
                    PLATFORM_DISCOVERY_REDIRECT, "AEP Platform discovery redirect changed origin or scheme");
        }
        return next;
    }

    private URI endpoint(String path, String identityId) {
        String value = path;
        if (identityId != null) value = value.replace(IDENTITY_PARAMETER, pathSegment(identityId));
        URI reference;
        try {
            reference = URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new AepAgentException(
                    "platform_endpoint_invalid", "AEP Platform advertised an invalid endpoint", exception);
        }
        if (!value.startsWith("/")
                || value.startsWith("//")
                || value.contains("{")
                || reference.isAbsolute()
                || reference.getRawQuery() != null
                || reference.getRawFragment() != null
                || reference.getUserInfo() != null) {
            throw new AepAgentException("platform_endpoint_invalid", "AEP Platform advertised an invalid endpoint");
        }
        URI resolved = platformOrigin.resolve(reference);
        if (!AgentHttp.sameOrigin(platformOrigin, resolved)) {
            throw new AepAgentException("platform_endpoint_invalid", "AEP Platform endpoint changed origin");
        }
        return resolved;
    }

    private String idempotencyKey() {
        String value = idempotencyKeys.get();
        if (value == null || value.isBlank()) {
            throw new AepAgentException(
                    "platform_idempotency_key_invalid", "AEP Platform idempotency key must not be blank");
        }
        return value;
    }

    private static boolean ownedHeader(String name) {
        return name != null
                && ("Accept".equalsIgnoreCase(name)
                        || "Content-Type".equalsIgnoreCase(name)
                        || "Idempotency-Key".equalsIgnoreCase(name));
    }

    private static void putHeader(Map<String, List<String>> headers, String name, List<String> values) {
        headers.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
        headers.put(name, values);
    }

    private static String requireHeaderName(String name) {
        if (name == null || name.isBlank() || name.indexOf('\r') >= 0 || name.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("AEP Platform authentication header name is invalid.");
        }
        return name;
    }

    private static List<String> requireHeaderValues(List<String> values) {
        Objects.requireNonNull(values, "header values");
        if (values.isEmpty()) {
            throw new IllegalArgumentException("AEP Platform authentication header values must not be empty.");
        }
        List<String> result = new ArrayList<>(values.size());
        for (String value : values) {
            if (value == null || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("AEP Platform authentication header value is invalid.");
            }
            result.add(value);
        }
        return List.copyOf(result);
    }

    private static String pathSegment(String value) {
        if (value == null || value.isEmpty()) {
            throw new AepAgentException(
                    PLATFORM_IDENTITY_INVALID, "AEP Platform identity identifier must not be empty");
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder encoded = new StringBuilder(bytes.length);
        for (byte item : bytes) {
            int character = item & 0xff;
            if ((character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || '-' == character
                    || '.' == character
                    || '_' == character
                    || '~' == character) {
                encoded.append((char) character);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit(character >>> 4, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(character & 0x0f, 16)));
            }
        }
        return encoded.toString();
    }

    private static String queryValue(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static void requireDid(String value, String name) {
        if (value == null || !value.startsWith("did:") || value.length() == 4) {
            throw new IllegalArgumentException(name + " must be a DID");
        }
    }

    private static void requireValid(String documentType, List<foundation.aep.core.ValidationIssue> issues) {
        if (!issues.isEmpty()) throw new AepValidationException(documentType, issues);
    }

    private void requireValidIdentityList(PlatformAgentIdentityListResponse list, PlatformDiscoveryDocument discovery) {
        BigInteger count = new BigInteger(list.count());
        BigInteger total = new BigInteger(list.total());
        if (total.compareTo(count) < 0) {
            throw new AepAgentException(PLATFORM_IDENTITY_INVALID, "AEP Platform returned an invalid identity list");
        }
        list.data().forEach(identity -> requireUsableIdentity(identity, discovery));
    }

    private void requireUsableIdentity(PlatformAgentIdentity identity, PlatformDiscoveryDocument discovery) {
        if (!identity.agentDid().startsWith("did:web:")
                || !identity.agentDid().equals(identity.keyId())
                || identity.signingAlgorithms().stream()
                        .anyMatch(algorithm -> !discovery.signing().algorithms().contains(algorithm))) {
            throw new AepAgentException(PLATFORM_IDENTITY_INVALID, "AEP Platform returned an invalid hosted identity");
        }
        URI expected;
        try {
            expected = DidWeb.documentUri(identity.agentDid(), allowInsecureLoopback);
        } catch (IllegalArgumentException exception) {
            throw new AepAgentException(
                    PLATFORM_IDENTITY_INVALID, "AEP Platform returned an invalid hosted identity", exception);
        }
        if (!expected.equals(URI.create(identity.didDocumentUrl()))) {
            throw new AepAgentException(
                    PLATFORM_IDENTITY_INVALID, "AEP Platform DID document URL does not match the Agent DID");
        }
    }

    private boolean bindsServiceDid(String serviceDid, URI serviceOrigin) {
        if (!allowInsecureLoopback) return DidWeb.bindsOrigin(serviceDid, serviceOrigin);
        try {
            return AgentHttp.sameOrigin(DidWeb.documentUri(serviceDid, true), serviceOrigin);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private static <T> CompletableFuture<T> future(CompletionStage<T> stage) {
        if (stage == null) return CompletableFuture.failedFuture(new NullPointerException("CompletionStage"));
        CompletableFuture<T> result = new CompletableFuture<>();
        stage.whenComplete((value, failure) -> {
            if (failure == null) result.complete(value);
            else result.completeExceptionally(unwrap(failure));
        });
        return result;
    }

    private static Throwable unwrap(Throwable failure) {
        if (failure instanceof CompletionException && failure.getCause() != null) return failure.getCause();
        return failure;
    }

    private static <T> CompletableFuture<T> failed(String code, String message) {
        return CompletableFuture.failedFuture(new AepAgentException(code, message));
    }

    private record DiscoveryEntry(
            PlatformDiscoveryDocument document,
            URI finalUri,
            String etag,
            String lastModified,
            Instant expiresAt,
            boolean noStore) {}

    public static final class Builder {
        private final URI requestedPlatformOrigin;
        private AepHttpTransport configuredTransport;
        private PlatformAuthenticationHeadersProvider configuredAuthenticationHeaders;
        private String configuredAuthorization;
        private Supplier<String> configuredIdempotencyKeys =
                () -> UUID.randomUUID().toString();
        private PlatformContextProvider configuredPlatformContext;
        private PlatformPendingSignResolver configuredPendingSignResolver;
        private Clock configuredClock = Clock.systemUTC();
        private Duration configuredDefaultDiscoveryFreshness = DEFAULT_DISCOVERY_FRESHNESS;
        private Duration configuredRequestTimeout = DEFAULT_REQUEST_TIMEOUT;
        private int configuredMaximumRedirects = DEFAULT_MAXIMUM_REDIRECTS;
        private int configuredMaximumResponseBytes = DEFAULT_MAXIMUM_RESPONSE_BYTES;
        private boolean configuredAllowInsecureLoopback;

        private Builder(URI value) {
            requestedPlatformOrigin = Objects.requireNonNull(value, "platformOrigin");
        }

        public Builder transport(AepHttpTransport value) {
            configuredTransport = Objects.requireNonNull(value, "transport");
            return this;
        }

        public Builder authenticationHeaders(PlatformAuthenticationHeadersProvider value) {
            configuredAuthenticationHeaders = Objects.requireNonNull(value, "authenticationHeaders");
            return this;
        }

        public Builder authorization(String value) {
            configuredAuthorization = requireHeaderValue(value, "authorization");
            return this;
        }

        public Builder idempotencyKeys(Supplier<String> value) {
            configuredIdempotencyKeys = Objects.requireNonNull(value, "idempotencyKeys");
            return this;
        }

        public Builder platformContext(PlatformContextProvider value) {
            configuredPlatformContext = Objects.requireNonNull(value, "platformContext");
            return this;
        }

        public Builder pendingSignResolver(PlatformPendingSignResolver value) {
            configuredPendingSignResolver = Objects.requireNonNull(value, "pendingSignResolver");
            return this;
        }

        public Builder clock(Clock value) {
            configuredClock = Objects.requireNonNull(value, "clock");
            return this;
        }

        public Builder defaultDiscoveryFreshness(Duration value) {
            configuredDefaultDiscoveryFreshness = positive(value, "defaultDiscoveryFreshness");
            return this;
        }

        public Builder requestTimeout(Duration value) {
            configuredRequestTimeout = positive(value, "requestTimeout");
            return this;
        }

        public Builder maximumRedirects(int value) {
            if (value < 0) throw new IllegalArgumentException("maximumRedirects must not be negative");
            configuredMaximumRedirects = value;
            return this;
        }

        public Builder maximumResponseBytes(int value) {
            if (value <= 0) throw new IllegalArgumentException("maximumResponseBytes must be positive");
            configuredMaximumResponseBytes = value;
            return this;
        }

        public Builder allowInsecureLoopback(boolean value) {
            configuredAllowInsecureLoopback = value;
            return this;
        }

        public PlatformIdentityProvider build() {
            Objects.requireNonNull(configuredTransport, "transport");
            return new PlatformIdentityProvider(this);
        }

        private static Duration positive(Duration value, String name) {
            Objects.requireNonNull(value, name);
            if (value.isZero() || value.isNegative()) throw new IllegalArgumentException(name + " must be positive");
            return value;
        }

        private static String requireHeaderValue(String value, String name) {
            if (value == null || value.isBlank() || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                throw new IllegalArgumentException(name + " must be a valid non-empty header value");
            }
            return value;
        }

        private static URI origin(URI value, boolean allowInsecureLoopback) {
            Objects.requireNonNull(value, "platformOrigin");
            String scheme = value.getScheme() == null ? "" : value.getScheme().toLowerCase(Locale.ROOT);
            boolean loopback = value.getHost() != null
                    && ("localhost".equalsIgnoreCase(value.getHost())
                            || "127.0.0.1".equals(value.getHost()) // NOPMD - Explicit loopback opt-in.
                            || "::1".equals(value.getHost()) // NOPMD - Explicit loopback opt-in.
                            || "[::1]".equals(value.getHost()));
            if (value.getHost() == null
                    || value.getUserInfo() != null
                    || (!"https".equals(scheme) && !(allowInsecureLoopback && loopback && "http".equals(scheme)))
                    || (!value.getPath().isEmpty() && !"/".equals(value.getPath()))
                    || value.getRawQuery() != null
                    || value.getRawFragment() != null) {
                throw new IllegalArgumentException("AEP Platform origin must be an HTTPS origin");
            }
            String host = IDN.toASCII(value.getHost()).toLowerCase(Locale.ROOT);
            return URI.create(scheme + "://" + host + (value.getPort() < 0 ? "" : ":" + value.getPort()));
        }
    }
}
