package foundation.aep.service;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AepHttp;
import foundation.aep.core.AepJson;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.AuthorizationScheme;
import foundation.aep.core.ProblemDetails;
import foundation.aep.core.ProtectedResourceAuthorization;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public final class AepServiceHttpHandler {
    public static final int DEFAULT_MAXIMUM_REQUEST_BYTES = 65_536;
    public static final String DEFAULT_INSPECT_CACHE_CONTROL = "public, max-age=300";
    private static final String ERROR_INVALID_REQUEST = "invalid_request";
    private static final String CACHE_CONTROL = "Cache-Control";
    private static final String NO_STORE = "no-store";
    private static final String SAFE_METHODS = "GET, HEAD";
    private static final int SINGLE_HEADER_VALUE = 1;

    private final AepService service;
    private final Map<AepCommand, String> commandRoutes;
    private final int requestByteLimit;
    private final String cacheControlValue;
    private final String entityTagValue;

    public AepServiceHttpHandler(AepService service) {
        this(service, DEFAULT_MAXIMUM_REQUEST_BYTES);
    }

    public AepServiceHttpHandler(AepService service, int maximumRequestBytes) {
        this(service, maximumRequestBytes, DEFAULT_INSPECT_CACHE_CONTROL);
    }

    public AepServiceHttpHandler(AepService service, int maximumRequestBytes, String inspectCacheControl) {
        this.service = Objects.requireNonNull(service, "service");
        if (maximumRequestBytes <= 0) throw new IllegalArgumentException("maximumRequestBytes must be positive.");
        requestByteLimit = maximumRequestBytes;
        cacheControlValue = requireFieldValue(inspectCacheControl, "inspectCacheControl");
        Map<AepCommand, String> configuredRoutes = new EnumMap<>(AepCommand.class);
        configuredRoutes.put(AepCommand.INSPECT, Aep.WELL_KNOWN_PATH);
        for (String command : service.inspectDocument().commands().supported()) {
            AepCommand parsed = command(command);
            if (parsed == AepCommand.INSPECT) continue;
            configuredRoutes.put(
                    parsed,
                    AepHttp.commandPath(parsed, service.inspectDocument().http().endpointBase()));
        }
        commandRoutes = Map.copyOf(configuredRoutes);
        entityTagValue = entityTag(AepJson.write(service.inspectDocument()));
    }

    public String inspectCacheControl() {
        return cacheControlValue;
    }

    public String inspectEntityTag() {
        return entityTagValue;
    }

    public Map<AepCommand, String> routes() {
        return commandRoutes;
    }

    public int maximumRequestBytes() {
        return requestByteLimit;
    }

    public CompletionStage<AepHttpResponse> handle(AepCommand command, AepHttpRequest request) {
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(request, "request");
        if (!commandRoutes.containsKey(command)) {
            return completed(problem(404, ERROR_INVALID_REQUEST, "AEP route not found"));
        }
        // RFC 9110 section 9.3.2 makes HEAD identical to GET apart from the content, so a resource
        // that answers GET answers HEAD as well. Allowing only GET turned every cache revalidation
        // and every link check into a 405.
        boolean safe = command == AepCommand.INSPECT || command == AepCommand.STATUS;
        String method = request.method().toUpperCase(Locale.ROOT);
        if (!(safe ? "GET".equals(method) || "HEAD".equals(method) : "POST".equals(method))) {
            return completed(withHeader(
                    problem(405, ERROR_INVALID_REQUEST, "Method not allowed"),
                    "Allow",
                    List.of(safe ? SAFE_METHODS : "POST")));
        }
        if (request.body().length > requestByteLimit) {
            return completed(problem(413, ERROR_INVALID_REQUEST, "AEP request exceeds its byte limit"));
        }
        if (command == AepCommand.INSPECT) {
            if (request.body().length != 0) {
                return completed(problem(400, ERROR_INVALID_REQUEST, "Inspect has no body"));
            }
            // CORE-CACHE-001 and CORE-CACHE-002 ask for cache metadata on Inspect, and CORE-CACHE-004
            // makes an Agent revalidate through 304. Without a validator to echo, every expiry cost a
            // full refetch of a document that rarely changes.
            Map<String, List<String>> cache = new java.util.LinkedHashMap<>();
            cache.put(CACHE_CONTROL, List.of(cacheControlValue));
            cache.put("ETag", List.of(entityTagValue));
            if (matchesEntityTag(request.headerValues("If-None-Match"), entityTagValue)) {
                return completed(new AepHttpResponse(304, Aep.MEDIA_TYPE, cache, new byte[0]));
            }
            return completed(json(200, Aep.MEDIA_TYPE, service.inspectDocument(), cache));
        }
        if (command == AepCommand.STATUS) {
            if (request.body().length != 0) {
                return completed(problem(400, ERROR_INVALID_REQUEST, "Status has no body"));
            }
            return service.status(CommandOptions.authenticated(clientAssertion(request)))
                    .thenApply(this::encode);
        }
        if (!hasAepContentType(request)) {
            return completed(problem(415, ERROR_INVALID_REQUEST, "Expected application/aep+json"));
        }
        try {
            String body = decodeUtf8(request.body());
            CommandOptions options = CommandOptions.idempotent(clientAssertion(request), idempotencyKey(request));
            return switch (command) {
                case ENROLL ->
                    service.enroll(AepJson.parseEnrollRequest(body), options).thenApply(this::encode);
                case GRANT ->
                    service.grant(AepJson.parseGrantRequest(body), options).thenApply(this::encode);
                case REVOKE ->
                    service.revoke(AepJson.parseRevokeRequest(body), options).thenApply(this::encode);
                case INSPECT, STATUS -> throw new IllegalStateException("AEP command dispatch is inconsistent.");
            };
        } catch (IllegalArgumentException exception) {
            return completed(problem(400, ERROR_INVALID_REQUEST, "AEP request body is invalid"));
        }
    }

    public CompletionStage<AepHttpAuthenticationResult> authenticate(AepHttpRequest request) {
        Objects.requireNonNull(request, "request");
        return service.authenticate(new ProtectedResourceRequest(request.headers(), request.method(), request.url()))
                .thenApply(result -> result.authenticated()
                        ? AepHttpAuthenticationResult.authenticated(result.principal())
                        : AepHttpAuthenticationResult.rejected(encode(result.response())));
    }

    // Authenticated command responses carry enrollment state and, for Grant, the credential secret
    // itself. Nothing on this path is a shared representation, so no intermediary or browser cache
    // should keep one.
    private AepHttpResponse encode(ServiceResponse<?> response) {
        Object body = response.problem() == null ? response.body() : response.problem();
        Map<String, List<String>> headers = new java.util.LinkedHashMap<>(response.headers());
        headers.putIfAbsent(CACHE_CONTROL, List.of(NO_STORE));
        return json(response.status(), response.contentType(), body, headers);
    }

    private static AepHttpResponse json(
            int status, String contentType, Object body, Map<String, List<String>> headers) {
        return new AepHttpResponse(
                status, contentType, headers, AepJson.write(body).getBytes(StandardCharsets.UTF_8));
    }

    private static AepHttpResponse problem(int status, String code, String title) {
        return json(
                status,
                Aep.PROBLEM_MEDIA_TYPE,
                ProblemDetails.of(code, title, status),
                Map.of(CACHE_CONTROL, List.of(NO_STORE)));
    }

    private static String requireFieldValue(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || !value.equals(value.strip()) || value.chars().anyMatch(AepServiceHttpHandler::control)) {
            throw new IllegalArgumentException(name + " must be a valid HTTP field value.");
        }
        return value;
    }

    private static boolean control(int character) {
        return character != '\t' && (character < ' ' || character == 0x7f);
    }

    private static String entityTag(String body) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8));
            return "\"sha256:" + java.util.HexFormat.of().formatHex(digest) + "\"";
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    // RFC 9110 section 13.1.2: If-None-Match is a comma-separated list, "*" matches any
    // representation, and the comparison is weak, so a W/ prefix on either side still matches.
    private static boolean matchesEntityTag(List<String> values, String entityTag) {
        for (String value : values) {
            for (String candidate : value.split(",")) {
                String trimmed = candidate.trim();
                if ("*".equals(trimmed) || entityTag.equals(strongTag(trimmed))) return true;
            }
        }
        return false;
    }

    private static String strongTag(String value) {
        return value.startsWith("W/") ? value.substring(2) : value;
    }

    private static AepHttpResponse withHeader(AepHttpResponse response, String name, List<String> values) {
        Map<String, List<String>> headers = new java.util.LinkedHashMap<>(response.headers());
        headers.put(name, values);
        return new AepHttpResponse(response.status(), response.contentType(), headers, response.body());
    }

    private static boolean hasAepContentType(AepHttpRequest request) {
        List<String> values = request.headerValues("Content-Type");
        if (!hasSingleValue(values)) return false;
        String essence = values.get(0).split(";", 2)[0].trim();
        return Aep.MEDIA_TYPE.equalsIgnoreCase(essence);
    }

    private static String clientAssertion(AepHttpRequest request) {
        List<String> values = request.headerValues("Authorization");
        if (!hasSingleValue(values)) return "";
        try {
            ProtectedResourceAuthorization authorization =
                    AepHttp.parseAuthorization(values.get(0), AuthorizationCarrier.STANDARD);
            return authorization.scheme() == AuthorizationScheme.AEP ? authorization.credentials() : "";
        } catch (IllegalArgumentException exception) {
            return "";
        }
    }

    private static String idempotencyKey(AepHttpRequest request) {
        List<String> values = request.headerValues("Idempotency-Key");
        return hasSingleValue(values) ? values.get(0) : "";
    }

    private static String decodeUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("AEP request body is not valid UTF-8.", exception);
        }
    }

    private static AepCommand command(String value) {
        for (AepCommand command : AepCommand.values()) {
            if (command.value().equals(value)) return command;
        }
        throw new IllegalArgumentException("AEP Service advertises an unknown command.");
    }

    private static boolean hasSingleValue(List<String> values) {
        return values.size() == SINGLE_HEADER_VALUE;
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }
}
