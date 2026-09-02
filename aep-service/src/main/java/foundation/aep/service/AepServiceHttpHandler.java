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
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public final class AepServiceHttpHandler {
    public static final int DEFAULT_MAXIMUM_REQUEST_BYTES = 65_536;
    private static final String ERROR_INVALID_REQUEST = "invalid_request";
    private static final int SINGLE_HEADER_VALUE = 1;

    private final AepService service;
    private final Map<AepCommand, String> commandRoutes;
    private final int requestByteLimit;

    public AepServiceHttpHandler(AepService service) {
        this(service, DEFAULT_MAXIMUM_REQUEST_BYTES);
    }

    public AepServiceHttpHandler(AepService service, int maximumRequestBytes) {
        this.service = Objects.requireNonNull(service, "service");
        if (maximumRequestBytes <= 0) throw new IllegalArgumentException("maximumRequestBytes must be positive.");
        requestByteLimit = maximumRequestBytes;
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
        String expectedMethod = command == AepCommand.INSPECT || command == AepCommand.STATUS ? "GET" : "POST";
        if (!expectedMethod.equals(request.method().toUpperCase(Locale.ROOT))) {
            return completed(withHeader(
                    problem(405, ERROR_INVALID_REQUEST, "Method not allowed"), "Allow", List.of(expectedMethod)));
        }
        if (request.body().length > requestByteLimit) {
            return completed(problem(413, ERROR_INVALID_REQUEST, "AEP request exceeds its byte limit"));
        }
        if (command == AepCommand.INSPECT) {
            if (request.body().length != 0) {
                return completed(problem(400, ERROR_INVALID_REQUEST, "Inspect has no body"));
            }
            return completed(json(200, Aep.MEDIA_TYPE, service.inspectDocument(), Map.of()));
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

    private AepHttpResponse encode(ServiceResponse<?> response) {
        Object body = response.problem() == null ? response.body() : response.problem();
        return json(response.status(), response.contentType(), body, response.headers());
    }

    private static AepHttpResponse json(
            int status, String contentType, Object body, Map<String, List<String>> headers) {
        return new AepHttpResponse(
                status, contentType, headers, AepJson.write(body).getBytes(StandardCharsets.UTF_8));
    }

    private static AepHttpResponse problem(int status, String code, String title) {
        return json(status, Aep.PROBLEM_MEDIA_TYPE, ProblemDetails.of(code, title, status), Map.of());
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
